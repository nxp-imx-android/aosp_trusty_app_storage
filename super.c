/*
 * Copyright (C) 2015-2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <assert.h>
#include <inttypes.h>
#include <lk/compiler.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef LOCAL_TRACE
#define LOCAL_TRACE TRACE_LEVEL_INIT
#endif
#ifndef LOCAL_TRACE_ERR
#define LOCAL_TRACE_ERR TRACE_LEVEL_INIT
#endif

#include "array.h"
#include "block_allocator.h"
#include "block_cache.h"
#include "block_set.h"
#include "debug.h"
#include "file.h"
#include "fs.h"
#include "transaction.h"

#define SUPER_BLOCK_MAGIC (0x0073797473757274ULL) /* trustys */
#define SUPER_BLOCK_FLAGS_VERSION_MASK (0x3U)
#define SUPER_BLOCK_FLAGS_BLOCK_INDEX_MASK (0x1U)
#define SUPER_BLOCK_FLAGS_EMPTY (0x4U)
#define SUPER_BLOCK_FLAGS_ALTERNATE (0x8U)
#define SUPER_BLOCK_FLAGS_SUPPORTED_MASK (0xfU)
#define SUPER_BLOCK_FS_VERSION (0U)

/**
 * typedef super_block_opt_flags8_t - Optional flags, can be ORed together
 *
 * %SUPER_BLOCK_OPT_FLAGS_HAS_FLAGS3
 *   Indicates that the superblock has additional data after flags2 and that
 *   flags3 should be set to the same value as flags
 */
typedef uint8_t super_block_opt_flags8_t;
#define SUPER_BLOCK_OPT_FLAGS_HAS_FLAGS3 (0x1U)

/**
 * struct super_block - On-disk root block for file system state
 * @iv:             Initial value used for encrypt/decrypt.
 * @magic:          SUPER_BLOCK_MAGIC.
 * @flags:          Version in bottom two bits, other bits are reserved.
 * @fs_version:     Required file system version. If greater than
 *                  %SUPER_BLOCK_FS_VERSION, do not mount or overwrite
 *                  filesystem.
 * @block_size:     Block size of file system.
 * @block_num_size: Number of bytes used to store block numbers.
 * @mac_size:       number of bytes used to store mac values.
 * @opt_flags:      Optional flags, any of &typedef super_block_opt_flags8_t
 *                  ORed together.
 * @res2:           Reserved for future use. Write 0, read ignore.
 * @block_count:    Size of file system.
 * @free:           Block and mac of free set root node.
 * @free_count:     Currently unused.
 * @files:          Block and mac of files tree root node.
 * @res3:           Reserved for future use. Write 0, read ignore.
 * @flags2:         Copy of @flags. Allows storing the super-block in a device
 *                  that does not support an atomic write of the entire
 *                  super-block.
 * @backup:         Backup of previous super-block, used to support an alternate
 *                  backing store. 0 if no backup has ever been written. Once a
 *                  backup exists, it will only ever be swapped, not cleared.
 * @res4:           Reserved for future use. Write 0, read ignore.
 * @flags3:         Copy of @flags. Allows storing the super-block in a device
 *                  that does not support an atomic write of the entire
 *                  super-block. If SUPER_BLOCK_OPT_FLAGS_HAS_FLAGS3 is not set,
 *                  @flags3 is not checked and fields after @flags2 are ignored.
 *
 * Block numbers and macs in @free and @files are packed as indicated by
 * @block_num_size and @mac_size, but unlike other on-disk data, the size of the
 * whole field is always the full 24 bytes needed for a 8 byte block number and
 * 16 byte mac This allows the @flags2 and @flags3 to be validated before
 * knowing @block_num_size and @mac_size.
 */
struct super_block {
    struct iv iv;
    uint64_t magic;
    uint32_t flags;
    uint32_t fs_version;
    uint32_t block_size;
    uint8_t block_num_size;
    uint8_t mac_size;
    super_block_opt_flags8_t opt_flags;
    uint8_t res2;
    data_block_t block_count;
    struct block_mac free;
    data_block_t free_count;
    struct block_mac files;
    uint32_t res3[5];
    uint32_t flags2;
    struct super_block_backup backup;
    uint32_t res4[18];
    uint32_t flags3;
};
STATIC_ASSERT(offsetof(struct super_block, flags2) == 124);
STATIC_ASSERT(offsetof(struct super_block, flags3) == 252);
STATIC_ASSERT(sizeof(struct super_block) == 256);

/* block_device_tipc.c ensures that we have at least 256 bytes in RPMB blocks */
STATIC_ASSERT(sizeof(struct super_block) <= 256);

static struct list_node fs_list = LIST_INITIAL_VALUE(fs_list);

/**
 * update_super_block_internal - Generate and write superblock
 * @tr:         Transaction object.
 * @free:       New free root.
 * @files:      New files root.
 * @pinned:     New block should not be reused in the block cache until
 *              it is successfully written.
 *
 * Return: %true if super block was updated (in cache), %false if transaction
 * failed before super block was updated.
 */
static bool update_super_block_internal(struct transaction* tr,
                                        const struct block_mac* free,
                                        const struct block_mac* files,
                                        bool pinned) {
    struct super_block* super_rw;
    struct obj_ref super_ref = OBJ_REF_INITIAL_VALUE(super_ref);
    unsigned int ver;
    unsigned int index;
    uint32_t flags;
    uint32_t block_size = tr->fs->super_dev->block_size;

    assert(block_size >= sizeof(struct super_block));
    assert(tr->fs->initial_super_block_tr == NULL ||
           tr->fs->initial_super_block_tr == tr);

    ver = (tr->fs->super_block_version + 1) & SUPER_BLOCK_FLAGS_VERSION_MASK;
    index = ver & SUPER_BLOCK_FLAGS_BLOCK_INDEX_MASK;
    flags = ver;
    if (!free && !files) {
        /*
         * If the free and files trees are not provided, the filesystem is in
         * the initial empty state.
         */
        flags |= SUPER_BLOCK_FLAGS_EMPTY;
    } else {
        /* Non-empty filesystems must have both trees (with root node blocks) */
        assert(free);
        assert(files);
    }
    if (tr->fs->alternate_data) {
        flags |= SUPER_BLOCK_FLAGS_ALTERNATE;
    }

    pr_write("write super block %" PRIu64 ", ver %d\n",
             tr->fs->super_block[index], ver);

    super_rw = block_get_cleared_super(tr, tr->fs->super_block[index],
                                       &super_ref, pinned);
    if (tr->failed) {
        block_put_dirty_discard(super_rw, &super_ref);
        return false;
    }
    super_rw->magic = SUPER_BLOCK_MAGIC;
    super_rw->flags = flags;
    /* TODO: keep existing fs version when possible */
    super_rw->fs_version = SUPER_BLOCK_FS_VERSION;
    super_rw->block_size = tr->fs->dev->block_size;
    super_rw->block_num_size = tr->fs->block_num_size;
    super_rw->mac_size = tr->fs->mac_size;
    super_rw->opt_flags = SUPER_BLOCK_OPT_FLAGS_HAS_FLAGS3;
    super_rw->block_count = tr->fs->dev->block_count;
    if (free) {
        super_rw->free = *free;
    }
    super_rw->free_count = 0; /* TODO: remove or update */
    if (files) {
        super_rw->files = *files;
    }
    super_rw->flags2 = flags;
    super_rw->backup = tr->fs->backup;
    super_rw->flags3 = flags;
    tr->fs->written_super_block_version = ver;

    block_put_dirty_no_mac(super_rw, &super_ref);

    return true;
}

/**
 * update_super_block - Generate and write superblock
 * @tr:         Transaction object.
 * @free:       New free root.
 * @files:      New files root.
 *
 * Return: %true if super block was updated (in cache), %false if transaction
 * failed before super block was updated.
 */
bool update_super_block(struct transaction* tr,
                        const struct block_mac* free,
                        const struct block_mac* files) {
    return update_super_block_internal(tr, free, files, false);
}

/**
 * write_initial_super_block - Write initial superblock to internal transaction
 * @fs:         File system state object.
 *
 * When needed, this must be called before creating any other transactions on
 * this filesystem so we don't fill up the cache with entries that can't be
 * flushed to make room for this block.
 *
 * Return: %true if the initial empty superblock was successfully written to the
 * cache, or %false otherwise.
 */
static bool write_initial_super_block(struct fs* fs) {
    struct transaction* tr;
    tr = calloc(1, sizeof(*tr));
    if (!tr) {
        return false;
    }
    fs->initial_super_block_tr = tr;

    transaction_init(tr, fs, true);
    return update_super_block_internal(tr, NULL, NULL, true);
}

/**
 * write_current_super_block - Write current superblock to internal transaction
 * @fs:           File system state object.
 * @reinitialize: Allow the special transaction to be reinitialized if it has
 *                failed
 *
 * Write the current state of the super block to an internal transaction that
 * will be written before any other block. This can be used to re-sync the
 * in-memory fs-state with the on-disk state after detecting a write failure
 * where no longer know the on-disk super block state.
 */
void write_current_super_block(struct fs* fs, bool reinitialize) {
    bool super_block_updated;
    struct transaction* tr;

    if (fs->initial_super_block_tr) {
        /*
         * If initial_super_block_tr is already pending and not failed there is
         * no need to allocate a new one so return early.
         *
         * If the special transaction has failed, we need to re-initialize it so
         * that we can attempt to recover to a good state.
         *
         * We are only allowed to reinitialze if the @reinitialize parameter is
         * true. We don't want to allow reinitialization while cleaning blocks
         * (i.e. via fs_unknown_super_block_state_all()), as this would reset
         * the special transaction to non-failed state and create a situation
         * where transaction_initial_super_block_complete() cannot know if it
         * successfully flushed the special transaction to disk. Therefore we
         * only allow transaction_initial_super_block_complete() to reinitialize
         * a failed special transaction after it attempts and fails to write the
         * block to disk.
         *
         * Since we pin special superblock entries in the block cache and
         * therefore cannot evict them with normal transactions,
         * transaction_initial_super_block_complete() is the only place we can
         * attempt a special transaction write, and if it fails the transaction
         * is immediately reinitialized. Therefore we should only ever be in a
         * failed state if reinitialize is true (i.e. we are being called from
         * transaction_initial_super_block_complete()).
         */

        assert(reinitialize || !fs->initial_super_block_tr->failed);
        if (!fs->initial_super_block_tr->failed || !reinitialize) {
            return;
        }

        tr = fs->initial_super_block_tr;
        transaction_activate(tr);
    } else {
        tr = calloc(1, sizeof(*tr));
        if (!tr) {
            /* Not safe to proceed. TODO: add flag to defer this allocation? */
            abort();
        }
        transaction_init(tr, fs, true);
        fs->initial_super_block_tr = tr;
    }

    /*
     * Until the filesystem contains committed data, fs->free.block_tree.root
     * will be zero, i.e. an invalid block mac. fs->free.block_tree.root is only
     * updated in transaction_complete() after successfully writing a new
     * superblock. If the filesystem is empty, we need to emit a cleared
     * superblock with a special flag to prevent the superblock state from
     * getting out of sync with the filesystem data if a reboot occurrs before
     * committing a superblock with data.
     *
     * We can't use fs->files.root here because it may be invalid if there are
     * no files in the filesystem. If the free node is zero, then the files node
     * must be as well, so we assert this.
     */
    bool fs_is_cleared = !block_mac_valid(tr, &fs->free.block_tree.root);
    if (fs_is_cleared) {
        assert(!block_mac_valid(tr, &fs->files.root));
        super_block_updated = update_super_block_internal(tr, NULL, NULL, true);
    } else {
        super_block_updated = update_super_block_internal(
                tr, &fs->free.block_tree.root, &fs->files.root, true);
    }
    if (!super_block_updated) {
        /* Not safe to proceed. TODO: add flag to try again? */
        fprintf(stderr,
                "Could not create pending write for current superblock state. "
                "Not safe to proceed.\n");
        abort();
    }
}

/**
 * super_block_valid - Check if superblock is valid
 * @dev:        Block device that supoer block was read from.
 * @super:      Super block data.
 *
 * Return: %true if @super is valid for @dev, %false otherwise.
 */
static bool super_block_valid(const struct block_device* dev,
                              const struct super_block* super) {
    if (super->magic != SUPER_BLOCK_MAGIC) {
        pr_init("bad magic, 0x%" PRIx64 "\n", super->magic);
        return false;
    }
    if (super->flags != super->flags2) {
        pr_warn("flags, 0x%x, does not match flags2, 0x%x\n", super->flags,
                super->flags2);
        return false;
    }
    if ((super->opt_flags & SUPER_BLOCK_OPT_FLAGS_HAS_FLAGS3) &&
        super->flags != super->flags3) {
        pr_warn("flags, 0x%x, does not match flags3, 0x%x\n", super->flags,
                super->flags3);
        return false;
    }
    if (super->fs_version > SUPER_BLOCK_FS_VERSION) {
        pr_warn("super block is from the future: 0x%x\n", super->fs_version);
        return true;
    }
    if (super->flags & ~SUPER_BLOCK_FLAGS_SUPPORTED_MASK) {
        pr_warn("unknown flags set, 0x%x\n", super->flags);
        return false;
    }
    if (super->block_size != dev->block_size) {
        pr_warn("bad block size 0x%x, expected 0x%zx\n", super->block_size,
                dev->block_size);
        return false;
    }
    if (super->block_num_size != dev->block_num_size) {
        pr_warn("invalid block_num_size %d, expected %zd\n",
                super->block_num_size, dev->block_num_size);
        return false;
    }
    if (super->mac_size != dev->mac_size) {
        pr_warn("invalid mac_size %d, expected %zd\n", super->mac_size,
                dev->mac_size);
        return false;
    }
    if (!dev->tamper_detecting && super->mac_size != sizeof(struct mac)) {
        pr_warn("invalid mac_size %d != %zd\n", super->mac_size,
                sizeof(data_block_t));
        return false;
    }
    /*
     * This check only disallows shrinking the block device without clearing the
     * filesystem as we don't currently check and shrink the backing file on the
     * block device. However, we don't actually read this value from the
     * super-block after this check and we instead use the value from the block
     * device (which may be larger), and save that value to future super-blocks.
     * Since we don't use this value from the super-block, we don't need a
     * separate block count for the alternate backup roots as long as the block
     * device doesn't shrink.
     */
    if (super->block_count > dev->block_count) {
        pr_warn("bad block count 0x%" PRIx64 ", expected <= 0x%" PRIx64 "\n",
                super->block_count, dev->block_count);
        return false;
    }
    return true;
}

/**
 * super_version_delta - Find the version delta between two superblocks
 * @new_super: Candidate new superblock
 * @old_super: Old superblock
 *
 * The overflow in this function is intentional as a way to use a wrapping
 * two-bit counter.
 *
 * Return: Wrapped difference between the two bit version numbers in the two
 * superblocks. This will be 1 when new is newer than old, 3 when old is
 * newer than new, and any other number indicates an invalid/corrupt version.
 */
__attribute__((no_sanitize("unsigned-integer-overflow"))) static inline uint8_t
super_version_delta(const struct super_block* new_super,
                    const struct super_block* old_super) {
    return (new_super->flags - old_super->flags) &
           SUPER_BLOCK_FLAGS_VERSION_MASK;
}

/**
 * use_new_super - Check if new superblock is valid and more recent than old
 * @dev:                Block device that super block was read from.
 * @new_super:          New super block data.
 * @new_super_index:    Index that @new_super was read from.
 * @old_super:          Old super block data, or %NULL.
 *
 * Return: %true if @new_super is valid for @dev, and more recent than
 * @old_super (or @old_super is %NULL), %false otherwise.
 */
static bool use_new_super(const struct block_device* dev,
                          const struct super_block* new_super,
                          unsigned int new_super_index,
                          const struct super_block* old_super) {
    uint8_t dv;
    if (!super_block_valid(dev, new_super)) {
        return false;
    }
    if ((new_super->flags & SUPER_BLOCK_FLAGS_BLOCK_INDEX_MASK) !=
        new_super_index) {
        pr_warn("block index, 0x%x, does not match flags, 0x%x\n",
                new_super_index, new_super->flags);
        return false;
    }
    if (!old_super) {
        return true;
    }
    dv = super_version_delta(new_super, old_super);
    pr_read("version delta, %d (new flags 0x%x, old flags 0x%x)\n", dv,
            new_super->flags, old_super->flags);
    if (dv == 1) {
        return true;
    }
    if (dv == 3) {
        return false;
    }
    pr_warn("bad version delta, %d (new flags 0x%x, old flags 0x%x)\n", dv,
            new_super->flags, old_super->flags);
    return false;
}

/**
 * fs_init_empty - Initialize free set for empty file system
 * @fs:         File system state object.
 */
static void fs_init_empty(struct fs* fs) {
    struct block_range range = {
            .start = fs->min_block_num,
            .end = fs->dev->block_count,
    };
    block_set_add_initial_range(&fs->free, range);
}

/**
 * fs_init_from_super - Initialize file system from super block
 * @fs:         File system state object.
 * @super:      Superblock data, or %NULL.
 * @flags:      Any of &typedef fs_init_flags32_t, ORed together.
 *
 * Return: 0 if super block was usable, -1 if not.
 */
static int fs_init_from_super(struct fs* fs,
                              const struct super_block* super,
                              fs_init_flags32_t flags) {
    size_t block_mac_size;
    bool is_clear = false;
    bool do_clear = flags & FS_INIT_FLAGS_DO_CLEAR;
    bool do_swap = false; /* Does the active superblock alternate mode match the
                             current mode? */
    bool has_backup_field =
            super && (super->opt_flags & SUPER_BLOCK_OPT_FLAGS_HAS_FLAGS3);
    bool recovery_allowed = flags & FS_INIT_FLAGS_RECOVERY_CLEAR_ALLOWED;
    const struct block_mac* new_files_root;
    const struct block_mac* new_free_root;

    if (super && super->fs_version > SUPER_BLOCK_FS_VERSION) {
        pr_err("ERROR: super block is from the future 0x%x\n",
               super->fs_version);
        return -1;
    }

    /*
     * We check that the super-block matches these block device params in
     * super_block_valid(). If these params change, the filesystem (and
     * alternate backup) will be wiped and reset with the new params.
     */
    fs->block_num_size = fs->dev->block_num_size;
    fs->mac_size = fs->dev->mac_size;

    block_mac_size = fs->block_num_size + fs->mac_size;
    block_set_init(fs, &fs->free);
    fs->free.block_tree.copy_on_write = true;
    block_tree_init(&fs->files, fs->dev->block_size, fs->block_num_size,
                    block_mac_size, block_mac_size);
    fs->files.copy_on_write = true;
    fs->files.allow_copy_on_write = true;

    /* Reserve 1/4 for tmp blocks plus half of the remaining space */
    fs->reserved_count = fs->dev->block_count / 8 * 5;

    fs->alternate_data = flags & FS_INIT_FLAGS_ALTERNATE_DATA;

    if (super) {
        fs->super_block_version = super->flags & SUPER_BLOCK_FLAGS_VERSION_MASK;

        do_swap = !(super->flags & SUPER_BLOCK_FLAGS_ALTERNATE) !=
                  !(flags & FS_INIT_FLAGS_ALTERNATE_DATA);

        if (do_swap) {
            pr_init("Swapping super-block with alternate\n");

            fs->backup.flags = super->flags & (SUPER_BLOCK_FLAGS_EMPTY |
                                               SUPER_BLOCK_FLAGS_ALTERNATE);
            fs->backup.free = super->free;
            fs->backup.files = super->files;

            if (!has_backup_field ||
                super->backup.flags & SUPER_BLOCK_FLAGS_EMPTY) {
                is_clear = true;
            } else if (has_backup_field) {
                new_files_root = &super->backup.files;
                new_free_root = &super->backup.free;
            }
        } else {
            if (has_backup_field) {
                fs->backup = super->backup;
            }

            if (super->flags & SUPER_BLOCK_FLAGS_EMPTY) {
                is_clear = true;
            } else {
                new_files_root = &super->files;
                new_free_root = &super->free;
            }
        }

        if (!is_clear && !do_clear && !block_probe(fs, new_files_root)) {
            pr_init("Backing file probe failed, fs is corrupted.\n");
            if (recovery_allowed) {
                pr_init("Attempting to clear corrupted fs.\n");
                do_clear = true;
            }
        }
    }

    /*
     * If we are initializing a new fs or if we are not swapping but detect an
     * old superblock without the backup slot, ensure that the backup slot is a
     * valid empty filesystem in case we later switch filesystems without an
     * explicit clear flag.
     */
    if (!super || (!do_swap && !has_backup_field)) {
        fs->backup = (struct super_block_backup){
                .flags = SUPER_BLOCK_FLAGS_EMPTY,
                .files = {0},
                .free = {0},
        };
    }

    if (super && !is_clear && !do_clear) {
        fs->free.block_tree.root = *new_free_root;
        fs->files.root = *new_files_root;
        pr_init("loaded super block version %d\n", fs->super_block_version);
    } else {
        if (is_clear) {
            pr_init("superblock, version %d, is empty fs\n",
                    fs->super_block_version);
        } else if (do_clear) {
            pr_init("clear requested, create empty, version %d\n",
                    fs->super_block_version);
        } else {
            pr_init("no valid super-block found, create empty\n");
        }
        fs_init_empty(fs);
    }
    assert(fs->block_num_size >= fs->dev->block_num_size);
    assert(fs->block_num_size <= sizeof(data_block_t));
    assert(fs->mac_size >= fs->dev->mac_size);
    assert(fs->mac_size <= sizeof(struct mac));
    assert(fs->mac_size == sizeof(struct mac) || fs->dev->tamper_detecting);

    if (do_clear && !is_clear) {
        if (!write_initial_super_block(fs)) {
            return -1;
        }
    }

    return 0;
}

/**
 * load_super_block - Find and load superblock and initialize file system state
 * @fs:         File system state object.
 * @flags:      Any of &typedef fs_init_flags32_t, ORed together.
 *
 * Return: 0 if super block was readable and not from a future file system
 * version (regardless of its other content), -1 if not.
 */
static int load_super_block(struct fs* fs, fs_init_flags32_t flags) {
    unsigned int i;
    int ret;
    const struct super_block* new_super;
    struct obj_ref new_super_ref = OBJ_REF_INITIAL_VALUE(new_super_ref);
    const struct super_block* old_super = NULL;
    struct obj_ref old_super_ref = OBJ_REF_INITIAL_VALUE(old_super_ref);

    assert(fs->super_dev->block_size >= sizeof(struct super_block));

    for (i = 0; i < countof(fs->super_block); i++) {
        new_super = block_get_super(fs, fs->super_block[i], &new_super_ref);
        if (!new_super) {
            pr_err("failed to read super-block\n");
            ret = -1;  // -EIO ? ERR_IO?;
            goto err;
        }
        if (use_new_super(fs->dev, new_super, i, old_super)) {
            if (old_super) {
                block_put(old_super, &old_super_ref);
            }
            old_super = new_super;
            obj_ref_transfer(&old_super_ref, &new_super_ref);
        } else {
            block_put(new_super, &new_super_ref);
        }
    }

    ret = fs_init_from_super(fs, old_super, flags);
err:
    if (old_super) {
        block_put(old_super, &old_super_ref);
    }
    return ret;
}

/**
 * fs_init - Initialize file system state
 * @fs:         File system state object.
 * @key:        Key pointer. Must not be freed while @fs is in use.
 * @dev:        Main block device.
 * @super_dev:  Block device for super block.
 * @flags:      Any of &typedef fs_init_flags32_t, ORed together.
 */
int fs_init(struct fs* fs,
            const struct key* key,
            struct block_device* dev,
            struct block_device* super_dev,
            fs_init_flags32_t flags) {
    int ret;

    if (super_dev->block_size < sizeof(struct super_block)) {
        pr_err("unsupported block size for super_dev, %zd < %zd\n",
               super_dev->block_size, sizeof(struct super_block));
        return -1;  // ERR_NOT_VALID?
    }

    if (super_dev->block_count < 2) {
        pr_err("unsupported block count for super_dev, %" PRIu64 "\n",
               super_dev->block_count);
        return -1;  // ERR_NOT_VALID?
    }

    fs->key = key;
    fs->dev = dev;
    fs->super_dev = super_dev;
    list_initialize(&fs->transactions);
    list_initialize(&fs->allocated);
    fs->initial_super_block_tr = NULL;
    list_add_tail(&fs_list, &fs->node);

    if (dev == super_dev) {
        fs->min_block_num = 2;
    } else {
        /* TODO: use 0 when btree code allows it */
        fs->min_block_num = 1;
    }
    fs->super_block[0] = 0;
    fs->super_block[1] = 1;
    ret = load_super_block(fs, flags);
    if (ret) {
        fs_destroy(fs);
        fs->dev = NULL;
        fs->super_dev = NULL;
        return ret;
    }

    return 0;
}

/**
 * fs_destroy - Destroy file system state
 * @fs:         File system state object.
 *
 * Free any dynamically allocated state and check that @fs is not referenced by
 * any transactions.
 */
void fs_destroy(struct fs* fs) {
    if (fs->initial_super_block_tr) {
        transaction_fail(fs->initial_super_block_tr);
        transaction_free(fs->initial_super_block_tr);
        free(fs->initial_super_block_tr);
        fs->initial_super_block_tr = NULL;
    }
    assert(list_is_empty(&fs->transactions));
    assert(list_is_empty(&fs->allocated));
    list_delete(&fs->node);
}

/**
 * fs_unknown_super_block_state_all - Notify filesystems of unknown disk state
 *
 * Call from other layers when detecting write failues that can cause the
 * in-memory state of super blocks (or other block that we don't care about) to
 * be different from the on-disk state. Write in-memory state to disk before
 * writing any other block.
 */
void fs_unknown_super_block_state_all(void) {
    struct fs* fs;
    list_for_every_entry(&fs_list, fs, struct fs, node) {
        /* TODO: filter out filesystems that are not affected? */
        /*
         * We can't reinitialize an existing, failed special transaction here.
         * If a initial superblock write failed and triggered
         * fs_unknown_super_block_state_all() we need to leave that superblock
         * transaction in a failed state so that the transaction that that
         * triggered the failing write can also be failed further up the call
         * chain. If a special transaction already exists we are guaranteed that
         * it will be reinitialized and flushed to disk before any new writes to
         * that FS, so we don't need to reinitialize it here.
         */
        write_current_super_block(fs, false /* reinitialize */);
    }
}
