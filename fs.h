/*
 * Copyright (C) 2015 The Android Open Source Project
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

#pragma once

#include <stdbool.h>

#if BUILD_STORAGE_TEST
#define FULL_ASSERT 1
#else
#define FULL_ASSERT 0
#endif
#if FULL_ASSERT
#define full_assert assert
#else
#define full_assert(x) \
    do {               \
    } while (0)
#endif

#include "block_mac.h"
#include "block_set.h"
#include "block_tree.h"

/**
 * struct super_block_backup - Backup of root block for file system state
 * @flags:          Super-block flags for the backup, with the bits in
 *                  SUPER_BLOCK_VERSION_MASK set to 0 (i.e. the backup does not
 *                  contain a version).
 * @free:           Block and mac of backup free set root node.
 * @files:          Block and mac of backup files tree root node.
 *
 * Block numbers and macs in @free and @files are packed as indicated by
 * @block_num_size and @mac_size, but unlike other on-disk data, the size of the
 * whole field is always the full 24 bytes needed for a 8 byte block number and
 * 16 byte mac so this structure is always a fixed size.
 */
struct super_block_backup {
    uint32_t flags;
    struct block_mac free;
    struct block_mac files;
};
STATIC_ASSERT(sizeof(struct super_block_backup) == 52);

/**
 * struct fs - File system state
 * @node:                           List node for fs_list.
 * @dev:                            Main block device.
 * @transactions:                   Transaction list.
 * @allocated:                      List of block sets containing blocks
 *                                  allocated by active transactions.
 * @free:                           Block set of free blocks.
 * @files:                          B+ tree of all files.
 * @super_dev:                      Block device used to store super blocks.
 * @key:                            Key to use for encrypt, decrypt and mac.
 * @super_block:                    Block numbers in @super_dev to store
 *                                  super-block in.
 * @super_block_version:            Last read or written super block version.
 * @written_super_block_version:    Last written super block version.
 * @alternate_data:                 If true, the current superblock is for a
 *                                  filesystem with a backing store in an
 *                                  alternate data location and @backup contains
 *                                  the superblock of the normal filesystem. If
 *                                  false, @backup may contain a backup of the
 *                                  superblock for an alternate filesystem, but
 *                                  it may be outdated.
 * @backup:                         Backup superblock of other filesystem state
 *                                  (alternate if @alternate_data is false, main
 *                                  otherwise) Should be preserved across all
 *                                  filesystem operations after initialization.
 * @min_block_num:                  First block number that can store non
 *                                  super blocks.
 * @block_num_size:                 Number of bytes used to store block numbers.
 * @mac_size:                       Number of bytes used to store mac values.
 *                                  Must be 16 if @dev is not tamper_detecting.
 * @reserved_count:                 Number of free blocks reserved for active
 *                                  transactions.
 * @initial_super_block_tr:         Internal transaction containing initial
 *                                  super block that must be written before any
 *                                  other data. If %NULL superblock is already
 *                                  a safe state.
 */

struct fs {
    struct list_node node;
    struct block_device* dev;
    struct list_node transactions;
    struct list_node allocated;
    struct block_set free;
    struct block_tree files;
    struct block_device* super_dev;
    const struct key* key;
    data_block_t super_block[2];
    unsigned int super_block_version;
    unsigned int written_super_block_version;
    bool alternate_data;
    struct super_block_backup backup;
    data_block_t min_block_num;
    size_t block_num_size;
    size_t mac_size;
    data_block_t reserved_count;
    struct transaction* initial_super_block_tr;
};

bool update_super_block(struct transaction* tr,
                        const struct block_mac* free,
                        const struct block_mac* files);

/**
 * typedef fs_init_flags32_t - Flags that control filesystem clearing and
 * backups. These flags may be ORed together.
 *
 * %FS_INIT_FLAGS_NONE
 *   No flags set
 *
 * %FS_INIT_FLAGS_DO_CLEAR
 *   Unconditionally clear the filesystem, regardless of corruption state.
 *   %FS_INIT_FLAGS_RECOVERY_* flags are ignored when combined with this flag.
 *
 * %FS_INIT_FLAGS_RECOVERY_CLEAR_ALLOWED
 *   Allows clearing of corrupt filesystem.
 *
 * %FS_INIT_FLAGS_ALTERNATE_DATA
 *   Indicates that the filesystem is temporarily running on top of an alternate
 *   location for the @dev block device and rollback should be enforced
 *   separately from the normal mode.
 */
typedef uint32_t fs_init_flags32_t;
#define FS_INIT_FLAGS_NONE 0U
#define FS_INIT_FLAGS_DO_CLEAR (1U << 0)
#define FS_INIT_FLAGS_RECOVERY_CLEAR_ALLOWED (1U << 1)
#define FS_INIT_FLAGS_ALTERNATE_DATA (1U << 2)
#define FS_INIT_FLAGS_MASK                                           \
    (FS_INIT_FLAGS_DO_CLEAR | FS_INIT_FLAGS_RECOVERY_CLEAR_ALLOWED | \
     FS_INIT_FLAGS_ALTERNATE_DATA)

int fs_init(struct fs* fs,
            const struct key* key,
            struct block_device* dev,
            struct block_device* super_dev,
            fs_init_flags32_t flags);

void fs_unknown_super_block_state_all(void);
void write_current_super_block(struct fs* fs, bool reinitialize);

void fs_destroy(struct fs* fs);
