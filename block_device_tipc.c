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

#include "block_device_tipc.h"

#include <errno.h>
#include <inttypes.h>
#include <lib/system_state/system_state.h>
#include <lk/compiler.h>
#include <stdint.h>
#include <string.h>
#include <trusty_ipc.h>
#include <uapi/err.h>

#include <interface/storage/storage.h>

#include <openssl/mem.h>
#include <openssl/rand.h>

#include "block_cache.h"
#include "client_tipc.h"
#include "ipc.h"
#include "rpmb.h"
#include "tipc_ns.h"

#ifdef APP_STORAGE_RPMB_BLOCK_SIZE
#define BLOCK_SIZE_RPMB (APP_STORAGE_RPMB_BLOCK_SIZE)
#else
#define BLOCK_SIZE_RPMB (512)
#endif
#ifdef APP_STORAGE_RPMB_BLOCK_COUNT
#define BLOCK_COUNT_RPMB (APP_STORAGE_RPMB_BLOCK_COUNT)
#else
#define BLOCK_COUNT_RPMB (0) /* Auto detect */
#endif
#ifdef APP_STORAGE_MAIN_BLOCK_SIZE
#define BLOCK_SIZE_MAIN (APP_STORAGE_MAIN_BLOCK_SIZE)
#else
#define BLOCK_SIZE_MAIN (2048)
#endif
#ifdef APP_STORAGE_MAIN_BLOCK_COUNT
#define BLOCK_COUNT_MAIN (APP_STORAGE_MAIN_BLOCK_COUNT)
#else
#define BLOCK_COUNT_MAIN (0x10000000000 / BLOCK_SIZE_MAIN)
#endif

#define BLOCK_SIZE_RPMB_BLOCKS (BLOCK_SIZE_RPMB / RPMB_BUF_SIZE)

STATIC_ASSERT(BLOCK_SIZE_RPMB_BLOCKS == 1 || BLOCK_SIZE_RPMB_BLOCKS == 2);
STATIC_ASSERT((BLOCK_SIZE_RPMB_BLOCKS * RPMB_BUF_SIZE) == BLOCK_SIZE_RPMB);

STATIC_ASSERT(BLOCK_COUNT_RPMB == 0 || BLOCK_COUNT_RPMB >= 8);

STATIC_ASSERT(BLOCK_SIZE_MAIN >= 256);
STATIC_ASSERT(BLOCK_COUNT_MAIN >= 8);
STATIC_ASSERT(BLOCK_SIZE_MAIN >= BLOCK_SIZE_RPMB);

#define SS_ERR(args...) fprintf(stderr, "ss: " args)
#define SS_WARN(args...) fprintf(stderr, "ss: " args)

#ifdef SS_DATA_DEBUG_IO
#define SS_DBG_IO(args...) fprintf(stdout, "ss: " args)
#else
#define SS_DBG_IO(args...) \
    do {                   \
    } while (0)
#endif

struct rpmb_key_derivation_in {
    uint8_t prefix[sizeof(struct key)];
    uint8_t block_data[RPMB_BUF_SIZE];
};

struct rpmb_key_derivation_out {
    struct rpmb_key rpmb_key;
    uint8_t unused[sizeof(struct key)];
};

static int rpmb_check(struct block_device_tipc* state, uint16_t block) {
    int ret;
    uint8_t tmp[RPMB_BUF_SIZE];
    ret = rpmb_read(state->rpmb_state, tmp, block, 1);
    SS_DBG_IO("%s: check rpmb_block %d, ret %d\n", __func__, block, ret);
    return ret;
}

static uint32_t rpmb_search_size(struct block_device_tipc* state,
                                 uint16_t hint) {
    int ret;
    uint32_t low = 0;
    uint16_t high = UINT16_MAX;
    uint16_t curr = hint ? hint - 1 : UINT16_MAX;

    while (low <= high) {
        ret = rpmb_check(state, curr);
        switch (ret) {
        case 0:
            low = curr + 1;
            break;
        case -ENOENT:
            high = curr - 1;
            break;
        default:
            return 0;
        };
        if (ret || curr != hint) {
            curr = (low + high) / 2;
            hint = curr;
        } else {
            curr = curr + 1;
        }
    }
    assert((uint32_t)high + 1 == low);
    return low;
}

static struct block_device_rpmb* dev_rpmb_to_state(struct block_device* dev) {
    assert(dev);
    return containerof(dev, struct block_device_rpmb, dev);
}

static void block_device_tipc_rpmb_start_read(struct block_device* dev,
                                              data_block_t block) {
    int ret;
    uint8_t tmp[BLOCK_SIZE_RPMB]; /* TODO: pass data in? */
    uint16_t rpmb_block;
    struct block_device_rpmb* dev_rpmb = dev_rpmb_to_state(dev);

    assert(block < dev->block_count);
    rpmb_block = block + dev_rpmb->base;

    ret = rpmb_read(dev_rpmb->state->rpmb_state, tmp,
                    rpmb_block * BLOCK_SIZE_RPMB_BLOCKS,
                    BLOCK_SIZE_RPMB_BLOCKS);

    SS_DBG_IO("%s: block %" PRIu64 ", base %d, rpmb_block %d, ret %d\n",
              __func__, block, dev_rpmb->base, rpmb_block, ret);

    block_cache_complete_read(dev, block, tmp, BLOCK_SIZE_RPMB, !!ret);
}

static void block_device_tipc_rpmb_start_write(struct block_device* dev,
                                               data_block_t block,
                                               const void* data,
                                               size_t data_size) {
    int ret;
    uint16_t rpmb_block;
    struct block_device_rpmb* dev_rpmb = dev_rpmb_to_state(dev);

    assert(data_size == BLOCK_SIZE_RPMB);
    assert(block < dev->block_count);

    rpmb_block = block + dev_rpmb->base;

    ret = rpmb_write(dev_rpmb->state->rpmb_state, data,
                     rpmb_block * BLOCK_SIZE_RPMB_BLOCKS,
                     BLOCK_SIZE_RPMB_BLOCKS, true);

    SS_DBG_IO("%s: block %" PRIu64 ", base %d, rpmb_block %d, ret %d\n",
              __func__, block, dev_rpmb->base, rpmb_block, ret);

    block_cache_complete_write(dev, block, !!ret);
}

static void block_device_tipc_rpmb_wait_for_io(struct block_device* dev) {
    assert(0); /* TODO: use async read/write */
}

static struct block_device_ns* to_block_device_ns(struct block_device* dev) {
    assert(dev);
    return containerof(dev, struct block_device_ns, dev);
}

static void block_device_tipc_ns_start_read(struct block_device* dev,
                                            data_block_t block) {
    int ret;
    uint8_t tmp[BLOCK_SIZE_MAIN]; /* TODO: pass data in? */
    struct block_device_ns* dev_ns = to_block_device_ns(dev);

    ret = ns_read_pos(dev_ns->state->ipc_handle, dev_ns->ns_handle,
                      block * BLOCK_SIZE_MAIN, tmp, BLOCK_SIZE_MAIN);
    SS_DBG_IO("%s: block %" PRIu64 ", ret %d\n", __func__, block, ret);
    block_cache_complete_read(dev, block, tmp, BLOCK_SIZE_MAIN,
                              ret != BLOCK_SIZE_MAIN);
}

static void block_device_tipc_ns_start_write(struct block_device* dev,
                                             data_block_t block,
                                             const void* data,
                                             size_t data_size) {
    int ret;
    struct block_device_ns* dev_ns = to_block_device_ns(dev);

    assert(data_size == BLOCK_SIZE_MAIN);

    ret = ns_write_pos(dev_ns->state->ipc_handle, dev_ns->ns_handle,
                       block * BLOCK_SIZE_MAIN, data, data_size);
    SS_DBG_IO("%s: block %" PRIu64 ", ret %d\n", __func__, block, ret);
    block_cache_complete_write(dev, block, ret != BLOCK_SIZE_MAIN);
}

static void block_device_tipc_ns_wait_for_io(struct block_device* dev) {
    assert(0); /* TODO: use async read/write */
}

static void block_device_tipc_init_dev_rpmb(struct block_device_rpmb* dev_rpmb,
                                            struct block_device_tipc* state,
                                            uint16_t base,
                                            uint32_t block_count) {
    dev_rpmb->dev.start_read = block_device_tipc_rpmb_start_read;
    dev_rpmb->dev.start_write = block_device_tipc_rpmb_start_write;
    dev_rpmb->dev.wait_for_io = block_device_tipc_rpmb_wait_for_io;
    dev_rpmb->dev.block_count = block_count;
    dev_rpmb->dev.block_size = BLOCK_SIZE_RPMB;
    dev_rpmb->dev.block_num_size = 2;
    dev_rpmb->dev.mac_size = 2;
    dev_rpmb->dev.tamper_detecting = true;
    list_initialize(&dev_rpmb->dev.io_ops);
    dev_rpmb->state = state;
    dev_rpmb->base = base;
}

static void block_device_tipc_init_dev_ns(struct block_device_ns* dev_ns,
                                          struct block_device_tipc* state) {
    dev_ns->dev.start_read = block_device_tipc_ns_start_read;
    dev_ns->dev.start_write = block_device_tipc_ns_start_write;
    dev_ns->dev.wait_for_io = block_device_tipc_ns_wait_for_io;
    dev_ns->dev.block_count = BLOCK_COUNT_MAIN;
    dev_ns->dev.block_size = BLOCK_SIZE_MAIN;
    dev_ns->dev.block_num_size = sizeof(data_block_t);
    dev_ns->dev.mac_size = sizeof(struct mac);
    dev_ns->dev.tamper_detecting = false;
    list_initialize(&dev_ns->dev.io_ops);
    dev_ns->state = state;
    dev_ns->ns_handle = 0; /* Filled in later */
}

/**
 * hwkey_derive_rpmb_key() - Derive rpmb key through hwkey server.
 * @session:  The hwkey session handle.
 * @in:       The input data to derive rpmb key.
 * @out:      The output data from deriving rpmb key.
 *
 * Return: NO_ERROR on success, error code less than 0 on error.
 */
static int hwkey_derive_rpmb_key(hwkey_session_t session,
                                 const struct rpmb_key_derivation_in* in,
                                 struct rpmb_key_derivation_out* out) {
    uint32_t kdf_version = HWKEY_KDF_VERSION_1;
    const void* in_buf = in;
    void* out_buf = out;
    uint32_t key_size = sizeof(*out);
    STATIC_ASSERT(sizeof(*in) >= sizeof(*out));

    int ret = hwkey_derive(session, &kdf_version, in_buf, out_buf, key_size);
    if (ret < 0) {
        SS_ERR("%s: failed to get key: %d\n", __func__, ret);
        return ret;
    }

    return NO_ERROR;
}

/**
 * block_device_tipc_program_key() - Program a rpmb key derived through hwkey
 * server.
 * @state:              The rpmb state.
 * @rpmb_key_part_base: The base of rpmb_key_part in rpmb partition.
 * @in                  The input rpmb key derivation data.
 * @out                 The output rpmb key derivation data.
 * @hwkey_session:      The hwkey session handle.
 *
 * Return: NO_ERROR on success, error code less than 0 on error.
 */
static int block_device_tipc_program_key(struct rpmb_state* state,
                                         uint16_t rpmb_key_part_base,
                                         struct rpmb_key_derivation_in* in,
                                         struct rpmb_key_derivation_out* out,
                                         hwkey_session_t hwkey_session) {
    int ret;

    if (!system_state_provisioning_allowed()) {
        ret = ERR_NOT_ALLOWED;
        SS_ERR("%s: rpmb key provisioning is not allowed (%d)\n", __func__,
               ret);
        return ret;
    }

    STATIC_ASSERT(sizeof(in->block_data) >= sizeof(out->rpmb_key));
    RAND_bytes(in->block_data, sizeof(out->rpmb_key.byte));
    ret = hwkey_derive_rpmb_key(hwkey_session, in, out);
    if (ret < 0) {
        SS_ERR("%s: hwkey_derive_rpmb_key failed (%d)\n", __func__, ret);
        return ret;
    }

    ret = rpmb_program_key(state, &out->rpmb_key);
    if (ret < 0) {
        SS_ERR("%s: rpmb_program_key failed (%d)\n", __func__, ret);
        return ret;
    }

    rpmb_set_key(state, &out->rpmb_key);

    ret = rpmb_write(state, in->block_data,
                     rpmb_key_part_base * BLOCK_SIZE_RPMB_BLOCKS, 1, false);
    if (ret < 0) {
        SS_ERR("%s: rpmb_write failed (%d)\n", __func__, ret);
        return ret;
    }

    return 0;
}

static int block_device_tipc_derive_rpmb_key(struct rpmb_state* state,
                                             uint16_t rpmb_key_part_base,
                                             hwkey_session_t hwkey_session) {
    int ret;
    struct rpmb_key_derivation_in in = {
            .prefix = {
                    0x74, 0x68, 0x43, 0x49, 0x2b, 0xa2, 0x4f, 0x77,
                    0xb0, 0x8e, 0xd1, 0xd4, 0xb7, 0x01, 0x0e, 0xc6,
                    0x86, 0x4c, 0xa9, 0xe5, 0x28, 0xf0, 0x20, 0xb1,
                    0xb8, 0x1e, 0x73, 0x3d, 0x8c, 0x9d, 0xb9, 0x96,
            }};
    struct rpmb_key_derivation_out out;

    ret = rpmb_read_no_mac(state, in.block_data,
                           rpmb_key_part_base * BLOCK_SIZE_RPMB_BLOCKS, 1);

    if (ret < 0) {
        ret = block_device_tipc_program_key(state, rpmb_key_part_base, &in,
                                            &out, hwkey_session);
        if (ret < 0) {
            SS_ERR("%s: program_key failed (%d)\n", __func__, ret);
            return ret;
        }

        return 0;
    }

    ret = hwkey_derive_rpmb_key(hwkey_session, &in, &out);
    if (ret < 0) {
        SS_ERR("%s: hwkey_derive_rpmb_key failed (%d)\n", __func__, ret);
        return ret;
    }

    rpmb_set_key(state, &out.rpmb_key);

    /*
     * Validate that the derived rpmb key is correct as we use it to check
     * both mac and content of the block_data.
     */
    ret = rpmb_verify(state, in.block_data,
                      rpmb_key_part_base * BLOCK_SIZE_RPMB_BLOCKS, 1);
    if (ret < 0) {
        SS_ERR("%s: rpmb_verify failed with the derived rpmb key (%d)\n",
               __func__, ret);
        return ret;
    }

    return 0;
}

static int block_device_tipc_init_rpmb_key(struct rpmb_state* state,
                                           const struct rpmb_key* rpmb_key,
                                           uint16_t rpmb_key_part_base,
                                           hwkey_session_t hwkey_session) {
    rpmb_set_key(state, rpmb_key);
    return 0;
}

int block_device_tipc_init(struct block_device_tipc* state,
                           handle_t ipc_handle,
                           const struct key* fs_key,
                           const struct rpmb_key* rpmb_key,
                           hwkey_session_t hwkey_session) {
    int ret;
    bool new_ns_fs;
    uint8_t probe;
    uint16_t rpmb_key_part_base = 0;
    uint32_t rpmb_block_count;
    uint32_t rpmb_part_sb_ns_block_count = 2;
    /*
     * First block is reserved for rpmb key derivation data, whose base is
     * rpmb_key_part_base
     */
    uint16_t rpmb_part1_base = 1;
    uint16_t rpmb_part2_base = rpmb_part1_base + rpmb_part_sb_ns_block_count;
#if HAS_FS_TDP
    uint16_t rpmb_part_sb_tdp_base = rpmb_part2_base;
    rpmb_part2_base += rpmb_part_sb_ns_block_count;
#endif
    state->ipc_handle = ipc_handle;

    /* init rpmb */
    ret = rpmb_init(&state->rpmb_state, &state->ipc_handle);
    if (ret < 0) {
        SS_ERR("%s: rpmb_init failed (%d)\n", __func__, ret);
        goto err_rpmb_init;
    }

    ret = block_device_tipc_init_rpmb_key(state->rpmb_state, rpmb_key,
                                          rpmb_key_part_base, hwkey_session);
    if (ret < 0) {
        SS_ERR("%s: block_device_tipc_init_rpmb_key failed (%d)\n", __func__,
               ret);
        goto err_init_rpmb_key;
    }

    if (BLOCK_COUNT_RPMB) {
        rpmb_block_count = BLOCK_COUNT_RPMB;
        ret = rpmb_check(state, rpmb_block_count * BLOCK_SIZE_RPMB_BLOCKS - 1);
        if (ret) {
            SS_ERR("%s: bad static rpmb size, %d\n", __func__,
                   rpmb_block_count);
            goto err_bad_rpmb_size;
        }
    } else {
        rpmb_block_count =
                rpmb_search_size(state, 0); /* TODO: get hint from ns */
        rpmb_block_count /= BLOCK_SIZE_RPMB_BLOCKS;
    }
    if (rpmb_block_count < rpmb_part2_base) {
        ret = -1;
        SS_ERR("%s: bad rpmb size, %d\n", __func__, rpmb_block_count);
        goto err_bad_rpmb_size;
    }

    block_device_tipc_init_dev_rpmb(&state->dev_rpmb, state, rpmb_part2_base,
                                    rpmb_block_count - rpmb_part2_base);

    /* TODO: allow non-rpmb based tamper proof storage */
    ret = fs_init(&state->tr_state_rpmb, fs_key, &state->dev_rpmb.dev,
                  &state->dev_rpmb.dev, false);
    if (ret < 0) {
        goto err_init_tr_state_rpmb;
    }

    state->fs_rpmb.tr_state = &state->tr_state_rpmb;

    ret = client_create_port(&state->fs_rpmb.client_ctx,
                             STORAGE_CLIENT_TP_PORT);
    if (ret < 0) {
        goto err_fs_rpmb_create_port;
    }

    state->fs_rpmb_boot.tr_state = &state->tr_state_rpmb;

    ret = client_create_port(&state->fs_rpmb_boot.client_ctx,
                             STORAGE_CLIENT_TDEA_PORT);
    if (ret < 0) {
        goto err_fs_rpmb_boot_create_port;
    }

    block_device_tipc_init_dev_ns(&state->dev_ns, state);

    ret = ns_open_file(state->ipc_handle, "0", &state->dev_ns.ns_handle, true);
    if (ret < 0) {
        /* RPMB fs only */
        state->dev_ns.dev.block_count = 0;
        return 0;
    }

#if HAS_FS_TDP
    block_device_tipc_init_dev_ns(&state->dev_ns_tdp, state);

    ret = ns_open_file(state->ipc_handle, "persist/0",
                       &state->dev_ns_tdp.ns_handle, true);
    if (ret < 0) {
        SS_ERR("%s: failed to open tdp file (%d)\n", __func__, ret);
        goto err_open_tdp;
    }

    state->fs_tdp.tr_state = &state->tr_state_ns_tdp;

    block_device_tipc_init_dev_rpmb(&state->dev_ns_tdp_rpmb, state,
                                    rpmb_part_sb_tdp_base,
                                    rpmb_part_sb_ns_block_count);

    ret = fs_init(&state->tr_state_ns_tdp, fs_key, &state->dev_ns_tdp.dev,
                  &state->dev_ns_tdp_rpmb.dev, false /* Don't allow wiping */);
    if (ret < 0) {
        goto err_init_fs_ns_tdp_tr_state;
    }

#else
    /*
     * Create STORAGE_CLIENT_TDP_PORT alias after we know the backing file for
     * STORAGE_CLIENT_TD_PORT is available. On future devices, using HAS_FS_TDP,
     * STORAGE_CLIENT_TDP_PORT will not be available when the bootloader is
     * running, so we limit access to this alias as well to prevent apps
     * developed on old devices from relying on STORAGE_CLIENT_TDP_PORT being
     * available early.
     */
    state->fs_tdp.tr_state = &state->tr_state_rpmb;
#endif

    ret = client_create_port(&state->fs_tdp.client_ctx,
                             STORAGE_CLIENT_TDP_PORT);
    if (ret < 0) {
        goto err_fs_rpmb_tdp_create_port;
    }

    /* Request empty file system if file is empty */
    ret = ns_read_pos(state->ipc_handle, state->dev_ns.ns_handle, 0, &probe,
                      sizeof(probe));
    new_ns_fs = ret < (int)sizeof(probe);

    state->fs_ns.tr_state = &state->tr_state_ns;

    block_device_tipc_init_dev_rpmb(&state->dev_ns_rpmb, state, rpmb_part1_base,
                                    rpmb_part_sb_ns_block_count);

    ret = fs_init(&state->tr_state_ns, fs_key, &state->dev_ns.dev,
                  &state->dev_ns_rpmb.dev, new_ns_fs);
    if (ret < 0) {
        goto err_init_fs_ns_tr_state;
    }

    ret = client_create_port(&state->fs_ns.client_ctx, STORAGE_CLIENT_TD_PORT);
    if (ret < 0) {
        goto err_fs_ns_create_port;
    }

    return 0;

err_fs_ns_create_port:
    /* undo fs_init */
err_init_fs_ns_tr_state:
    ipc_port_destroy(&state->fs_tdp.client_ctx);
err_fs_rpmb_tdp_create_port:
#if HAS_FS_TDP
    /* undo fs_init */
err_init_fs_ns_tdp_tr_state:
    ns_close_file(state->ipc_handle, state->dev_ns_tdp.ns_handle);
err_open_tdp:
#endif
    ns_close_file(state->ipc_handle, state->dev_ns.ns_handle);
    ipc_port_destroy(&state->fs_rpmb_boot.client_ctx);
err_fs_rpmb_boot_create_port:
    ipc_port_destroy(&state->fs_rpmb.client_ctx);
err_fs_rpmb_create_port:
    /* undo fs_init */
err_init_tr_state_rpmb:
err_bad_rpmb_size:
err_init_rpmb_key:
    rpmb_uninit(state->rpmb_state);
err_rpmb_init:
    return ret;
}

void block_device_tipc_uninit(struct block_device_tipc* state) {
    if (state->dev_ns.dev.block_count) {
        ipc_port_destroy(&state->fs_ns.client_ctx);
        /* undo fs_init */
        ns_close_file(state->ipc_handle, state->dev_ns.ns_handle);

        ipc_port_destroy(&state->fs_tdp.client_ctx);
#if HAS_FS_TDP
        /* undo fs_init */
        ns_close_file(state->ipc_handle, state->dev_ns_tdp.ns_handle);
#endif
    }
    ipc_port_destroy(&state->fs_rpmb_boot.client_ctx);
    ipc_port_destroy(&state->fs_rpmb.client_ctx);
    /* undo fs_init */
    rpmb_uninit(state->rpmb_state);
}

int storage_program_rpmb_key(struct rpmb_state* rpmb_state)
{
    int rc;
    struct rpmb_key rpmb_key;
    uint32_t key_size = sizeof(rpmb_key.byte);
    const char* huk_id = "com.android.trusty.storage_auth.huk";

    rc = hwkey_open();
    if (rc < 0) {
        SS_ERR("%s: hwkey init failed: %d\n", __func__, rc);
        goto err_hwkey_open;
    }

    hwkey_session_t hwkey_session = (hwkey_session_t)rc;

    rc = hwkey_get_keyslot_data(hwkey_session, huk_id, rpmb_key.byte, &key_size);
    if (rc < 0) {
        SS_ERR("%s: failed to get huk: %d\n", __func__, rc);
        goto err;
    }

    rc = rpmb_program_key(rpmb_state, &rpmb_key);
    if (rc < 0) {
        SS_ERR("%s: failed to program rpmb key: %d\n", __func__, rc);
        goto err;
    }

    return STORAGE_NO_ERROR;

err:
    hwkey_close(hwkey_session);
err_hwkey_open:
    return STORAGE_ERR_GENERIC;
}

int storage_erase_rpmb(struct rpmb_state* rpmb_state)
{
    int buf[BLOCK_SIZE_RPMB];
    int i, ret;

    memset(buf, 0, BLOCK_SIZE_RPMB);
    for (i = 0; i < BLOCK_COUNT_RPMB; i++) {
        ret = rpmb_write(rpmb_state, buf, i * BLOCK_SIZE_RPMB_BLOCKS,
                         BLOCK_SIZE_RPMB_BLOCKS, true);
        if (ret < 0) {
            SS_ERR("%s: failed to write to rpmb: %d\n", __func__, ret);
            return STORAGE_ERR_GENERIC;
        }
    }

    return STORAGE_NO_ERROR;
}
