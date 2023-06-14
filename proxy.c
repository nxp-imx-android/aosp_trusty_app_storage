/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Copyright 2023 NXP
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
#include <lk/list.h>  // for containerof
#include <stdlib.h>
#include <string.h>
#include <uapi/err.h>

#include <interface/storage/storage.h>
#include <lib/hwkey/hwkey.h>

#include "ipc.h"
#include "rpmb.h"
#include "session.h"

#define SS_ERR(args...) fprintf(stderr, "ss: " args)

static void proxy_disconnect(struct ipc_channel_context* ctx);
static int proxy_handle_msg(struct ipc_channel_context* ctx,
                            void* msg_buf, size_t msg_size);

static struct storage_session* proxy_context_to_session(
        struct ipc_channel_context* context) {
    assert(context != NULL);
    struct storage_session* session =
            containerof(context, struct storage_session, proxy_ctx);
    assert(session->magic == STORAGE_SESSION_MAGIC);
    return session;
}

static int get_storage_encryption_key(hwkey_session_t session,
                                      uint8_t* key,
                                      uint32_t key_size) {
    static const struct key storage_key_derivation_data = {
            .byte = {
                    0xbc, 0x10, 0x6c, 0x9e, 0xc1, 0xa4, 0x71, 0x04,
                    0x83, 0xab, 0x03, 0x4b, 0x75, 0x8a, 0xb3, 0x5e,
                    0xfb, 0xe5, 0x43, 0x6c, 0xe6, 0x74, 0xb7, 0xfc,
                    0xee, 0x20, 0xad, 0xae, 0xfb, 0x34, 0xab, 0xd3,
            }};

    if (key_size != sizeof(storage_key_derivation_data.byte)) {
        return ERR_BAD_LEN;
    }

    uint32_t kdf_version = HWKEY_KDF_VERSION_1;
    int rc = hwkey_derive(session, &kdf_version,
                          storage_key_derivation_data.byte, key, key_size);
    if (rc < 0) {
        SS_ERR("%s: failed to get key: %d\n", __func__, rc);
        return rc;
    }

    return NO_ERROR;
}

#if !WITH_HKDF_RPMB_KEY
static int get_rpmb_auth_key(hwkey_session_t session,
                             uint8_t* key,
                             uint32_t key_size) {
    const char* storage_auth_key_id = "com.android.trusty.storage_auth.rpmb";

    int rc = hwkey_get_keyslot_data(session, storage_auth_key_id, key,
                                    &key_size);
    if (rc < 0) {
        SS_ERR("%s: failed to get key: %d\n", __func__, rc);
        return rc;
    }

    return NO_ERROR;
}
#endif

static bool block_device_initialized = true;
struct ipc_channel_context* proxy_connect(struct ipc_port_context* parent_ctx,
                                          const uuid_t* peer_uuid,
                                          handle_t chan_handle) {
    struct rpmb_key* rpmb_key_ptr = NULL;
    int rc;

    struct storage_session* session = calloc(1, sizeof(*session));
    if (session == NULL) {
        SS_ERR("%s: out of memory\n", __func__);
        goto err_alloc_session;
    }

    session->magic = STORAGE_SESSION_MAGIC;

    rc = hwkey_open();
    if (rc < 0) {
        SS_ERR("%s: hwkey init failed: %d\n", __func__, rc);
        goto err_hwkey_open;
    }

    hwkey_session_t hwkey_session = (hwkey_session_t)rc;

    /* Generate encryption key */
    rc = get_storage_encryption_key(hwkey_session, session->key.byte,
                                    sizeof(session->key));
    if (rc < 0) {
        SS_ERR("%s: can't get storage key: (%d) \n", __func__, rc);
        goto err_get_storage_key;
    }

    /* Init RPMB key */
#if !WITH_HKDF_RPMB_KEY
    struct rpmb_key rpmb_key;
    rc = get_rpmb_auth_key(hwkey_session, rpmb_key.byte, sizeof(rpmb_key.byte));
    if (rc < 0) {
        SS_ERR("%s: can't get storage auth key: (%d)\n", __func__, rc);
        goto err_get_rpmb_key;
    }

    rpmb_key_ptr = &rpmb_key;
#endif

    rc = block_device_tipc_init(&session->block_device, chan_handle,
                                &session->key, rpmb_key_ptr, hwkey_session);
    if (rc < 0) {
        SS_ERR("%s: block_device_tipc_init failed (%d)\n", __func__, rc);
        block_device_initialized = false;
    }

    session->proxy_ctx.ops.on_disconnect = proxy_disconnect;
    session->proxy_ctx.ops.on_handle_msg = proxy_handle_msg;

    hwkey_close(hwkey_session);

    return &session->proxy_ctx;

#if !WITH_HKDF_RPMB_KEY
err_get_rpmb_key:
#endif
err_get_storage_key:
    hwkey_close(hwkey_session);
err_hwkey_open:
    free(session);
err_alloc_session:
    return NULL;
}

void proxy_disconnect(struct ipc_channel_context* ctx) {
    struct storage_session* session = proxy_context_to_session(ctx);

    if (block_device_initialized)
        block_device_tipc_uninit(&session->block_device);

    free(session);
}

static int send_response(struct storage_session* session,
                         enum storage_err result,
                         struct storage_msg* msg,
                         void* out,
                         size_t out_size) {
    size_t resp_buf_count = 1;
    if (result == STORAGE_NO_ERROR && out != NULL && out_size != 0) {
        ++resp_buf_count;
    }

    struct iovec resp_bufs[2];

    msg->cmd |= STORAGE_RESP_BIT;
    msg->flags = 0;
    msg->size = sizeof(struct storage_msg) + out_size;
    msg->result = result;

    resp_bufs[0].iov_base = msg;
    resp_bufs[0].iov_len = sizeof(struct storage_msg);

    if (resp_buf_count == 2) {
        resp_bufs[1].iov_base = out;
        resp_bufs[1].iov_len = out_size;
    }

    struct ipc_msg resp_ipc_msg = {
            .iov = resp_bufs,
            .num_iov = resp_buf_count,
    };

    return send_msg(session->proxy_ctx.common.handle, &resp_ipc_msg);
}

static int proxy_handle_msg(struct ipc_channel_context* ctx,
                            void* msg_buf, size_t msg_size) {
    struct storage_session* session;
    struct storage_msg* msg = msg_buf;
    enum storage_err result;

    session = proxy_context_to_session(ctx);

    if (msg_size < sizeof(struct storage_msg)) {
        SS_ERR("%s: invalid message of size (%zu)\n", __func__, msg_size);
        return send_response(session, STORAGE_ERR_NOT_VALID, msg, NULL, 0);
    }

    switch (msg->cmd) {
    case STORAGE_RPMB_KEY_SET:
        result = storage_program_rpmb_key(session->block_device.rpmb_state);
        break;
#if SUPPORT_ERASE_RPMB
    case STORAGE_RPMB_ERASE_ALL:
        result = storage_erase_rpmb(session->block_device.rpmb_state);
        break;
#endif
    default:
        SS_ERR("%s: unsupported command 0x%x\n", __func__, msg->cmd);
        result = STORAGE_ERR_UNIMPLEMENTED;
        break;
    }

    return send_response(session, result, msg, NULL, 0);
}
