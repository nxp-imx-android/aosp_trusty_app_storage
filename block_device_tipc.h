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

#include <lib/hwkey/hwkey.h>
#include <trusty_ipc.h>
#include "block_device.h"
#include "ipc.h"
#include "tipc_ns.h"
#include "transaction.h"

struct rpmb_key;
struct block_device_tipc;

/**
 * struct block_device_rpmb
 * @state:       Pointer to shared state containing ipc_handle and rpmb_state
 * @dev:         Block device state
 * @base:        First block to use in rpmb partition
 * @is_userdata: Is this RPMB device tied to the state of the userdata
 * partition?
 */
struct block_device_rpmb {
    struct block_device dev;
    struct block_device_tipc* state;
    uint16_t base;
    bool is_userdata;
};

/**
 * struct block_device_ns
 * @dev:        Block device state
 * @state:      Pointer to shared state containing ipc_handle
 * @ns_handle:  Handle
 * @is_userdata: Is the backing file for this device in the (non-persistent)
 *               userdata partition?
 */
struct block_device_ns {
    struct block_device dev;
    struct block_device_tipc* state;
    ns_handle_t ns_handle;
    bool is_userdata;
};

struct client_port_context {
    struct fs* tr_state;
    struct ipc_port_context client_ctx;
};

/**
 * struct block_device_tipc
 * @ipc_handle
 */

struct block_device_tipc {
    handle_t ipc_handle;
    struct rpmb_state* rpmb_state;

    struct block_device_rpmb dev_rpmb;
    struct fs tr_state_rpmb;
    struct client_port_context fs_rpmb;
    struct client_port_context fs_rpmb_boot;

#if HAS_FS_TDP
    struct block_device_ns dev_ns_tdp;
    struct block_device_rpmb dev_ns_tdp_rpmb;
    struct fs tr_state_ns_tdp;
#endif
    struct client_port_context fs_tdp;

    struct block_device_ns dev_ns;
    struct block_device_rpmb dev_ns_rpmb;
    struct fs tr_state_ns;
    struct client_port_context fs_ns;
};

int block_device_tipc_init(struct block_device_tipc* state,
                           handle_t ipc_handle,
                           const struct key* fs_key,
                           const struct rpmb_key* rpmb_key,
                           hwkey_session_t hwkey_session);
void block_device_tipc_uninit(struct block_device_tipc* state);
