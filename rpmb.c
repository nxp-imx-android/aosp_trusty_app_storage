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

#include "rpmb.h"
#include "rpmb_protocol.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <lk/compiler.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/hmac.h>
#include <openssl/mem.h>
#include <openssl/rand.h>

#define RPMB_DEBUG 0
#define MAX_PACKET_COUNT 2

#define RPMB_PROTOCOL_MMC 1
#define RPMB_PROTOCOL_UFS 2

#if RPMB_PROTOCOL != RPMB_PROTOCOL_MMC && RPMB_PROTOCOL != RPMB_PROTOCOL_UFS
#error "invalid RPMB_PROTOCOL!"
#endif

struct rpmb_state {
    struct rpmb_key key;
    void* mmc_handle;
    uint32_t write_counter;
    bool first_write_complete;
};

#if RPMB_DEBUG
#define rpmb_dprintf(fmt, ...) fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define rpmb_dprintf(fmt, ...) \
    do {                       \
    } while (0)
#endif

static void rpmb_dprint_buf(const char* prefix,
                            const uint8_t* buf,
                            size_t size) {
#if RPMB_DEBUG
    size_t i, j;

    rpmb_dprintf("%s", prefix);
    for (i = 0; i < size; i++) {
        if (i && i % 32 == 0) {
            rpmb_dprintf("\n");
            j = strlen(prefix);
            while (j--)
                rpmb_dprintf(" ");
        }
        rpmb_dprintf(" %02x", buf[i]);
    }
    rpmb_dprintf("\n");
#endif
}

static void rpmb_dprint_u16(const char* prefix, const struct rpmb_u16 u16) {
    rpmb_dprint_buf(prefix, u16.byte, sizeof(u16.byte));
}

static void rpmb_dprint_u32(const char* prefix, const struct rpmb_u32 u32) {
    rpmb_dprint_buf(prefix, u32.byte, sizeof(u32.byte));
}

static void rpmb_dprint_key(const char* prefix,
                            const struct rpmb_key key,
                            const char* expected_prefix,
                            const struct rpmb_key expected_key) {
#if RPMB_DEBUG
    rpmb_dprint_buf(prefix, key.byte, sizeof(key.byte));
    if (CRYPTO_memcmp(key.byte, expected_key.byte, sizeof(key.byte)))
        rpmb_dprint_buf(expected_prefix, expected_key.byte,
                        sizeof(expected_key.byte));
#endif
}

static struct rpmb_nonce rpmb_nonce_init(void) {
    struct rpmb_nonce rpmb_nonce;

    RAND_bytes(rpmb_nonce.byte, sizeof(rpmb_nonce.byte));

    return rpmb_nonce;
}

static int rpmb_mac(struct rpmb_key key,
                    struct rpmb_packet* packet,
                    size_t packet_count,
                    struct rpmb_key* mac) {
    size_t i;
    int hmac_ret;
    unsigned int md_len;
    HMAC_CTX hmac_ctx;

    HMAC_CTX_init(&hmac_ctx);
    hmac_ret = HMAC_Init_ex(&hmac_ctx, &key, sizeof(key), EVP_sha256(), NULL);
    if (!hmac_ret) {
        fprintf(stderr, "HMAC_Init_ex failed\n");
        goto err;
    }
    for (i = 0; i < packet_count; i++) {
        STATIC_ASSERT(sizeof(*packet) - offsetof(__typeof__(*packet), data) ==
                      284);
        hmac_ret = HMAC_Update(&hmac_ctx, packet[i].data, 284);
        if (!hmac_ret) {
            fprintf(stderr, "HMAC_Update failed\n");
            goto err;
        }
    }
    hmac_ret = HMAC_Final(&hmac_ctx, mac->byte, &md_len);
    if (md_len != sizeof(mac->byte)) {
        fprintf(stderr, "bad md_len %d != %zd\n", md_len, sizeof(mac->byte));
        exit(1);
    }
    if (!hmac_ret) {
        fprintf(stderr, "HMAC_Final failed\n");
        goto err;
    }

err:
    HMAC_CTX_cleanup(&hmac_ctx);
    return hmac_ret ? 0 : -1;
}

static int rpmb_check_response(const char* cmd_str,
                               enum rpmb_response response_type,
                               struct rpmb_packet* res,
                               int res_count,
                               struct rpmb_key* mac,
                               struct rpmb_nonce* nonce,
                               uint16_t* addrp,
                               uint32_t write_counter) {
    int i;
    for (i = 0; i < res_count; i++) {
        if (rpmb_get_u16(res[i].req_resp) != response_type) {
            fprintf(stderr, "%s: Bad response type, 0x%x, expected 0x%x\n",
                    cmd_str, rpmb_get_u16(res[i].req_resp), response_type);
            return -1;
        }

        if (rpmb_get_u16(res[i].result) != RPMB_RES_OK) {
            if (rpmb_get_u16(res[i].result) == RPMB_RES_ADDR_FAILURE) {
                fprintf(stderr, "%s: Addr failure, %u\n", cmd_str,
                        rpmb_get_u16(res[i].address));
                return -ENOENT;
            }
            fprintf(stderr, "%s: Bad result, 0x%x\n", cmd_str,
                    rpmb_get_u16(res[i].result));
            return -1;
        }

        if (i == res_count - 1 && mac &&
            CRYPTO_memcmp(res[i].key_mac.byte, mac->byte, sizeof(mac->byte))) {
            fprintf(stderr, "%s: Bad MAC\n", cmd_str);
            return -1;
        }

        if (nonce && CRYPTO_memcmp(res[i].nonce.byte, nonce->byte,
                                   sizeof(nonce->byte))) {
            fprintf(stderr, "%s: Bad nonce\n", cmd_str);
            return -1;
        }

        if (write_counter &&
            write_counter != rpmb_get_u32(res[i].write_counter)) {
            fprintf(stderr, "%s: Bad write counter, got %u, expected %u\n",
                    cmd_str, rpmb_get_u32(res[i].write_counter), write_counter);
            return -1;
        }

        if (addrp && *addrp != rpmb_get_u16(res[i].address)) {
            fprintf(stderr, "%s: Bad addr, got %u, expected %u\n", cmd_str,
                    rpmb_get_u16(res[i].address), *addrp);
            return -1;
        }
    }

    return 0;
}

int rpmb_program_key(struct rpmb_state* state, const struct rpmb_key* key) {
    int ret;
    struct rpmb_packet cmd = {
            .req_resp = rpmb_u16(RPMB_REQ_PROGRAM_KEY),
    };
    struct rpmb_packet rescmd = {
            .req_resp = rpmb_u16(RPMB_REQ_RESULT_READ),
    };
    struct rpmb_packet res;

    memcpy(cmd.key_mac.byte, key->byte, sizeof(cmd.key_mac.byte));

    ret = rpmb_send(state->mmc_handle, &cmd, sizeof(cmd), &rescmd,
                    sizeof(rescmd), &res, sizeof(res), false);
    if (ret < 0)
        return ret;

    rpmb_dprint_key("  key/mac       ", res.key_mac, "   expected mac ",
                    res.key_mac);
    rpmb_dprint_buf("  nonce         ", res.nonce.byte, sizeof(res.nonce.byte));
    rpmb_dprint_u32("  write_counter ", res.write_counter);
    rpmb_dprint_u16("  result        ", res.result);
    rpmb_dprint_u16("  req/resp      ", res.req_resp);

    ret = rpmb_check_response("program key", RPMB_RESP_PROGRAM_KEY, &res, 1,
                              NULL, NULL, NULL, 0);
    return ret;
}

static int rpmb_read_counter(struct rpmb_state* state,
                             uint32_t* write_counter) {
    int ret;
    struct rpmb_key mac;
    struct rpmb_nonce nonce = rpmb_nonce_init();
    struct rpmb_packet cmd = {
            .nonce = nonce,
            .req_resp = rpmb_u16(RPMB_REQ_GET_COUNTER),
    };
    struct rpmb_packet res;

    ret = rpmb_send(state->mmc_handle, NULL, 0, &cmd, sizeof(cmd), &res,
                    sizeof(res), false);
    if (ret < 0)
        return ret;

    ret = rpmb_mac(state->key, &res, 1, &mac);
    if (ret < 0)
        return ret;

    rpmb_dprintf("rpmb: read counter response:\n");
    rpmb_dprint_key("  key/mac       ", res.key_mac, "   expected mac ", mac);
    rpmb_dprint_buf("  nonce         ", res.nonce.byte, sizeof(res.nonce.byte));
    rpmb_dprint_u32("  write_counter ", res.write_counter);
    rpmb_dprint_u16("  result        ", res.result);
    rpmb_dprint_u16("  req/resp      ", res.req_resp);

    ret = rpmb_check_response("read counter", RPMB_RESP_GET_COUNTER, &res, 1,
                              &mac, &nonce, NULL, 0);
    if (ret < 0)
        return ret;

    if (write_counter)
        *write_counter = rpmb_get_u32(res.write_counter);

    return 0;
}

static int rpmb_read_data(struct rpmb_state* state,
                          const void* cmp_buf,
                          void* out_buf,
                          uint16_t addr,
                          uint16_t count,
                          struct rpmb_key* mac) {
    int i;
    int ret;
    struct rpmb_nonce nonce = rpmb_nonce_init();
    struct rpmb_packet cmd = {
        .nonce = nonce,
        .address = rpmb_u16(addr),
#if RPMB_PROTOCOL == RPMB_PROTOCOL_UFS
        .block_count = rpmb_u16(count),
#endif
        .req_resp = rpmb_u16(RPMB_REQ_DATA_READ),
    };
    struct rpmb_packet res[MAX_PACKET_COUNT];
    const uint8_t* cmp_bufp;
    uint8_t* out_bufp;

    assert(count <= MAX_PACKET_COUNT);

    if (!state)
        return -EINVAL;

    ret = rpmb_send(state->mmc_handle, NULL, 0, &cmd, sizeof(cmd), res,
                    sizeof(res[0]) * count, false);
    if (ret < 0)
        return ret;

    if (mac) {
        ret = rpmb_mac(state->key, res, count, mac);
        if (ret < 0)
            return ret;
    }

    rpmb_dprintf("rpmb: read data, addr %d, count %d, response:\n", addr,
                 count);
    for (i = 0; i < count; i++) {
        rpmb_dprintf("  block %d\n", i);
        if (i == count - 1 && mac)
            rpmb_dprint_key("    key/mac       ", res[i].key_mac,
                            "     expected mac ", *mac);
        rpmb_dprint_buf("    data          ", res[i].data, sizeof(res[i].data));
        rpmb_dprint_buf("    nonce         ", res[i].nonce.byte,
                        sizeof(res[i].nonce.byte));
        rpmb_dprint_u16("    address       ", res[i].address);
        rpmb_dprint_u16("    block_count   ", res[i].block_count);
        rpmb_dprint_u16("    result        ", res[i].result);
        rpmb_dprint_u16("    req/resp      ", res[i].req_resp);
    }

    ret = rpmb_check_response("read data", RPMB_RESP_DATA_READ, res, count, mac,
                              &nonce, &addr, 0);
    if (ret < 0)
        return ret;

    if (cmp_buf) {
        for (cmp_bufp = cmp_buf, i = 0; i < count;
             i++, cmp_bufp += sizeof(res[i].data)) {
            if (memcmp(cmp_bufp, res[i].data, sizeof(res[i].data))) {
                fprintf(stderr, "verify read: data compare failed\n");
                return -1;
            }
        }
    }

    if (out_buf) {
        for (out_bufp = out_buf, i = 0; i < count;
             i++, out_bufp += sizeof(res[i].data)) {
            memcpy(out_bufp, res[i].data, sizeof(res[i].data));
        }
    }

    return 0;
}

int rpmb_read(struct rpmb_state* state,
              void* buf,
              uint16_t addr,
              uint16_t count) {
    struct rpmb_key mac;
    return rpmb_read_data(state, NULL, buf, addr, count, &mac);
}

int rpmb_read_no_mac(struct rpmb_state* state,
                     void* buf,
                     uint16_t addr,
                     uint16_t count) {
    return rpmb_read_data(state, NULL, buf, addr, count, NULL);
}

int rpmb_verify(struct rpmb_state* state,
                const void* buf,
                uint16_t addr,
                uint16_t count) {
    struct rpmb_key mac;
    return rpmb_read_data(state, buf, NULL, addr, count, &mac);
}

static int rpmb_write_data(struct rpmb_state* state,
                           const char* buf,
                           uint16_t addr,
                           uint16_t count,
                           bool sync) {
    int i;
    int ret;
    struct rpmb_key mac;
    struct rpmb_packet cmd[MAX_PACKET_COUNT];
    struct rpmb_packet rescmd = {
            .req_resp = rpmb_u16(RPMB_REQ_RESULT_READ),
    };
    struct rpmb_packet res;

    assert(count <= MAX_PACKET_COUNT);

    rpmb_dprintf("rpmb: write data, addr %d, count %d\n", addr, count);
    for (i = 0; i < count; i++) {
        memset(&cmd[i], 0, sizeof(cmd[i]));
        memcpy(cmd[i].data, buf + i * sizeof(cmd[i].data), sizeof(cmd[i].data));
        rpmb_dprint_buf("    data          ", cmd[i].data, sizeof(cmd[i].data));
        cmd[i].write_counter = rpmb_u32(state->write_counter);
        cmd[i].address = rpmb_u16(addr);
        cmd[i].block_count = rpmb_u16(count);
        cmd[i].req_resp = rpmb_u16(RPMB_REQ_DATA_WRITE);
    }
    ret = rpmb_mac(state->key, cmd, count, &cmd[count - 1].key_mac);
    if (ret < 0)
        return ret;

    ret = rpmb_send(state->mmc_handle, cmd, sizeof(cmd[0]) * count, &rescmd,
                    sizeof(rescmd), &res, sizeof(res), sync);
    if (ret < 0)
        goto err_sent;

    ret = rpmb_mac(state->key, &res, 1, &mac);
    if (ret < 0)
        goto err_sent;

    rpmb_dprintf(
            "rpmb: write data, addr %d, count %d, write_counter %d, response\n",
            addr, count, state->write_counter);
    rpmb_dprint_key("  key/mac       ", res.key_mac, "   expected mac ", mac);
    rpmb_dprint_buf("  nonce         ", res.nonce.byte, sizeof(res.nonce.byte));
    rpmb_dprint_u32("  write_counter ", res.write_counter);
    rpmb_dprint_u16("  address       ", res.address);
    rpmb_dprint_u16("  result        ", res.result);
    rpmb_dprint_u16("  req/resp      ", res.req_resp);

    ret = rpmb_check_response("write data", RPMB_RESP_DATA_WRITE, &res, 1, &mac,
                              NULL, &addr, state->write_counter + 1);
    if (ret < 0) {
        if (rpmb_get_u16(res.result) == RPMB_RES_COUNT_FAILURE) {
            fprintf(stderr, "rpmb write counter failure\n");
            abort(); /* see comment in err_sent */
        }
        goto err_sent;
    }

    state->write_counter++;

    return 0;

err_sent:
    /*
     * An error occured after the write requestst was sent. An attacker might
     * have saved this write request and might send it to the rpmb device at
     * any time. Any other write with this write counter value now needs extra
     * checks to make sure there is no corruption:
     *
     * 1. The next write fails.
     *
     * 1.1. The failure is a count failure.
     * A write operation that was previously reported as an error must have
     * actually been written. The filesystem may now be in a state where is it
     * not safe to write any other block.
     *
     * 1.1.1. The block actually written was a super-block.
     * This means a transaction was committed to disk that the file-system code
     * think was aborted. The in-memory view of free blocks will not match the
     * on disk state. It is not safe to proceed with any other write operations
     * in this state as the file-system could pick an block to write to that is
     * not actually free until the super block gets updated again with the
     * in-memory state.
     *
     * 1.1.2. The block actually written was a data block.
     * It might be possible to recover from this state (by incrementing the
     * write counter by one) as any transaction that used that block should have
     * already been aborted. The rpmb layer does not currently know if the
     * write requests are for super blocks or data blocks though, so we can't
     * currently know if we are in this state. The count failure would also have
     * to be authenticated as otherwise an attacker could report a fake count
     * failure to get write requests with more than one counter value.
     *
     * 1.2. The failure is not reported as count failure.
     * This can be handled the same way as the inital failure. We now have one
     * more possible write request that can be saved and written at any time by
     * an attacker, but it is in the same class as before.
     *
     * 2. The next write succeeds.
     *
     * 2.1. The same block number and counter value has already been sent.
     * This success status cannot be trusted. We read back the data to verify.
     * 2.1.1. Verify failed.
     * This has the same effect as 1.1.
     *
     * 2.1.2. Verify passed.
     * We are back to a normal state.
     *
     * 2.2. The same block number and counter has not already been sent.
     * We are back to a normal state.
     */
    state->first_write_complete = false;
    return ret;
}

int rpmb_write(struct rpmb_state* state,
               const void* buf,
               uint16_t addr,
               uint16_t count,
               bool sync) {
    int ret;

    if (!state)
        return -EINVAL;

    ret = rpmb_write_data(state, buf, addr, count, sync);
    if (ret < 0)
        return ret;

    if (!state->first_write_complete) {
        /*
         * The first write request after reading the write counter could get a
         * signed response from a different write request. There is no nonce in
         * the write request, only a write counter. The response could be from
         * another valid write request we generated on a previous boot that was
         * not completed. Read back the data and verify that the correct data
         * was written for this case. Note that this only works if we never
         * send more than one write request to the non-secure proxy at once. If
         * we later add support for pipelining rpmb operation we need to verify
         * the first n write requests here instead, where n is the max pipeline
         * depth of any build that may have run on the same device. We would
         * also need ensure that a superblock write request is not sent until
         * all other write requests have been validated and that an attacker
         * cannot have any saved write requests to the same filesystem with a
         * larger write-counter value than the superblock update (e.g. by
         * repeating a non-superblock write request until only one write
         * operation remains to be verified).
         */
        ret = rpmb_verify(state, buf, addr, count);
        if (ret < 0) {
            fprintf(stderr, "rpmb write counter failure\n");
            abort(); /* see comment in rpmb_write_data:err_sent */
        }
        state->first_write_complete = true;
    }
    return 0;
}

void rpmb_set_key(struct rpmb_state* state, const struct rpmb_key* key) {
    assert(state);
    state->key = *key;

    /*
     * We need to read the counter before reading the super blocks. If an
     * attacker writes to a super block after we read it, but before we read the
     * write counter, or next write would succeed without us detecting that the
     * in-memory super block does not match the on-disk state.
     */
    int ret;
    ret = rpmb_read_counter(state, &state->write_counter);
    if (ret < 0) {
        fprintf(stderr, "failed to read rpmb write counter\n");
        /*
         * Ignore errora. Any future write will fail since we initalized the
         * write_counter with the value where it expires.
         */
    }
}

int rpmb_init(struct rpmb_state** statep, void* mmc_handle) {
    struct rpmb_state* state = malloc(sizeof(*state));
    if (!state)
        return -ENOMEM;

    state->mmc_handle = mmc_handle;
    state->write_counter = RPMB_WRITE_COUNTER_EXPIRED_VALUE;
    state->first_write_complete = false;

    *statep = state;

    return 0;
}

void rpmb_uninit(struct rpmb_state* statep) {
    free(statep);
}
