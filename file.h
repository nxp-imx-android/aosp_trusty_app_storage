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
#include "block_cache.h"
#include "block_mac.h"

struct fs;
struct transaction;

#define FS_PATH_MAX (64 + 128)

struct file_handle {
    struct list_node node;
    struct block_mac to_commit_block_mac;
    struct block_mac committed_block_mac;
    struct block_mac block_mac;
    data_block_t to_commit_size;
    data_block_t size;
    bool used_by_tr;
};

/**
 * struct file_info - On-disk file entry
 * @size:       File size in bytes.
 * @reserved:   Reserved for future use. Write 0, read ignore.
 * @path:       File path and name.
 */
struct file_info {
    data_block_t size;
    uint64_t reserved;
    char path[FS_PATH_MAX];
};

/**
 * struct file_iterate_state - File iterator state
 */
struct file_iterate_state {
    /**
     * file - Found file callback
     * @iter:       Iterator object.
     * @tr:         Transaction object.
     * @block_mac:  File entry block_mac.
     * @added:      %true if file was added in current transaction and has not
     *              yet been committed
     */
    bool (*file)(struct file_iterate_state* iter,
                 struct transaction* tr,
                 const struct block_mac* block_mac,
                 bool added,
                 bool removed);
};

size_t get_file_block_size(struct fs* fs);
const void* file_get_block(struct transaction* tr,
                           struct file_handle* file,
                           data_block_t file_block,
                           struct obj_ref* ref);
void* file_get_block_write(struct transaction* tr,
                           struct file_handle* file,
                           data_block_t file_block,
                           bool read,
                           struct obj_ref* ref);
void file_block_put(const void* data, struct obj_ref* data_ref);
void file_block_put_dirty(struct transaction* tr,
                          struct file_handle* file,
                          data_block_t file_block,
                          void* data,
                          struct obj_ref* data_ref);

const struct file_info* file_get_info(struct transaction* tr,
                                      const struct block_mac* block_mac,
                                      struct obj_ref* ref);
void file_info_put(const struct file_info* data, struct obj_ref* data_ref);

bool file_get_size(struct transaction* tr,
                   struct file_handle* file,
                   data_block_t* size);
void file_set_size(struct transaction* tr,
                   struct file_handle* file,
                   data_block_t size);

void file_print(struct transaction* tr, const struct file_handle* file);
void files_print(struct transaction* tr);

void file_transaction_complete(struct transaction* tr,
                               struct block_mac* new_files_block_mac);
void file_transaction_complete_failed(struct transaction* tr);

void file_transaction_success(struct transaction* tr);
void file_transaction_failed(struct transaction* tr);

/* TODO: move to dir? */
enum file_create_mode {
    FILE_OPEN_NO_CREATE,
    FILE_OPEN_CREATE,
    FILE_OPEN_CREATE_EXCLUSIVE,
};
bool file_open(struct transaction* tr,
               const char* path,
               struct file_handle* file,
               enum file_create_mode create);
void file_close(struct file_handle* file);
bool file_delete(struct transaction* tr,
                 const char* path); /* returns true if path was found */
bool file_move(struct transaction* tr,
               struct file_handle* file,
               const char* dest_path,
               enum file_create_mode dest_create);
bool file_iterate(struct transaction* tr,
                  const char* start_path,
                  bool added,
                  struct file_iterate_state* state);
