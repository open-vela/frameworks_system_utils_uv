/*
 * Copyright (C) 2020 Xiaomi Corporation
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

#ifndef __SYSTEM_LIBUV_EXT_ASYNC_QUEUE_H
#define __SYSTEM_LIBUV_EXT_ASYNC_QUEUE_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdint.h>
#include <uv.h>
#include "../../libuv/src/queue.h"

/****************************************************************************
 * Public Types
 ****************************************************************************/

typedef struct uv_async_queue_s uv_async_queue_t;

typedef void (*uv_async_queue_cb)(uv_async_queue_t*, void*);

typedef struct uv_async_queue_s {
    /* uv_async_t must be placed first in the structure */
    uv_async_t async;
    uv_mutex_t mutex;
    uv_async_queue_cb cb;
    uv_close_cb close_cb;
    void* data;
    struct uv__queue queue;
} uv_async_queue_t;

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * uv_async_queue_init
 ****************************************************************************/

int uv_async_queue_init(uv_loop_t* loop, uv_async_queue_t* async,
    uv_async_queue_cb async_queue_cb);

/****************************************************************************
 * uv_async_queue_send
 ****************************************************************************/

int uv_async_queue_send(uv_async_queue_t* async, void* data);

/****************************************************************************
 * uv_async_queue_close
 ****************************************************************************/

void uv_async_queue_close(uv_async_queue_t* queue_async, uv_close_cb cb);

#ifdef __cplusplus
}
#endif

#endif
