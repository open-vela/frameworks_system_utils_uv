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

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stddef.h>
#include <stdlib.h>
#include <uv_ext.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define uv_queue_debug(format, ...) uv_log_debug(async_queue, format, ##__VA_ARGS__)
#define uv_queue_info(format, ...) uv_log_info(async_queue, format, ##__VA_ARGS__)
#define uv_queue_error(format, ...) uv_log_error(async_queue, format, ##__VA_ARGS__)

/****************************************************************************
 * Private Types
 ****************************************************************************/

struct uv__async_queue_handle_s {
    void* data;
    struct uv__queue node;
};

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static void uv__acync_queue_cb(uv_async_t* async)
{
    uv_async_queue_t* async_queue = async->data;
    struct uv__async_queue_handle_s* queue_handle;
    struct uv__queue* node;

    uv_mutex_lock(&async_queue->mutex);
    while (!uv__queue_empty(&async_queue->queue)) {
        node = uv__queue_head(&async_queue->queue);
        queue_handle = uv__queue_data(node, struct uv__async_queue_handle_s, node);
        uv__queue_remove(node);
        uv_mutex_unlock(&async_queue->mutex);
        async_queue->cb(async_queue, queue_handle->data);
        uv_mutex_lock(&async_queue->mutex);
        free(queue_handle);
    }

    uv_mutex_unlock(&async_queue->mutex);
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * uv_async_queue_init
 ****************************************************************************/

int uv_async_queue_init(uv_loop_t* loop, uv_async_queue_t* async_queue,
    uv_async_queue_cb async_queue_cb)
{
    int ret;

    ret = uv_async_init(loop, &async_queue->async, uv__acync_queue_cb);
    if (ret != 0) {
        uv_queue_error("async init failed, %d", ret);
        return ret;
    }

    uv_queue_debug("uv_async_queue_init");
    async_queue->cb = async_queue_cb;
    async_queue->async.data = async_queue;
    uv_mutex_init(&async_queue->mutex);
    uv__queue_init(&async_queue->queue);
    return ret;
}

/****************************************************************************
 * uv_async_queue_send
 ****************************************************************************/

int uv_async_queue_send(uv_async_queue_t* async_queue, void* data)
{
    int ret;

    struct uv__async_queue_handle_s* handle = malloc(sizeof(*handle));
    handle->data = data;
    uv_mutex_lock(&async_queue->mutex);
    uv__queue_insert_tail(&async_queue->queue, &handle->node);
    uv_mutex_unlock(&async_queue->mutex);
    ret = uv_async_send(&async_queue->async);
    if (ret != 0) {
        uv_queue_error("async init failed, %d", ret);
    }

    return ret;
}

/****************************************************************************
 * uv_async_queue_close
 ****************************************************************************/

void uv_async_queue_close(uv_async_queue_t* async_queue, uv_close_cb cb)
{
    struct uv__async_queue_handle_s* queue_handle;
    struct uv__queue* node;

    uv_mutex_lock(&async_queue->mutex);
    while (!uv__queue_empty(&async_queue->queue)) {
        node = uv__queue_head(&async_queue->queue);
        queue_handle = uv__queue_data(node, struct uv__async_queue_handle_s, node);
        uv__queue_remove(node);
        uv_queue_error("data is discarded: %p", queue_handle->data);
        free(queue_handle);
    }

    uv_queue_debug("uv_async_queue_close");
    uv_mutex_unlock(&async_queue->mutex);
    uv_mutex_destroy(&async_queue->mutex);
    uv_close((uv_handle_t*)&async_queue->async, cb);
}
