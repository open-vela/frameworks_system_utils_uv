
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

#include <stdlib.h>
#include <uv_ext.h>

static uv_async_queue_t async_queue;

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static void async_queue_cb(uv_async_queue_t* queue_async, void* data)
{
    syslog(LOG_INFO, "async data: %s\n", (char*)data);
}

static void work_cb(uv_work_t* handle)
{
    while (1) {
        uv_async_queue_send(&async_queue, "uv_async_send test 1");
        uv_async_queue_send(&async_queue, "uv_async_send test 2");
        uv_async_queue_send(&async_queue, "uv_async_send test 3");
        usleep(100);
    }
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int main(void)
{
    uv_loop_t* loop;
    uv_timer_t timer;
    uv_work_t work_queue;

    loop = malloc(sizeof(uv_loop_t));
    uv_loop_init(loop);
    uv_timer_init(loop, &timer);
    uv_queue_work(loop, &work_queue, work_cb, NULL);
    uv_async_queue_init(loop, &async_queue, async_queue_cb);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
    free(loop);
    return 0;
}
