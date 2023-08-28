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

#include <arch/inttypes.h>
#include <debug.h>
#include <string.h>

#ifndef CONFIG_MIWEAR_QAPP_PROXY_SERVER
#define CONFIG_MIWEAR_QAPP_PROXY_SERVER "miwear-server"
#endif

static uv_miwear_t client;
static uv_loop_t* loop;
static uint32_t count;

static void client_recv_cb(uv_miwear_t* miwear, int status,
    uv_miwear_message_t* msg, const char* client)

{
    if (msg->type == MIWEAR_MESSAGE_TYPE_STATUS) {
        const uv_miwear_status_t* miwear_status = msg->data;
        if (miwear_status->status == MIWEAR_STATUS_CLIENT_ID_SENT) {
            printf("Client ID sent.\n");
        } else if (miwear_status->status == MIWEAR_STATUS_CONNECTION_CLOSED) {
            printf("Client closed.\n");
        } else if (miwear_status->status == MIWEAR_STATUS_CONNECT_FAILED) {
            printf("Client failed to connect server.\n");
        }
        return;
    }

    if (status != 0) {
        printf("client got unexpected status: %d\n", status);
        return;
    }

    printf("client got message: %s, len: %" PRIu32 ", status: %d\n",
        (const char*)msg->data, msg->len, status);
}

void client_sent_cb(uv_miwear_t* miwear, int status, uv_miwear_message_t* msg,
    void* cb_para)
{
    printf("client sent message: %s, len: %" PRIu32 ", status: %d\n",
        (const char*)msg->data, msg->len, status);
}

static void timer_run_cb(uv_timer_t* handle)
{
    static char data[64];
    snprintf(data, 64, "Hello from client. %" PRIu32 "", count++);
    uv_miwear_message_t msg;
    msg.data = data;
    msg.len = strlen(data) + 1;
    msg.type = MIWEAR_MESSAGE_TYPE_DATA;
    uv_miwear_send(&client, NULL, &msg, client_sent_cb, NULL);
    if (count == 5) {
        uv_close((uv_handle_t*)handle, NULL);
        uv_miwear_close(&client);
        uv_stop(loop);
    }
}

int miwear_client_main(int argc, char* argv[])
{
    uv_timer_t timer_handle;
    uv_loop_t default_loop_struct;
    loop = &default_loop_struct;
    uv_loop_init(loop);
    count = 0;

    uv_miwear_start_client(loop, &client, "com.xiaomi.xms.wearable.demo",
        CONFIG_MIWEAR_QAPP_PROXY_SERVER, client_recv_cb);

    /* Sends message to client using timer */
    if (uv_timer_init(loop, &timer_handle) != 0) {
        goto testfail;
    }

    if (uv_timer_start(&timer_handle, timer_run_cb, 1, 1000) != 0) {
        goto testfail;
    }

    uv_run(loop, UV_RUN_DEFAULT);

    printf("TEST PASSED !\n");
    exit(0);

testfail:
    printf("TEST FAILED !\n");
    exit(1);
}
