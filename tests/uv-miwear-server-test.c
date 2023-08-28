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

#include <uv_ext.h>

#include <arch/inttypes.h>
#include <debug.h>
#include <string.h>

#ifndef CONFIG_MIWEAR_QAPP_PROXY_SERVER
#define CONFIG_MIWEAR_QAPP_PROXY_SERVER "miwear-server"
#endif

static uv_miwear_t server;

static void server_recv_cb(uv_miwear_t* miwear, int status,
    uv_miwear_message_t* msg, const char* client)
{
    if (msg->type == MIWEAR_MESSAGE_TYPE_STATUS) {
        const uv_miwear_status_t* miwear_status = msg->data;
        if (miwear_status->status == MIWEAR_STATUS_CLIENT_ONLINE) {
            printf("Server got connection from %s.\n",
                (char*)miwear_status->parameter);
        } else if (miwear_status->status == MIWEAR_STATUS_CONNECTION_CLOSED) {
            printf("Server closed connection with [%s]\n",
                (char*)miwear_status->parameter);
        } else {
            printf("Server got status message: %d\n", miwear_status->status);
        }
        return;
    }

    if (status != 0) {
        printf("server got unexpected status: %d\n", status);
        return;
    }

    printf("server got message: %s, len: %" PRIu32 ", status: %d\n",
        (const char*)msg->data, msg->len, status);
}

void server_sent_cb(uv_miwear_t* miwear, int status, uv_miwear_message_t* msg,
    void* cb_para)
{
    printf("server sent message: %s, len: %" PRIu32 ", status: %d\n",
        (const char*)msg->data, msg->len, status);
}

static void timer_run_cb(uv_timer_t* handle)
{
    static uint32_t count;
    static char data[64];
    snprintf(data, 64, "Hello from server. %" PRIu32 "", count++);
    uv_miwear_message_t msg;
    msg.data = data;
    msg.len = strlen(data) + 1;
    msg.type = MIWEAR_MESSAGE_TYPE_DATA;
    uv_miwear_send(&server, "com.xiaomi.xms.wearable.demo", &msg, server_sent_cb,
        NULL);
}

int miwear_server_main(int argc, char* argv[])
{
    static uv_loop_t default_loop_struct;
    uv_loop_init(&default_loop_struct);
    uv_loop_t* loop = &default_loop_struct;
    uv_timer_t timer_handle;

    uv_miwear_start_server(loop, &server, CONFIG_MIWEAR_QAPP_PROXY_SERVER,
        server_recv_cb);

    /* Sends message to client using timer */
    if (uv_timer_init(loop, &timer_handle) != 0) {
        goto testfail;
    }

    if (uv_timer_start(&timer_handle, timer_run_cb, 1, 1000) != 0) {
        goto testfail;
    }

    uv_run(loop, UV_RUN_DEFAULT);

    exit(0);

testfail:
    printf("TEST FAILED !\n");
    exit(1);
}
