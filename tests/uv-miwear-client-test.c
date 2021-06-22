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

#include <debug.h>
#include <string.h>

#ifndef CONFIG_MIWEAR_QAPP_PROXY_SERVER
#define CONFIG_MIWEAR_QAPP_PROXY_SERVER "miwear-server"
#endif

#define warn _warn
#define info _info
#define err _err

static uv_miwear_t client;
static uv_loop_t* loop;
static uint32_t count;

static void client_recv_cb(uv_miwear_t* miwear, int status, const void* data,
                           uint32_t len, miwear_message_type_t type)
{
  if (type == MIWEAR_MESSAGE_TYPE_STATUS) {
    const message_status_data_t* miwear_status = data;
    if(miwear_status->status == MIWEAR_CLIENT_ID_SENT){
        info("Client ID sent.\n");
    }
    else if(miwear_status->status == MIWEAR_CONNECTION_CLOSED){
        info("Client closed.\n");
    }
    else if(miwear_status->status == MIWEAR_CONNECT_FAILED){
        info("Client failed to connect server.\n");
    }
    return;
  }

  if (status != 0) {
    err("client got unexpected status: %d\n", status);
    return;
  }

  static char tmp[1024];
  len = len >= 1023 ? 1022 : len;
  memcpy(tmp, data, len);
  tmp[len] = '\0';

  info("client got message: %s, len: %d, status: %d\n", tmp, len, status);
}

void client_sent_cb(uv_miwear_t* miwear, int status, const void* data,
                    uint32_t len, miwear_message_type_t type)
{
  info("client sent message: %s, len: %d, status: %d\n", data, len, status);
}

static void timer_run_cb(uv_timer_t* handle)
{
  static char msg[64];
  snprintf(msg, 64, "Hello from client. %d", count++);
  uv_miwear_send_to_server(&client, msg, strlen(msg) + 1,
                           MIWEAR_MESSAGE_TYPE_DATA, client_sent_cb);
  if (count == 5) {
    uv_close((uv_handle_t*)handle, NULL);
    uv_miwear_stop_client(&client);
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
                         CONFIG_MIWEAR_QAPP_PROXY_SERVER,
                         client_recv_cb);

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