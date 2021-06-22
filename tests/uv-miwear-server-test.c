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

#include <debug.h>
#include <string.h>

#define warn _warn
#define info _info
#define err _err

static uv_miwear_t server;

static void server_recv_cb(uv_miwear_t* miwear, int status, const void* data,
                           uint32_t len, miwear_message_type_t type)
{
  if (type == MIWEAR_MESSAGE_TYPE_STATUS) {
    const message_status_data_t* miwear_status = data;
    if (miwear_status->status == MIWEAR_CLIENT_ONLINE) {
      info("Server got connection from %s.\n", (char*)miwear_status->parameter);
    } else if (miwear_status->status == MIWEAR_CONNECTION_CLOSED) {
      info("Server closed connection with [%s]\n",
           (char*)miwear_status->parameter);
    } else {
      info("Server got status message: %d\n", miwear_status->status);
    }
    return;
  }

  if (status != 0) {
    err("server got unexpected status: %d\n", status);
    return;
  }

  static char tmp[1024];
  len = len >= 1023 ? 1022 : len;
  memcpy(tmp, data, len);
  tmp[len] = '\0';

  info("server got message: %s, len: %d, status: %d\n", tmp, len, status);
}

void server_sent_cb(uv_miwear_t* miwear, int status, const void* data,
                    uint32_t len, miwear_message_type_t type)
{
  info("server sent message: %s, len: %d, status: %d\n", data, len, status);
}

static void timer_run_cb(uv_timer_t* handle)
{
  static uint32_t count;
  static char msg[64];
  snprintf(msg, 64, "Hello from server. %d", count++);
  uv_miwear_send_to_client(&server, "client123", msg, strlen(msg) + 1,
                           MIWEAR_MESSAGE_TYPE_DATA, server_sent_cb);
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