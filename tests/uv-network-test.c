/****************************************************************************
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <uv_ext.h>
#include <system/state.h>
#include <uORB/uORB.h>
#include <arpa/inet.h>

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/* uv_getip的回调函数，单独获取. */

void uv_netstatus_ipcb(char *data, int result, void *extra) {
  if (result == 0) {
    printf("ip: %s\n", data);
  } else {
    printf("ip callback fail\n");
  }
}

int main(int argc, char** argv)
{
  int ret;
  uint8_t type;
  uv_network_t net = { 0 };
  uv_loop_t loop;

  uv_loop_init(&loop);

  ret = uv_network_init(&loop, &net);
  if (ret != 0) {
    printf("%s %d fail\n", __FILE__, __LINE__);
    return ret;
  }

  ret = uv_netstatus_gettype(&type);
  if (ret > 0) {
    printf("network type: %d\n", type);
  } else {
    printf("get network type fail\n");
  }

  uv_netstatus_getip(&net, uv_netstatus_ipcb);
  uv_netstatus_getip(&net, uv_netstatus_ipcb);
  uv_netstatus_getip(&net, uv_netstatus_ipcb);

  uv_run(&loop, UV_RUN_DEFAULT);
  uv_network_close(&net);
  uv_loop_close(&loop);

  return 0;
}
