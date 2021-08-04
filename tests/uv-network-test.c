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
#include <uORB/uORBTopics.h>

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/* uv_getip的回调函数，单独获取. */
static void network_request_cb(int state, uv_response_t* response)
{
  if (!state && response->httpcode == 200) {
    if (response->body != NULL) {
      printf("%s %d body=%s\n", __FILE__, __LINE__, response->body);
    }
  } else {
    printf("%s %d state=%d fail\n", __FILE__, __LINE__, state);
  }
}

/* topic的回调函数. */
static void topic_cb(uv_topic_t *topic, int status, void *data, size_t datalen) {
  struct network_pubip *pubip = (struct network_pubip *)data;

  if (status == 0 && pubip) {
    printf("%s %d timestamp=%lld ip=%s\n", __FILE__, __LINE__, pubip->timestamp, pubip->addr.ss_data);
  } else {
    printf("%s %d state=%d fail\n", __FILE__, __LINE__, status);
  }
}

int main(int argc, char** argv)
{
  int ret;
  uv_network_t net;
  uv_topic_t topic_t;

  do {
    ret = uv_getip_init(uv_default_loop(), &net);
    if (ret != 0) {
      printf("%s %d\n", __FILE__, __LINE__);
      break;
    }

    ret = uv_getip(&net, network_request_cb);
    if (ret != 0) {
      uv_request_close(net.handle);
      printf("%s %d\n", __FILE__, __LINE__);
      break;
    }

    ret = uv_getip_advertise(uv_default_loop(), &net);
    if (ret != 0) {
      uv_request_close(net.handle);
      printf("%s %d\n", __FILE__, __LINE__);
      break;
    }

    ret = uv_topic_subscribe(uv_default_loop(), &topic_t, "network_pubip", topic_cb);
    if (ret != 0) {
      uv_request_close(net.handle);
      printf("%s %d\n", __FILE__, __LINE__);
      break;
    }

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);
    uv_request_close(net.handle);
    return 0;
  } while(0);

  printf("TEST FAILED !\n");
  return 0;
}
