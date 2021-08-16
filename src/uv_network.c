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
#include <system/state.h>
#include <uORB/uORB.h>
#include <uORB/uORBTopics.h>
#include <arpa/inet.h>

typedef struct uv_network_topic {
  uv_timer_t timer_handle;
  uv_request_session_t *handle;
  bool onceinit;
  int  ipfd;
  int  cref;
  void *data;
} uv_network_topic_t;

static uv_network_topic_t uv_net = {0};
extern struct network_state adv1;

/* Get the callback function of ip and push it through orb_publish. */
static void uv_network_publish_cb(int state, uv_response_t* response)
{
  int ret;
  struct network_pubip pubip = {0};
  struct in_addr addr = {0};
  if (!state && response->httpcode == 200) {
    if (response->body != NULL) {
      pubip.timestamp = orb_absolute_time();

      ret = strlen(response->body) - 1;
      if (response->body[ret] == '\n') {
        response->body[ret] = '\0';
      }

      ret = inet_aton(response->body, &addr);
      if (ret == 0) {
        return;
      }
      memcpy(pubip.addr.ss_data, &addr, sizeof(addr));

      /* publish data */
      orb_publish(ORB_ID(network_pubip), uv_net.ipfd, &pubip);
    }
  }
}

/* Callback function, used to obtain ip in a loop. */
static void timer_advertise_cb(uv_timer_t* handle) {
  uv_network_topic_t *iptopic = (uv_network_topic_t*)handle;
  uv_network_t *net = (uv_network_t*)iptopic->data;

  uv_request_create(&net->fetch);
  uv_request_set_url(net->fetch, "http://icanhazip.com");
  uv_request_set_atrribute(net->fetch, UV_REQUEST, NULL);
  uv_request_commit(net->handle, net->fetch, uv_network_publish_cb);
}

int uv_network_init(uv_loop_t *loop, uv_network_t *handle) {
  int ret;

  if (!loop || !handle) {
    return UV_EINVAL;
  }

  if (uv_net.onceinit == true) {
    handle->handle = uv_net.handle;
    return 0;
  }

  ret = uv_request_init(loop, &uv_net.handle);
  if (ret != 0) {
    return ret;
  }
 handle->handle = uv_net.handle;
  uv_net.onceinit = true;

  return 0;
}

int uv_network_close(uv_network_t *handle) {
  int ret;

  if (!handle || !handle->handle) {
    return UV_EINVAL;
  }

  ret = uv_pubip_unadvertise(handle);
  if (ret != 0) {
    return ret;
  }

  if (uv_net.cref > 0) {
    return 0;
  }

  ret = uv_request_close(uv_net.handle);
  if (ret != 0) {
    return ret;
  }

  memset(&uv_net, 0, sizeof(uv_net));
  return 0;
}

int uv_network_state(uv_network_t *handle, uv_request_cb cb) {
  if (!handle || !handle->handle || !cb) {
    return UV_EINVAL;
  }

  /* 1. Get current network status. */

  handle->stat.type = adv1.type;

  /* 2. Get public network ip. */

  uv_request_create(&handle->fetch);
  uv_request_set_url(handle->fetch, "http://icanhazip.com");
  uv_request_set_userp(handle->fetch, handle->data);
  uv_request_set_atrribute(handle->fetch, UV_REQUEST, NULL);
  uv_request_commit(handle->handle, handle->fetch, cb);

  return 0;
}

int uv_pubip_advertise(uv_loop_t *loop, uv_network_t *handle) {
  int ret;

  if (!handle || !handle->handle) {
    return UV_EINVAL;
  }

  if (++uv_net.cref > 1) {
    return 0;
  }

  uv_net.ipfd = orb_advertise(ORB_ID(network_pubip), NULL);
  if (uv_net.cref < 0) {
    uv_net.cref--;
    return -errno;
  }

  /* Set up private data. */
  uv_net.data = handle;

  ret = uv_timer_init(loop, &uv_net.timer_handle);
  if (ret != 0) {
    orb_unadvertise(uv_net.ipfd);
    uv_net.cref--;
    return ret;
  }

  ret = uv_timer_start(&uv_net.timer_handle, timer_advertise_cb, 0, 5000);
  if (ret != 0) {
    uv_timer_stop(&uv_net.timer_handle);
    orb_unadvertise(uv_net.ipfd);
    uv_net.cref--;
    return ret;
  }

  return 0;
}

int uv_pubip_unadvertise(uv_network_t *handle) {
  int ret;

  if (!handle || !handle->handle) {
    return UV_EINVAL;
  }

  if (--uv_net.cref > 0) {
    return 0;
  }

  ret = uv_timer_stop(&uv_net.timer_handle);
  if (ret != 0) {
    uv_net.cref++;
    return ret;
  }

  ret = orb_unadvertise(uv_net.ipfd);
  if (ret != 0) {
    uv_net.cref++;
    return ret;
  }

  return 0;
}

