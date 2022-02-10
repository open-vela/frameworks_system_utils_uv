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
#include <sys/types.h>
#include <netutils/netlib.h>
#include <net/if.h>

#define UV_NETSTATUS_IFNAME "wlan0"

static void uv_netstatus_ip_callback(int state, uv_response_t* response)
{
  int result = ERROR;
  uv_network_t* handle = (uv_network_t*)(response->userp);

  if (!state && response->httpcode == 200) {
    result = OK;
  }

  handle->cb(response->body, result, handle->data);
}

int uv_network_init(uv_loop_t *loop, uv_network_t *handle) {
  int ret;

  if (!loop || !handle) {
    return UV_EINVAL;
  }

  ret = uv_request_init(loop, &handle->handle);
  if (ret != 0) {
    return ret;
  }

  return 0;
}

int uv_network_close(uv_network_t *handle) {
  int ret;

  if (!handle || !handle->handle) {
    return UV_EINVAL;
  }

  ret = uv_request_close(handle->handle);
  if (ret != 0) {
    return ret;
  }

  return 0;
}

int uv_netstatus_gettype(uint8_t *type) {
  int ret;
  uint8_t flags;

  if (!type) {
    return UV_EINVAL;
  }

#ifdef CONFIG_ARCH_SIM
  *type = UV_NETSTATUS_WIFI;
#else
  /* Get current network status. */

  ret = netlib_getifstatus(UV_NETSTATUS_IFNAME, &flags);
  if (ret != 0) {
    return ret;
  }

  if (IFF_IS_RUNNING(flags)) {
    *type = UV_NETSTATUS_WIFI;
    return 0;
  }

  /* Todo: Get bluetooth connection status. */

  *type = UV_NETSTATUS_NONE;
#endif

  return 0;
}

int uv_netstatus_getip(uv_network_t *handle, uv_netstatus_ipcb_t cb) {
  if (!handle || !cb) {
    return UV_EINVAL;
  }

  handle->cb = cb;

  /* Get public network ip. */

  uv_request_create(&handle->fetch);
  uv_request_set_url(handle->fetch, "http://icanhazip.com");
  uv_request_set_userp(handle->fetch, handle);
  uv_request_set_atrribute(handle->fetch, UV_REQUEST, NULL);
  uv_request_commit(handle->handle, handle->fetch, uv_netstatus_ip_callback);

  return 0;
}
