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

static const char *uv_netstatus_ifname_list[]={
  "wlan0",
  "bt-pan",
  NULL
};

static bool uv_ifstatus_isup(const char *name){
  int ret;
  uint8_t flags;

  /* Get current network status. */

  ret = netlib_getifstatus(name, &flags);
  if (ret != 0) {
    return false;
  }

  if (IFF_IS_RUNNING(flags)) {
    return true;
  }

  return false;
}

int uv_netstatus_gettype(uint8_t *type) {
  int i;

  if (!type) {
    return UV_EINVAL;
  }

  /* Todo: Get bluetooth connection status. */
  for (i = 0; uv_netstatus_ifname_list[i] != NULL; i++)
  {
    if (uv_ifstatus_isup(uv_netstatus_ifname_list[i])){
      *type = UV_NETSTATUS_WIFI;
      return 0;
    }
  }

#if defined(CONFIG_ARCH_SIM)
  *type = UV_NETSTATUS_WIFI;
#else
  *type = UV_NETSTATUS_NONE;
#endif

  return 0;
}
