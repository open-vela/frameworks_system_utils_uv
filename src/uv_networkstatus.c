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

#include <net/if.h>
#include <netutils/netlib.h>
#include <sys/types.h>
#include <uv_ext.h>

struct uv_netstatus {
    const char* ifname;
    const char* desc;
    uint8_t type;
};

static const struct uv_netstatus uv_netstatus_list[] = {
    { "wlan0", "wifi", UV_NETSTATUS_WIFI },
    { "wlan1", "wifi", UV_NETSTATUS_WIFI },
    { "cellsurf", "cellular", UV_NETSTATUS_CELLULAR },
    { "bt-pan", "bluetooth", UV_NETSTATUS_BLUETOOTH },
    { "bt-net", "bluetooth", UV_NETSTATUS_BLUETOOTH },
    { "tun0", "tun", UV_NETSTATUS_TUN },
    { "eth0", "ethernet", UV_NETSTATUS_ETHERNET },
    { NULL, "none", UV_NETSTATUS_NONE }
};

static bool uv_ifstatus_isup(const char* name)
{
    int ret;
    uint8_t flags;

    /* Get current network status. */

    ret = netlib_getifstatus(name, &flags);
    if (ret != 0) {
        syslog(LOG_ERR, "uv_ifstatus_isup: getifstatus failed:%d, %d\n", ret, errno);
        return false;
    }

    syslog(LOG_INFO, "uv_ifstatus_isup: flags: %d\n", flags);
    if (IFF_IS_RUNNING(flags)) {
        return true;
    }

    return false;
}

int uv_netstatus_gettype(uint8_t* type)
{
    int i;

    if (!type) {
        return UV_EINVAL;
    }

    for (i = 0; uv_netstatus_list[i].ifname != NULL; i++) {
        if (uv_ifstatus_isup(uv_netstatus_list[i].ifname)) {
            break;
        }
    }

    *type = uv_netstatus_list[i].type;
    syslog(LOG_INFO, "uv_netstatus_gettype: status :%s\n", uv_netstatus_list[i].desc);
    return 0;
}
