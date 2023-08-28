/*
 * Copyright (C) 2020 Xiaomi Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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

int main(int argc, char* argv[])
{
    char devinfo[32];
    int num, i;
    uv_devinfo_t info;

    for (i = UV_EXT_DEVINFO_SCREENWIDTH; i < UV_EXT_DEVINFO_BRAND; i++) {
        if (uv_getdevinfonumber(&num, i) != 0) {
            goto testfail;
        }
        printf("[%02d], %d\n", i, num);
    }

    for (i = UV_EXT_DEVINFO_BRAND; i < UV_EXT_DEVINFO_MAX; i++) {
        if (uv_devinfobuff(devinfo, sizeof(devinfo), i) != 0) {
            goto testfail;
        }
        printf("[%02d], %s\n", i, devinfo);
    }

    if (uv_getdeviceinfo(&info) != 0) {
        goto testfail;
    }
    printf("brand:%s\n", info.brand);
    printf("manufacturer:%s\n", info.manufacturer);
    printf("model:%s\n", info.model);
    printf("product:%s\n", info.product);
    printf("ostype:%s\n", info.ostype);
    printf("osversionname:%s\n", info.osversionname);
    printf("language:%s\n", info.language);
    printf("region:%s\n", info.region);
    printf("did:%s\n", info.did);
    printf("screenshape:%d\n", info.screenshape);
    printf("osversioncode:%d\n", info.osversioncode);
    printf("screenwidth:%d\n", info.screenwidth);
    printf("screenheight:%d\n", info.screenheight);

    printf("TEST PASSED !\n");
    exit(0);

testfail:
    printf("TEST FAILED !\n");
    exit(1);
}