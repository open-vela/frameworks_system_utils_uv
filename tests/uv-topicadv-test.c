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

#include <alloca.h>
#include <stdlib.h>
#include <uv_ext.h>

static void uv_topicadv_help(void)
{
    printf("uv_topicadv usage: uv_topicadv start/stop\n");
}

int main(int argc, char* argv[])
{
    int ret;

    if (argc != 2) {
        uv_topicadv_help();
        return -EINVAL;
    }

    if (strcmp("start", argv[1]) == 0) {
        ret = uv_topicadv_init(uv_default_loop());
        if (ret < 0) {
            printf("topic advertise failed, ret=%d", ret);
            return ret;
        }

        printf("topic advertise success");
        uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    } else if (strcmp("stop", argv[1]) == 0) {
        ret = uv_topicadv_close();
        if (ret < 0) {
            printf("topic unadvertise failed, ret=%d", ret);
            return ret;
        }

        printf("topic unadvertise success");

    } else {
        uv_topicadv_help();
    }

    return 0;
}
