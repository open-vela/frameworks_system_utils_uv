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
    uv_locale_t locale;
    int ret;

    if (uv_getlocale(&locale) <= 0) {
        ret = uv_property_set(NULL, (const char*)UV_EXT_LOCALE_LANG_KEY, "zh_CN", NULL, NULL);
        if (ret != 0) {
            goto testfail;
        }

        if (uv_getlocale(&locale) <= 0) {
            goto testfail;
        }
    }

    printf("language:%s\n", locale.language);
    printf("region:%s\n\n", locale.country_region);

    printf("TEST PASSED !\n");
    exit(0);

testfail:
    printf("TEST FAILED !\n");
    exit(1);
}