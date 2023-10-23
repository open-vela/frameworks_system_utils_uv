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

#include <string.h>
#include <uv_ext.h>

/****************************************************************************
 * Name: uv_getlocale
 *
 * Description:
 *   TODO：完善NuttX的libc locale支持.
 *   https://doc.quickapp.cn/features/system/configuration.html
 *
 ****************************************************************************/

int uv_getlocale(uv_locale_t* locale)
{
    int ret;
    char buff[PROP_VALUE_MAX];
    char *pbuff, *pstr;

    if (!locale) {
        return UV_EINVAL;
    }

    ret = uv_property_get(NULL, UV_EXT_LOCALE_LANG_KEY, buff, NULL, NULL, NULL);
    if (ret <= 0) {
        return ret;
    }

    pbuff = buff;

    pstr = strsep(&pbuff, "_");
    if (!pstr) {
        return UV_ENOENT;
    }

    snprintf(locale->language, sizeof(locale->language), "%s", pstr);

    pstr = strsep(&pbuff, "_");
    if (!pstr) {
        return UV_ENOENT;
    }

    snprintf(locale->country_region, sizeof(locale->country_region), "%s", pstr);

    return ret;
}
