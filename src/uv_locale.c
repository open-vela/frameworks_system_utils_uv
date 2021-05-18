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

/****************************************************************************
 * Name: uv_getlocale
 *
 * Description:
 *   TODO：完善NuttX的libc locale支持.
 *   https://doc.quickapp.cn/features/system/configuration.html
 *
 ****************************************************************************/

int uv_getlocale(uv_locale_t *locale) {
  if (!locale) {
    return UV_EINVAL;
  }

  locale->language = "zh";
  locale->country_region = "CN";

  return 0;
}
