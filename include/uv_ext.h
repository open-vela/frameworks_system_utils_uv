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

#ifndef __SYSTEM_LIBUV_EXT_INCLUDE_UV_EXT_H
#define __SYSTEM_LIBUV_EXT_INCLUDE_UV_EXT_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <uv.h>

typedef struct uv_devinfo_s uv_devinfo_t;

struct uv_devinfo_s
{
  const char *brand;
  const char *manufacturer;
  const char *model;
  const char *product;
  const char *os_type;
  const char *os_version_name;
  const char *platform_version_code;
  const char *device_type;
};

void uv_get_devinfo(FAR uv_devinfo_t *devinfo);

#endif
