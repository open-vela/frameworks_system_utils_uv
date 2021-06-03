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

#include <assert.h>
#include <debug.h>
#include <nuttx/config.h>
#include <nuttx/version.h>
#include <uv_ext.h>

/****************************************************************************
 * Preprocessor Definitions
 ****************************************************************************/

#ifndef CONFIG_PRODUCT_BRAND
#define CONFIG_PRODUCT_BRAND "Vela"
#endif

#ifndef CONFIG_PRODUCT_DEVICE_TYPE
#if CONFIG_ARCH_SIM
#define CONFIG_PRODUCT_DEVICE_TYPE "SIM"
#else
#define CONFIG_PRODUCT_DEVICE_TYPE "DevKit"
#endif
#endif

#ifndef CONFIG_PRODUCT_MANUFACTURER
#define CONFIG_PRODUCT_MANUFACTURER "XiaoMi Vela Team"
#endif

#ifndef CONFIG_PRODUCT_MODEL
#define CONFIG_PRODUCT_MODEL CONFIG_ARCH_BOARD
#endif

#ifndef CONFIG_PRODUCT_NAME
#define CONFIG_PRODUCT_NAME "Dev Product"
#endif

/****************************************************************************
 * Public Function
 ****************************************************************************/

int uv_get_devinfo(uv_devinfo_t *devinfo)
{
  DEBUGASSERT(devinfo != NULL);

  devinfo->brand = CONFIG_PRODUCT_BRAND;
  devinfo->device_type = CONFIG_PRODUCT_DEVICE_TYPE;
  devinfo->manufacturer = CONFIG_PRODUCT_MANUFACTURER;
  devinfo->model = CONFIG_PRODUCT_MODEL;
  devinfo->product = CONFIG_PRODUCT_NAME;
  devinfo->os_type = "RTOS";
  devinfo->os_version_name = CONFIG_VERSION_STRING;
  devinfo->platform_version_code = CONFIG_VERSION_BUILD;

  return 0;
}
