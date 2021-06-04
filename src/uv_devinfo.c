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
#include <fcntl.h>

#if CONFIG_ARCH_BOARD_SIM
#include <nuttx/video/fb.h>
#elif CONFIG_ARCH_BOARD_CUSTOM
#include <nuttx/lcd/lcd_dev.h>
#endif

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
#define DEVINFO_BARND 1
/****************************************************************************
 * Public Function
 ****************************************************************************/

int uv_get_devinfo(uv_devinfo_t *devinfo)
{
  int fd, ret;
  struct fb_videoinfo_s videinfo;

  if (!devinfo) {
    return UV_EINVAL;
  }

  devinfo->brand = CONFIG_PRODUCT_BRAND;
  devinfo->device_type = CONFIG_PRODUCT_DEVICE_TYPE;
  devinfo->manufacturer = CONFIG_PRODUCT_MANUFACTURER;
  devinfo->model = CONFIG_PRODUCT_MODEL;
  devinfo->product = CONFIG_PRODUCT_NAME;
  devinfo->os_type = "RTOS";
  devinfo->os_version_name = CONFIG_VERSION_STRING;
  devinfo->os_version_code = CONFIG_VERSION_BUILD;
  devinfo->lanuage = "zh";
  devinfo->region = "CN";

#if CONFIG_ARCH_BOARD_SIM
  fd = open("dev/fb0", O_RDWR);
  if (fd < 0) {
    return -errno;
  }

  ret = ioctl(fd, FBIOGET_VIDEOINFO, &videinfo);
  if (ret != 0) {
    return ret;
  }

  devinfo->screenwidth = videinfo.xres;
  devinfo->screenheight = videinfo.yres;
#elif CONFIG_ARCH_BOARD_CUSTOM
  fd = open("dev/lcd", O_RDWR);
  if (fd < 0) {
    return -errno;
  }

  ret = ioctl(fd, LCDDEVIO_GETVIDEOINFO, &videinfo);
  if (ret != 0) {
    return ret;
  }

  devinfo->screenwidth = videinfo.xres;
  devinfo->screenheight = videinfo.yres;
#else
  devinfo->screenwidth = 0;
  devinfo->screenheight = 0;
#endif

  return 0;
}
