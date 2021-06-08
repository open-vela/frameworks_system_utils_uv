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
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <uv_ext.h>

#if defined(CONFIG_ARCH_SIM) && defined(CONFIG_SIM_X11FB)
#include <nuttx/video/fb.h>
#elif defined(CONFIG_ARCH_BOARD_CUSTOM) && defined(CONFIG_LCD_DEV)
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
#ifdef CONFIG_ARCH_BOARD
#define CONFIG_PRODUCT_MODEL CONFIG_ARCH_BOARD
#else
#define CONFIG_PRODUCT_MODEL CONFIG_ARCH_BOARD_CUSTOM_NAME
#endif
#endif

#ifndef CONFIG_PRODUCT_NAME
#define CONFIG_PRODUCT_NAME "Dev Product"
#endif

#ifndef CONFIG_LANGUAGE_NAME
#define CONFIG_LANGUAGE_NAME "zh"
#endif

#ifndef CONFIG_REGION_NAME
#define CONFIG_REGION_NAME "CN"
#endif

/****************************************************************************
 * Public Function
 ****************************************************************************/

int uv_get_devinfo(char *devinfo, int size, int id) {
  struct utsname uv_uanme;
  int ret;

  if (!devinfo || !size) {
    return UV_EINVAL;
  }

  switch (id) {
    case UV_EXT_DEVINFO_BRAND:
      snprintf((char*)devinfo, size, "%s", CONFIG_PRODUCT_BRAND);
    break;
    case UV_EXT_DEVINFO_MANUFACTURER:
      snprintf((char*)devinfo, size, "%s", CONFIG_PRODUCT_MANUFACTURER);
    break;
    case UV_EXT_DEVINFO_MODEL:
      snprintf((char*)devinfo, size, "%s", CONFIG_PRODUCT_MODEL);
    break;
    case UV_EXT_DEVINFO_PRODUCT:
      snprintf((char*)devinfo, size, "%s", CONFIG_PRODUCT_NAME);
    break;
    case UV_EXT_DEVINFO_OSTYPE:
      if ((ret = uname(&uv_uanme)) != 0) {
        return ret;
      }
      snprintf(devinfo, size, "%s", uv_uanme.sysname);
    break;
    case UV_EXT_DEVINFO_OSVERSIONNAME:
      if ((ret = uname(&uv_uanme)) != 0) {
        return ret;
      }
      snprintf(devinfo, size, "%s", uv_uanme.release);
    break;
    case UV_EXT_DEVINFO_OSVERSIONCODE:
      if ((ret = uname(&uv_uanme)) != 0) {
        return ret;
      }
      snprintf(devinfo, size, "%s", uv_uanme.version);
    break;
    case UV_EXT_DEVINFO_LANGUAGE:
      snprintf((char*)devinfo, size, "%s", CONFIG_LANGUAGE_NAME);
    break;
    case UV_EXT_DEVINFO_REGION:
      snprintf((char*)devinfo, size, "%s", CONFIG_REGION_NAME);
    break;
    default:
      return UV_EINVAL;
  }

  return 0;
}

int uv_get_versioncode(int *vsersioncode, int id) {
  if (!vsersioncode) {
    return UV_EINVAL;
  }

  if (id == UV_EXT_DEVINFO_OSVERSIONCODE) {
    *vsersioncode = CONFIG_VERSION;
    return 0;
  } else {
    return UV_EINVAL;
  }
}

int uv_get_resolution(int *wh, int id) {
  int fd, ret;
  struct fb_videoinfo_s videinfo = {};

  if (!wh) {
    return UV_EINVAL;
  }

#if defined(CONFIG_ARCH_SIM) && defined(CONFIG_SIM_X11FB)
  fd = open("/dev/fb0", O_RDWR);
  if (fd < 0) {
    return -errno;
  }

  ret = ioctl(fd, FBIOGET_VIDEOINFO, &videinfo);
  if (ret != 0) {
    return ret;
  }
#elif defined(CONFIG_ARCH_BOARD_CUSTOM) && defined(CONFIG_LCD_DEV)
  fd = open("/dev/lcd0", O_RDWR);
  if (fd < 0) {
    return -errno;
  }

  ret = ioctl(fd, LCDDEVIO_GETVIDEOINFO, &videinfo);
  if (ret != 0) {
    return ret;
  }
#endif
  close(fd);

  if (UV_EXT_DEVINFO_SCREENWIDTH == id) {
    *wh = videinfo.xres;
  } else if (UV_EXT_DEVINFO_SCREENHEIGHT == id) {
    *wh = videinfo.yres;
  } else {
    return UV_EINVAL;
  }

  return 0;
}