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

#include <nuttx/config.h>
#include <nuttx/version.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <uv_ext.h>
#include <string.h>
#include <cutils/properties.h>

#define CONFIG_FACT_WIFIMAC_KEY "ro.factory.mac_wifi"

#if defined(CONFIG_VIDEO_FB)
#  include <nuttx/video/fb.h>
#endif
#if defined(CONFIG_LCD_DEV)
#  include <nuttx/lcd/lcd_dev.h>
#endif
#if defined(CONFIG_LIB_BOARDCTL) && defined(CONFIG_BOARDCTL_UNIQUEID)
#  include <sys/boardctl.h>
#endif

/****************************************************************************
 * Preprocessor Definitions
 ****************************************************************************/

#ifndef CONFIG_PRODUCT_BRAND
#define CONFIG_PRODUCT_BRAND "Vela"
#endif

#ifndef CONFIG_PRODUCT_DEVICE_TYPE
#ifdef CONFIG_ARCH_SIM
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

#define UV_EXT_DEVINFO_DID_INFO "202107261219"

/****************************************************************************
 * Public Function
 ****************************************************************************/

#if defined(CONFIG_VIDEO_FB) || defined(CONFIG_LCD_DEV)
#if defined(CONFIG_VIDEO_FB) && !defined(CONFIG_LCD_DEV)
#  define DEVINFO_LCD_NAME          "/dev/fb0"
#  define DEVINFO_LCD_IOCDIDEOINFO  FBIOGET_VIDEOINFO
#elif defined(CONFIG_LCD_DEV)
#  define DEVINFO_LCD_NAME          "/dev/lcd0"
#  define DEVINFO_LCD_IOCDIDEOINFO  LCDDEVIO_GETVIDEOINFO
#endif

static int uv_getscreeninfo(struct fb_videoinfo_s *videinfo) {
  int fd, ret;

  fd = open(DEVINFO_LCD_NAME, O_RDWR);
  if (fd < 0) {
    return -errno;
  }

  ret = ioctl(fd, DEVINFO_LCD_IOCDIDEOINFO, videinfo);
  if (ret != 0) {
    return ret;
  }

  close(fd);
  return 0;
}
#endif

int uv_devinfobuff(char *buff, int size, int item) {
  struct utsname uv_uanme;
  int ret;

  if (!buff || !size) {
    return UV_EINVAL;
  }

  switch (item) {
    case UV_EXT_DEVINFO_BRAND:
      snprintf((char*)buff, size, "%s", CONFIG_PRODUCT_BRAND);
      break;
    case UV_EXT_DEVINFO_MANUFACTURER:
      snprintf((char*)buff, size, "%s", CONFIG_PRODUCT_MANUFACTURER);
      break;
    case UV_EXT_DEVINFO_MODEL:
      snprintf((char*)buff, size, "%s", CONFIG_PRODUCT_MODEL);
      break;
    case UV_EXT_DEVINFO_PRODUCT:
      snprintf((char*)buff, size, "%s", CONFIG_PRODUCT_NAME);
      break;
    case UV_EXT_DEVINFO_OSTYPE:
      if ((ret = uname(&uv_uanme)) != 0) {
        return ret;
      }
      snprintf(buff, size, "%s", uv_uanme.sysname);
      break;
    case UV_EXT_DEVINFO_OSVERSIONNAME:
      if ((ret = uname(&uv_uanme)) != 0) {
        return ret;
      }
      snprintf(buff, size, "%s", uv_uanme.release);
      break;
    case UV_EXT_DEVINFO_LANGUAGE:
      snprintf((char*)buff, size, "%s", CONFIG_LANGUAGE_NAME);
      break;
    case UV_EXT_DEVINFO_REGION:
      snprintf((char*)buff, size, "%s", CONFIG_REGION_NAME);
      break;
    case UV_EXT_DEVINFO_DID:
    {
      #if defined(CONFIG_KVDB) && defined(CONFIG_LIB_MBEDTLS)
      uv_buf_t input, output, ret;
      char kvbuf[PROP_VALUE_MAX] = { 0 };
      property_get(CONFIG_FACT_WIFIMAC_KEY, kvbuf, "NA");
      strlcpy(buff, kvbuf, size);
      input.base = (char*)buff;
      input.len = strlen(buff);
      if (uv_md("MD5", input, &output) == 0) {
        uv_hexify(output, &ret);
        strncpy(buff, ret.base, size - 1);
        buff[size -1] = '\0';
        free(output.base);
        free(ret.base);
      }
      #endif
      break;
    }
    default:
      return UV_EINVAL;
  }

  return 0;
}

int uv_getdevinfonumber(int *num, int item) {
  int ret = 0;
#if defined(CONFIG_VIDEO_FB) || defined(CONFIG_LCD_DEV)
  struct fb_videoinfo_s videinfo;
#endif

  if (!num) {
    return UV_EINVAL;
  }

  switch (item) {
    case UV_EXT_DEVINFO_OSVERSIONCODE: {
      *num = CONFIG_VERSION;
      break;
    }

#if defined(CONFIG_VIDEO_FB) || defined(CONFIG_LCD_DEV)
    case UV_EXT_DEVINFO_SCREENWIDTH: {
      ret = uv_getscreeninfo(&videinfo);
      if (ret < 0) {
        break;
      }

      *num = videinfo.xres;
      break;
    }

    case UV_EXT_DEVINFO_SCREENHEIGHT: {
      ret = uv_getscreeninfo(&videinfo);
      if (ret < 0) {
        break;
      }

      *num = videinfo.yres;
      break;
    }

#if defined(CONFIG_FB_MODULEINFO)
    case UV_EXT_DEVINFO_SCREENSHAPE: {
      int shape;

      sscanf((const char*)videinfo.moduleinfo, "%*[^:]:%*[^:]:%*[^:]:%*[^:]:%d", &shape);
      *num = shape;
      break;
    }
#endif
#endif
    default:
      return  UV_EINVAL;
  }

  return ret;
}

int uv_getdeviceinfo(uv_devinfo_t *info)
{
  struct utsname uv_uanme;
  int ret = 0;

  if (!info) {
    return UV_EINVAL;
  }

  snprintf(info->brand, sizeof(info->brand),
           "%s", CONFIG_PRODUCT_BRAND);

  snprintf(info->manufacturer, sizeof(info->manufacturer),
           "%s", CONFIG_PRODUCT_MANUFACTURER);

  snprintf(info->model, sizeof(info->model),
           "%s", CONFIG_PRODUCT_MODEL);

  snprintf(info->product, sizeof(info->product),
           "%s", CONFIG_PRODUCT_NAME);

  if ((ret = uname(&uv_uanme)) != 0) {
    return ret;
  }
  info->osversioncode = CONFIG_VERSION;
  snprintf(info->ostype, sizeof(info->ostype),
           "%s", uv_uanme.sysname);
  snprintf(info->osversionname, sizeof(info->osversionname),
           "%s", uv_uanme.release);

  snprintf(info->language, sizeof(info->language),
           "%s", CONFIG_LANGUAGE_NAME);
  snprintf(info->region, sizeof(info->region),
           "%s", CONFIG_REGION_NAME);
  snprintf(info->manufacturer, sizeof(info->manufacturer),
           "%s", CONFIG_PRODUCT_MANUFACTURER);

#if defined(CONFIG_KVDB) && defined(CONFIG_LIB_MBEDTLS)
  {
    uv_buf_t input, output, ret;
    char kvbuf[PROP_VALUE_MAX] = { 0 };
    property_get(CONFIG_FACT_WIFIMAC_KEY, kvbuf, "NA");
    strlcpy(info->did, kvbuf, sizeof(info->did));
    input.base = (char*)info->did;
    input.len = strlen(info->did);
    if (uv_md("MD5", input, &output) == 0) {
      uv_hexify(output, &ret);
      strncpy(info->did, ret.base, sizeof(info->did) - 1);
      info->did[sizeof(info->did) - 1] = '\0';
      free(output.base);
      free(ret.base);
    }
  }
#else
  snprintf(info->did, sizeof(info->did), "%s", UV_EXT_DEVINFO_DID_INFO);
#endif

#if defined(CONFIG_VIDEO_FB) || defined(CONFIG_LCD_DEV)
  struct fb_videoinfo_s videinfo = {};

  ret = uv_getscreeninfo(&videinfo);
  if (ret < 0) {
    return ret;
  }

  info->screenwidth  = videinfo.xres;
  info->screenheight = videinfo.yres;
#if defined(CONFIG_FB_MODULEINFO)
  int shape;

  sscanf((const char*)videinfo.moduleinfo, "%*[^:]:%*[^:]:%*[^:]:%*[^:]:%d", &shape);
  info->screenshape = shape;
#endif
#endif

  return ret;
}
