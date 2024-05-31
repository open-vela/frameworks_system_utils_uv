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

#include <fcntl.h>
#include <kvdb.h>
#include <nuttx/config.h>
#include <nuttx/version.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <uv_ext.h>

#define CONFIG_FACT_WIFIMAC_KEY "ro.factory.mac_wifi"
#define CONFIG_DEVICE_BRAND_KEY "ro.product.brand"
#define CONFIG_DEVICE_MODEL_KEY "ro.product.model"
#define CONFIG_DEVICE_PRODUCT_KEY "ro.product.name"
#define CONFIG_DEVICE_MANUFACTURER_KEY "ro.product.manufacturer"
#define CONFIG_DEVICE_DEVICETYPE_KEY "ro.product.device.devicetype"
#define CONFIG_DEVICE_SCREENSHAPE_KEY "ro.product.device.screenshape"
#define CONFIG_DEVICE_SCREENDENSITY_KEY "ro.product.device.screendensity"
#define CONFIG_DEVICE_LANGUAGE_KEY "ro.system.language"
#define CONFIG_DEVICE_REGION_KEY "ro.system.region"
#define CONFIG_DEVICE_OSVERSIONCODE_KEY "ro.system.osversioncode"

#if defined(CONFIG_KVDB)
#define DEVICE_PROPERTY_GET(key, dst_buf, default_value) \
    property_get(key, dst_buf, default_value);
#else
#define DEVICE_PROPERTY_GET(ret, key, dst_buf, default_value) \
    strlen(strcpy(dst_buf, default_value));
#endif

#if defined(CONFIG_VIDEO_FB)
#include <nuttx/video/fb.h>
#endif
#if defined(CONFIG_LCD_DEV)
#include <nuttx/lcd/lcd_dev.h>
#endif
#if defined(CONFIG_LIB_BOARDCTL) && defined(CONFIG_BOARDCTL_UNIQUEID)
#include <sys/boardctl.h>
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
#ifdef CONFIG_DEVICE_NAME
#define CONFIG_PRODUCT_NAME CONFIG_DEVICE_NAME
#else
#define CONFIG_PRODUCT_NAME "Dev Product"
#endif
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
#define DEVINFO_LCD_NAME "/dev/fb0"
#define DEVINFO_LCD_IOCDIDEOINFO FBIOGET_VIDEOINFO
#ifdef CONFIG_QUICKAPP_TEST_FRAMEWORK
#define DEVINFO_LCD_PLANEINFO FBIOGET_PLANEINFO
#endif
#elif defined(CONFIG_LCD_DEV)
#define DEVINFO_LCD_NAME "/dev/lcd0"
#define DEVINFO_LCD_IOCDIDEOINFO LCDDEVIO_GETVIDEOINFO
#endif

static int uv_getscreeninfo(struct fb_videoinfo_s* videinfo)
{
    int fd, ret;

    fd = open(DEVINFO_LCD_NAME, O_RDWR);
    if (fd < 0) {
        return -errno;
    }

    ret = ioctl(fd, DEVINFO_LCD_IOCDIDEOINFO, videinfo);
    if (ret != 0) {
        close(fd);
        return ret;
    }

    close(fd);
    return 0;
}

#ifdef CONFIG_QUICKAPP_TEST_FRAMEWORK
static int uv_getplaneinfo(struct fb_planeinfo_s* planeinfo)
{
    int fd, ret;
    fd = open(DEVINFO_LCD_NAME, O_RDWR);
    if (fd < 0) {
        return -errno;
    }

    ret = ioctl(fd, DEVINFO_LCD_PLANEINFO, planeinfo);

    close(fd);
    return ret;
}
#endif

#endif

int uv_devinfobuff(char* buff, int size, int item)
{
    struct utsname uv_uanme;
    int ret;

    if (!buff || !size) {
        return UV_EINVAL;
    }

    switch (item) {
    case UV_EXT_DEVINFO_BRAND:
        DEVICE_PROPERTY_GET(CONFIG_DEVICE_BRAND_KEY, buff, CONFIG_PRODUCT_BRAND);
        break;
    case UV_EXT_DEVINFO_MANUFACTURER:
        DEVICE_PROPERTY_GET(CONFIG_DEVICE_MANUFACTURER_KEY, buff, CONFIG_PRODUCT_MANUFACTURER);
        break;
    case UV_EXT_DEVINFO_MODEL:
        DEVICE_PROPERTY_GET(CONFIG_DEVICE_MODEL_KEY, buff, CONFIG_PRODUCT_MODEL);
        break;
    case UV_EXT_DEVINFO_PRODUCT:
        DEVICE_PROPERTY_GET(CONFIG_DEVICE_PRODUCT_KEY, buff, CONFIG_PRODUCT_NAME);
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
        DEVICE_PROPERTY_GET(CONFIG_DEVICE_LANGUAGE_KEY, buff, CONFIG_LANGUAGE_NAME);
        break;
    case UV_EXT_DEVINFO_REGION:
        DEVICE_PROPERTY_GET(CONFIG_DEVICE_REGION_KEY, buff, CONFIG_REGION_NAME);
        break;
    case UV_EXT_DEVINFO_DID: {
#if defined(CONFIG_KVDB) && defined(CONFIG_CRYPTO_MBEDTLS)
        uv_buf_t input, output, ret;
        char kvbuf[PROP_VALUE_MAX] = { 0 };
        property_get(CONFIG_FACT_WIFIMAC_KEY, kvbuf, "NA");
        strlcpy(buff, kvbuf, size);
        input.base = (char*)buff;
        input.len = strlen(buff);
        if (uv_md("MD5", input, &output) == 0) {
            uv_hexify(output, &ret);
            strncpy(buff, ret.base, size - 1);
            buff[size - 1] = '\0';
            free(output.base);
            free(ret.base);
        }
#endif
        break;
    }
    case UV_EXT_DEVINFO_SERIAL: {
#if defined(CONFIG_KVDB) && defined(CONFIG_CRYPTO_MBEDTLS)
        char kvbuf[PROP_VALUE_MAX] = { 0 };
        property_get(CONFIG_FACT_WIFIMAC_KEY, kvbuf, "NA");
        strlcpy(buff, kvbuf, size);
#endif
        break;
    }
    default:
        return UV_EINVAL;
    }

    return 0;
}

int uv_getdevinfonumber(int* num, int item)
{
    int ret = 0;
#if defined(CONFIG_VIDEO_FB) || defined(CONFIG_LCD_DEV)
    struct fb_videoinfo_s videinfo;
#endif

    if (!num) {
        return UV_EINVAL;
    }

    *num = 0;
    switch (item) {
    case UV_EXT_DEVINFO_OSVERSIONCODE: {
#if defined(CONFIG_KVDB)
        *num = property_get_int32(CONFIG_DEVICE_OSVERSIONCODE_KEY, CONFIG_VERSION);
#endif
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

#if defined(CONFIG_KVDB)
        *num = property_get_int32(CONFIG_DEVICE_SCREENSHAPE_KEY, 0);
#endif
        sscanf((const char*)videinfo.moduleinfo, "%*[^:]:%*[^:]:%*[^:]:%*[^:]:%d", &shape);
        *num = *num == 0 ? shape : *num;
        break;
    }
#endif
#endif
    default:
        return UV_EINVAL;
    }

    return ret;
}

int uv_getdeviceinfo(uv_devinfo_t* info)
{
    struct utsname uv_uanme;
    int ret = 0;

    if (!info) {
        return UV_EINVAL;
    }

    memset(info, 0, sizeof(uv_devinfo_t));
#if defined(CONFIG_KVDB)
    {
        char kvbuf[PROP_VALUE_MAX] = { 0 };

        DEVICE_PROPERTY_GET(CONFIG_DEVICE_BRAND_KEY, info->brand, CONFIG_PRODUCT_BRAND);
        DEVICE_PROPERTY_GET(CONFIG_DEVICE_MANUFACTURER_KEY, info->manufacturer, CONFIG_PRODUCT_MANUFACTURER);
        DEVICE_PROPERTY_GET(CONFIG_DEVICE_MODEL_KEY, info->model, CONFIG_PRODUCT_MODEL);
        DEVICE_PROPERTY_GET(CONFIG_DEVICE_PRODUCT_KEY, info->product, CONFIG_PRODUCT_NAME);
        DEVICE_PROPERTY_GET(CONFIG_DEVICE_LANGUAGE_KEY, info->language, CONFIG_LANGUAGE_NAME);
        DEVICE_PROPERTY_GET(CONFIG_DEVICE_REGION_KEY, info->region, CONFIG_REGION_NAME);

        info->osversioncode = property_get_int32(CONFIG_DEVICE_OSVERSIONCODE_KEY, CONFIG_VERSION);

        property_get(CONFIG_DEVICE_SCREENDENSITY_KEY, kvbuf, "1.0");
        info->screendensity = atof(kvbuf);

        DEVICE_PROPERTY_GET(CONFIG_DEVICE_SCREENSHAPE_KEY, info->screenshape, "unknown");
        DEVICE_PROPERTY_GET(CONFIG_DEVICE_DEVICETYPE_KEY, info->devicetype, "unknown");
    }
#endif

    if ((ret = uname(&uv_uanme)) != 0) {
        return ret;
    }
    snprintf(info->ostype, sizeof(info->ostype),
        "%s", uv_uanme.sysname);
    snprintf(info->osversionname, sizeof(info->osversionname),
        "%s", uv_uanme.release);

#if defined(CONFIG_KVDB) && defined(CONFIG_CRYPTO_MBEDTLS)
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

    info->screenwidth = videinfo.xres;
    info->screenheight = videinfo.yres;
    info->screendensity = abs(info->screendensity) < 0.000001 ? 1.0f : info->screendensity;

#ifdef CONFIG_QUICKAPP_TEST_FRAMEWORK
    struct fb_planeinfo_s planeinfo = {};
    ret = uv_getplaneinfo(&planeinfo);
    if (ret < 0) {
        return ret;
    }
    info->bpp = planeinfo.bpp;
#endif

#endif
    return ret;
}