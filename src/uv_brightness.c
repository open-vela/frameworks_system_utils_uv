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
#include <nuttx/lcd/lcd_dev.h>
#include <sys/ioctl.h>
#include <sensor/light.h>

#define CONFIG_UV_LCD_DEVNAME "/dev/lcd0"


/* System brightness information. */

typedef struct uv_sysbrightness_s {
  int count;        /* Number of brightness applications used. */
  int lightvalue;
  int lightmode;
  int keepon;
  float topic_light;
}uv_sysbrightness_t;

static uv_sysbrightness_t sysbrightness;
static uv_topic_t topic;

static void uv_topic_light_cb(uv_topic_t *ptopic, int status, void *data, size_t datalen) {
  struct sensor_light *light = data;

  if (status == 0 && light) {
    sysbrightness.topic_light = light->light;
  }
}

static void uv_brightness_cb(uv_timer_t *handle) {
  uv_brightness_t *bhandle = (uv_brightness_t*)handle;
  if (bhandle->lightmode && bhandle->active) {

    /* TODO: 根据光照强度调整屏幕亮度 */

  }
}

int uv_system_brightness_setval(uv_brightness_t *handle, int val) {
  int ret;

  if (!handle || !val)
    return UV_EINVAL;

  ret = ioctl(handle->devid, LCDDEVIO_SETPOWER, val);
  if (ret != 0) {
      return ret;
  }
  sysbrightness.lightvalue = val;

  return 0;
}

int uv_system_brightness_getval(uv_brightness_t *handle, int *val) {
  int ret;

  if (!handle || !val)
    return UV_EINVAL;

  if (sysbrightness.count == 0) {
    ret = ioctl(handle->devid, LCDDEVIO_GETPOWER, val);
    if (ret != 0) {
       return ret;
    }
    sysbrightness.lightvalue = *val;
  } else {
    *val = sysbrightness.lightvalue;
  }

  return 0;
}

int uv_brightness_setval(uv_brightness_t *handle, int val) {
  int ret;

  if (!handle)
    return UV_EINVAL;

  ret = ioctl(handle->devid, LCDDEVIO_SETPOWER, val);
  if (ret != 0) {
    return ret;
  }
  handle->lightvalue = val;

  return 0;
}

int uv_brightness_getval(uv_brightness_t *handle, int *val) {
  int ret;

  if (!handle || *val)
    return UV_EINVAL;

  ret = ioctl(handle->devid, LCDDEVIO_GETPOWER, val);
  if (ret != 0) {
    return ret;
  }
  handle->lightvalue = *val;

  return 0;
}

int uv_brightness_setmode(uv_brightness_t *handle, int mode) {
  int ret;

  if (!handle)
    return UV_EINVAL;

  handle->lightmode = mode;
  if (handle->lightmode) {
    ret = uv_timer_start(&handle->handle, uv_brightness_cb, 1000, 1000);
    if (ret != 0) {
      return ret;
    }
  } else {
    ret = uv_timer_stop(&handle->handle);
    if (ret != 0) {
      return ret;
    }
  }

  return 0;
}

int uv_brightness_getmode(uv_brightness_t *handle, int *mode) {
  if (!handle || *mode)
    return UV_EINVAL;

  *mode = handle->lightmode;
  return 0;
}

int uv_brightness_setkeepon(uv_brightness_t *handle, int keep) {
  if (!handle)
    return UV_EINVAL;

  handle->keepon = keep;
  return 0;
}

int uv_brightness_init(uv_loop_t *loop, uv_brightness_t *handle) {
  int val, ret;

  if (!loop || !handle) {
    return UV_EINVAL;
  }

  int fd = open(CONFIG_UV_LCD_DEVNAME, O_RDWR);
  if (fd < 0) {
    return -errno;
  }

  if (sysbrightness.count++ == 0) {
    ret = uv_system_brightness_getval(handle, &val);
    if (ret != 0) {
      goto initfail;
    }

    /* 添加一个topic获取光照强度，从而自动设置屏幕亮度 */

    if (uv_topic_subscribe(loop, &topic, "sensor_light", uv_topic_light_cb) < 0) {
      goto initfail;
    }

    if (uv_topic_set_frequency(&topic, 2) != 0) {
      goto initfail;
    }
  }

  ret = uv_timer_init(loop, &handle->handle);
  if (ret != 0) {
    goto initfail;
  }

  handle->active = 0;
  handle->devid = fd;
  handle->keepon = 1;
  handle->lightmode = 0;
  handle->lightvalue = val;

  return 0;

initfail:
  close(fd);
  return ret;
}

int uv_brightness_free(uv_brightness_t *handle) {
  if (!handle) {
    return UV_EINVAL;
  }

  close(handle->devid);
  uv_close((uv_handle_t*)&handle->handle, NULL);
  if (--sysbrightness.count == 0) {
    return uv_topic_unsubscribe(&topic);
  }

  return 0;
}