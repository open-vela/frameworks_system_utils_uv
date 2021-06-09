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
  uv_timer_t handle;
  int fd;
  int count;          /* Number of brightness applications used. */
  int lightvalue;
  int lightmode;
  bool keepon;
  bool sysflag;       /* Flag of whether it is currently on the system page */
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

int uv_system_brightness_setval(int val) {
  int ret;

  if (val < 0)
    return UV_EINVAL;

  ret = ioctl(sysbrightness.fd, LCDDEVIO_SETPOWER, val);
  if (ret != 0) {
      return ret;
  }
  sysbrightness.lightvalue = val;
  sysbrightness.sysflag = true;

  return 0;
}

int uv_system_brightness_getval(int *val) {
  int ret;

  if (!val)
    return UV_EINVAL;

  if (sysbrightness.count == 0) {
    ret = ioctl(sysbrightness.fd, LCDDEVIO_GETPOWER, val);
    if (ret != 0) {
       return ret;
    }
    sysbrightness.lightvalue = *val;
  } else {
    *val = sysbrightness.lightvalue;
  }

  return 0;
}

int uv_system_brightness_recovery(void) {
  int ret;

  ret = ioctl(sysbrightness.fd, LCDDEVIO_SETPOWER, sysbrightness.lightvalue);
  if (ret != 0) {
      return ret;
  }
  sysbrightness.sysflag = true;

  return 0;
}

int uv_brightness_setval(uv_brightness_t *handle, int val) {
  int ret;

  sysbrightness.sysflag = false;

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

  sysbrightness.sysflag = false;

  if (!handle || *val)
    return UV_EINVAL;

  ret = ioctl(handle->devid, LCDDEVIO_GETPOWER, val);
  if (ret != 0) {
    return ret;
  }

  return 0;
}

int uv_brightness_setmode(uv_brightness_t *handle, int mode) {
  int ret;

  sysbrightness.sysflag = false;

  if (!handle)
    return UV_EINVAL;

  if (mode && sysbrightness.lightmode == 0) {
    ret = uv_timer_start(&sysbrightness.handle, uv_brightness_cb, 1000, 1000);
    if (ret != 0) {
      return ret;
    }
    sysbrightness.lightmode = 1;
  }

  handle->lightmode = mode;

  return 0;
}

int uv_brightness_getmode(uv_brightness_t *handle, int *mode) {
  sysbrightness.sysflag = false;

  if (!handle || *mode)
    return UV_EINVAL;

  *mode = handle->lightmode;
  return 0;
}

int uv_brightness_setkeepon(uv_brightness_t *handle, bool keep) {
  sysbrightness.sysflag = false;

  if (!handle)
    return UV_EINVAL;

  handle->keepon = keep;
  return 0;
}

int uv_brightness_init(uv_loop_t *loop, uv_brightness_t *handle) {
  int val, ret, fd;

  if (!loop || !handle) {
    return UV_EINVAL;
  }

  if (sysbrightness.count == 0) {
    fd = open(CONFIG_UV_LCD_DEVNAME, O_RDWR);
    if (fd < 0) {
      return -errno;
    }

    ret = uv_system_brightness_getval(&val);
    if (ret != 0) {
      goto initfail;
    }

    /* 添加一个topic获取光照强度，从而自动设置屏幕亮度 */

    if (uv_topic_subscribe(loop, &topic, "sensor_light", uv_topic_light_cb) < 0) {
      goto initfail;
    }

    if (uv_topic_set_frequency(&topic, 2) != 0) {
      uv_topic_unsubscribe(&topic);
      goto initfail;
    }

    ret = uv_timer_init(loop, &sysbrightness.handle);
    if (ret != 0) {
      uv_topic_unsubscribe(&topic);
      goto initfail;
    }

    sysbrightness.fd = fd;
    sysbrightness.lightmode = 0;
  }

  sysbrightness.count++;
  sysbrightness.sysflag = false;
  handle->active = 1;
  handle->devid = sysbrightness.fd;
  handle->keepon = 1;
  handle->lightmode = 0;
  handle->lightvalue = val;

  return 0;

initfail:
  close(fd);
  return ret;
}

int uv_brightness_close(uv_brightness_t *handle) {
  if (!handle) {
    return UV_EINVAL;
  }

  sysbrightness.sysflag = false;
  if (--sysbrightness.count == 0) {
    close(sysbrightness.fd);
    uv_close((uv_handle_t*)&sysbrightness.handle, NULL);
    return uv_topic_unsubscribe(&topic);
  }

  return 0;
}

int uv_brightness_free(void) {
  close(sysbrightness.fd);
  uv_close((uv_handle_t*)&sysbrightness.handle, NULL);
  return uv_topic_unsubscribe(&topic);
}