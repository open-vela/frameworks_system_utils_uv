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

static uv_sysbrightness_ops_t sysbrightness;

int uv_sysbrightness_register(uv_sysbrightness_ops_t* brightness)
{
    if (!brightness) {
        return UV_EINVAL;
    }
    memcpy(&sysbrightness, brightness, sizeof(uv_sysbrightness_ops_t));
    return 0;
}

int uv_brightness_setval(uv_brightness_handle_t handle, int val, uv_brightness_cb_t cb, void* data)
{
    int ret;
    if (!sysbrightness.setval || !handle || !cb) {
        return UV_EINVAL;
    }

    ret = sysbrightness.setval(handle, val, cb, data);
    return ret;
}

int uv_brightness_getval(uv_brightness_handle_t handle, uv_brightness_cb_t cb, void* data)
{
    int ret;
    if (!sysbrightness.getval || !handle || !cb) {
        return UV_EINVAL;
    }

    ret = sysbrightness.getval(handle, cb, data);
    return ret;
}

int uv_brightness_setmode(uv_brightness_handle_t handle, int mode, uv_brightness_cb_t cb, void* data)
{
    int ret;
    if (!sysbrightness.setmode || !handle || !cb) {
        return UV_EINVAL;
    }

    ret = sysbrightness.setmode(handle, mode, cb, data);
    return ret;
}

int uv_brightness_getmode(uv_brightness_handle_t handle, uv_brightness_cb_t cb, void* data)
{
    int ret;
    if (!sysbrightness.getmode || !handle || !cb) {
        return UV_EINVAL;
    }

    ret = sysbrightness.getmode(handle, cb, data);
    return ret;
}

int uv_brightness_setkeepon(uv_brightness_handle_t handle, bool keep, uv_brightness_cb_t cb, void* data)
{
    int ret;
    if (!sysbrightness.keepscreenon || !handle || !cb) {
        return UV_EINVAL;
    }

    ret = sysbrightness.keepscreenon(handle, keep, cb, data);
    return ret;
}

int uv_brightness_recovery(uv_brightness_handle_t handle, uv_brightness_cb_t cb, void* data)
{
    int ret;
    if (!sysbrightness.recovery || !handle) {
        return UV_EINVAL;
    }

    ret = sysbrightness.recovery(handle, cb, data);
    return ret;
}

int uv_brightness_turnon(uv_brightness_handle_t handle, uv_brightness_cb_t cb, void* data)
{
    int ret;
    if (!sysbrightness.turnon || !handle) {
        return UV_EINVAL;
    }

    ret = sysbrightness.turnon(handle, cb, data);
    return ret;
}

int uv_brightness_init(uv_loop_t* loop, uv_brightness_handle_t* handle)
{
    int ret;
    if (!sysbrightness.init || !handle || !loop) {
        return UV_EINVAL;
    }
    ret = sysbrightness.init(loop, handle);
    return ret;
}

int uv_brightness_close(uv_brightness_handle_t handle)
{
    int ret;
    if (!sysbrightness.close || !handle) {
        return UV_EINVAL;
    }

    ret = sysbrightness.close(handle);
    return ret;
}
