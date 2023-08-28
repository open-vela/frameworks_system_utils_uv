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

#include <stdio.h>
#include <stdlib.h>
#include <uv_ext.h>

/****************************************************************************
 * Typedef
 ****************************************************************************/

enum {
    PROPERTY_OP_GET = 0,
    PROPERTY_OP_SET,
    PROPERTY_OP_DELETE,
    PROPERTY_OP_CLEAR,
    PROPERTY_OP_COMMIT,
};

struct uv_property_s {
    uv_work_t work_req;
    uv_property_cb cb;
    void* arg;
    uint8_t op;
    char* key;
    char* value;
    char* default_value;
    int status;
};
typedef struct uv_property_s uv_property_t;

static void uv_property_clear_cb(const char* key, const char* value, void* cookie)
{
    property_delete(key);
}

static void uv__property_work_cb(uv_work_t* req)
{
    uv_property_t* property = req->data;

    switch (property->op) {
    case PROPERTY_OP_GET:
        property->status = property_get(property->key, property->value,
            property->default_value);
        break;
    case PROPERTY_OP_SET:
        property->status = property_set(property->key, property->value);
        break;
    case PROPERTY_OP_DELETE:
        property->status = property_delete(property->key);
        break;
    case PROPERTY_OP_CLEAR:
        property->status = property_list(uv_property_clear_cb, NULL);
        break;
    case PROPERTY_OP_COMMIT:
        property->status = property_commit();
        break;
    default:
        break;
    }
}

static void uv__property_after_work_cb(uv_work_t* req, int status)
{
    uv_property_t* property = req->data;
    status = (status < 0) ? status : property->status;

    property->cb(status, property->key, property->value, property->arg);

    /** release memory */
    free(property);
}

int uv__property_alloc(uv_property_t** property, const char* key,
    const char* value, const char* def_val)
{
    if (!property) {
        return UV_EINVAL;
    }

    /** check length of key and value */
    uint32_t key_len = key ? strlen(key) + 1 : 0;
    uint32_t val_len = value ? strlen(value) + 1 : 0;
    uint32_t def_val_len = def_val ? strlen(def_val) + 1 : 0;
    if ((key_len > PROPERTY_KEY_MAX) || (val_len > PROPERTY_VALUE_MAX)
        || (def_val_len > PROPERTY_VALUE_MAX)) {
        return UV_E2BIG;
    }

    uint32_t len = sizeof(uv_property_t) + key_len + val_len + def_val_len;
    *property = malloc(len);
    if (!(*property)) {
        return UV_ENOMEM;
    }
    memset(*property, 0, len);

    char* buff = (char*)(*property + 1);
    uint32_t offset = 0;
    if (key_len > 0) {
        (*property)->key = buff + offset;
        offset += key_len;
        memcpy((*property)->key, key, key_len);
    }
    if (val_len > 0) {
        (*property)->value = buff + offset;
        offset += val_len;
        memcpy((*property)->value, value, val_len);
    }
    if (def_val_len > 0) {
        (*property)->default_value = buff + offset;
        offset += def_val_len;
        memcpy((*property)->default_value, def_val, def_val_len);
    }
    return 0;
}

int uv_property_set(uv_loop_t* loop, const char* key, const char* value,
    uv_property_cb cb, void* arg)
{
    /** synchronous mode */
    if (!cb) {
        return property_set(key, value);
    }

    if (!loop || !key || !value)
        return UV_EINVAL;

    uv_property_t* property = NULL;
    int ret = uv__property_alloc(&property, key, value, NULL);
    if (ret != 0) {
        return ret;
    }

    property->cb = cb;
    property->arg = arg;
    property->op = PROPERTY_OP_SET;
    property->work_req.data = property;

    return uv_queue_work(loop, &property->work_req, uv__property_work_cb,
        uv__property_after_work_cb);
}

int uv_property_get(uv_loop_t* loop, const char* key, char* value,
    const char* default_value, uv_property_cb cb, void* arg)
{
    /** synchronous mode */
    if (!cb) {
        return property_get(key, value, default_value);
    }

    if (!loop || !key || !value)
        return UV_EINVAL;

    uv_property_t* property = NULL;
    int ret = uv__property_alloc(&property, key, NULL, default_value);
    if (ret != 0) {
        return ret;
    }

    property->cb = cb;
    property->arg = arg;
    property->op = PROPERTY_OP_GET;
    property->value = value;
    property->work_req.data = property;

    return uv_queue_work(loop, &property->work_req, uv__property_work_cb,
        uv__property_after_work_cb);
}

int uv_property_delete(uv_loop_t* loop, const char* key, uv_property_cb cb,
    void* arg)
{
    /** synchronous mode */
    if (!cb) {
        return property_delete(key);
    }

    if (!loop || !key)
        return UV_EINVAL;

    uv_property_t* property = NULL;
    int ret = uv__property_alloc(&property, key, NULL, NULL);
    if (ret != 0) {
        return ret;
    }

    property->cb = cb;
    property->arg = arg;
    property->op = PROPERTY_OP_DELETE;
    property->work_req.data = property;

    return uv_queue_work(loop, &property->work_req, uv__property_work_cb,
        uv__property_after_work_cb);
}

int uv_property_clear(uv_loop_t* loop, uv_property_cb cb, void* arg)
{
    /** synchronous mode */
    if (cb == NULL) {
        return property_list(uv_property_clear_cb, NULL);
    }

    if (loop == NULL)
        return UV_EINVAL;

    uv_property_t* property = NULL;
    int ret = uv__property_alloc(&property, NULL, NULL, NULL);
    if (ret != 0) {
        return ret;
    }

    property->cb = cb;
    property->arg = arg;
    property->op = PROPERTY_OP_CLEAR;
    property->work_req.data = property;

    return uv_queue_work(loop, &property->work_req, uv__property_work_cb,
        uv__property_after_work_cb);
}

int uv_property_commit(uv_loop_t* loop, uv_property_cb cb, void* arg)
{
    /** synchronous mode */
    if (!cb) {
        return property_commit();
    }

    if (!loop)
        return UV_EINVAL;

    uv_property_t* property = NULL;
    int ret = uv__property_alloc(&property, NULL, NULL, NULL);
    if (ret != 0) {
        return ret;
    }
    property->cb = cb;
    property->arg = arg;
    property->op = PROPERTY_OP_COMMIT;
    property->work_req.data = property;

    return uv_queue_work(loop, &property->work_req, uv__property_work_cb,
        uv__property_after_work_cb);
}
