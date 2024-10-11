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

#include "unqlite.h"
#include "uv_ext.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define assert_res(x, code) \
    do {                    \
        if (!(x)) {         \
            res = code;     \
            goto error;     \
        }                   \
    } while (0)

#ifndef container_of
#define container_of(ptr, type, member) \
    ((type*)((char*)(ptr)-offsetof(type, member)))
#endif

enum {
    UV_DB_OP_SET,
    UV_DB_OP_GET,
    UV_DB_OP_DELETE,
    UV_DB_OP_KEY,
    UV_DB_OP_LIST,
};

typedef struct uv_db_s {
    unqlite* db;
    uv_loop_t* loop;
    struct uv__queue queue;
    int closing;
} uv_db_t;

typedef struct uv_db_req_s {
    int op;
    int status;
    void* arg;
    const char* key;
    uv_buf_t value;
    uv_db_callback cb;
    uv_db_t* handle;
    uv_work_t work_req;
    uv_sem_t* sem;
    struct uv__queue node;
} uv_db_req_t;

static int db_get(uv_db_t* handle, const char* key, uv_buf_t* value)
{
    int res;
    unqlite_int64 len = 0;
    value->base = NULL;

    res = unqlite_kv_fetch(handle->db, key, -1, NULL, &len);
    assert_res(res == UNQLITE_OK, res);

    value->base = (char*)malloc(len + 1);
    assert_res(value->base, UV_ENOMEM);
    value->base[len] = '\0';

    res = unqlite_kv_fetch(handle->db, key, -1, value->base, &len);
    assert_res(res == 0, res);
    value->len = len;

    return 0;
error:
    free(value->base);
    value->base = NULL;
    return res;
}

static void async_cb(uv_async_t* handle)
{
    uv_db_req_t* req = handle->data;
    req->cb(0, req->key, req->value, req->arg);

    free((void*)req->key);
    free(req->value.base);
    uv_sem_post(req->sem);
}

static int db_list(uv_db_t* handle, uv_db_callback cb, void* arg, uv_db_req_t* req)
{
    unqlite_kv_cursor* curros;
    int res, key_len;
    char* key = NULL;
    uv_buf_t value = { 0 };
    unqlite_int64 value_len;

    res = unqlite_kv_cursor_init(handle->db, &curros);
    assert_res(res == UNQLITE_OK, res);

    for (unqlite_kv_cursor_first_entry(curros); unqlite_kv_cursor_valid_entry(curros);
         unqlite_kv_cursor_next_entry(curros)) {
        res = unqlite_kv_cursor_key(curros, NULL, &key_len);
        assert_res(res == UNQLITE_OK, res);
        key = malloc(key_len + 1);
        assert_res(key, UV_ENOMEM);
        res = unqlite_kv_cursor_key(curros, key, &key_len);
        key[key_len] = '\0';
        assert_res(res == UNQLITE_OK, res);

        res = unqlite_kv_cursor_data(curros, NULL, &value_len);
        assert_res(res == UNQLITE_OK, res);
        value.base = malloc(value_len + 1);
        assert_res(value.base, UV_ENOMEM);
        res = unqlite_kv_cursor_data(curros, value.base, &value_len);
        assert_res(res == UNQLITE_OK, res);
        value.len = (size_t)value_len;
        value.base[value_len] = '\0';

        if (req) {
            uv_async_t* async = req->work_req.data;
            req->key = key;
            req->value = value;
            req->cb = cb;
            async->data = req;
            res = uv_async_send(async);
            assert_res(res == 0, res);
            uv_sem_wait(req->sem);
        } else {
            cb(res, key, value, arg);
            free(key);
            free(value.base);
        }
    }

    if (req != NULL) {
        req->cb = NULL;
    }
    unqlite_kv_cursor_release(handle->db, curros);

    return 0;
error:
    free(key);
    free(value.base);
    req->key = NULL;
    req->cb = NULL;
    if (handle->db) {
        unqlite_kv_cursor_release(handle->db, curros);
    }
    return res;
}

static int db_index_to_key(uv_db_t* handle, int32_t* index, char** key)
{
    unqlite_kv_cursor* curros;
    int res, key_len, offset = 0;
    *key = NULL;

    res = unqlite_kv_cursor_init(handle->db, &curros);
    assert_res(res == UNQLITE_OK, res);

    for (unqlite_kv_cursor_first_entry(curros); unqlite_kv_cursor_valid_entry(curros);
         unqlite_kv_cursor_next_entry(curros)) {
        if (offset++ < *(uint32_t*)index) {
            continue;
        }
        res = unqlite_kv_cursor_key(curros, NULL, &key_len);
        assert_res(res == UNQLITE_OK, res);
        *key = malloc(key_len + 1);
        assert_res(*key, UV_ENOMEM);
        res = unqlite_kv_cursor_key(curros, *key, &key_len);
        (*key)[key_len] = '\0';
        assert_res(res == UNQLITE_OK, res);
        break;
    }

    if (*index != -1) {
        res = UV_EINVAL;
    }
    assert_res(offset > *index, UV_EINVAL);

    *index = offset - 1;
    unqlite_kv_cursor_release(handle->db, curros);
    return 0;
error:
    free(*key);
    if (handle->db) {
        unqlite_kv_cursor_release(handle->db, curros);
    }
    return res;
}

static void db_work_cb(uv_work_t* work_req)
{
    uv_db_req_t* req = container_of(work_req, uv_db_req_t, work_req);
    unqlite_int64 len;

    switch (req->op) {
    case UV_DB_OP_GET:
        req->status = db_get(req->handle, req->key, &req->value);
        break;
    case UV_DB_OP_SET:
        len = req->value.len;
        req->status = unqlite_kv_store(req->handle->db, req->key, -1, req->value.base, len);
        unqlite_commit(req->handle->db);
        break;
    case UV_DB_OP_DELETE:
        req->status = unqlite_kv_delete(req->handle->db, req->key, -1);
        unqlite_commit(req->handle->db);
        break;
    case UV_DB_OP_KEY:
        req->status = db_index_to_key(req->handle, (int32_t*)&req->value.len, (char**)&req->key);
        req->value.len = (int32_t)req->value.len;
        break;
    case UV_DB_OP_LIST:
        req->status = db_list(req->handle, req->cb, req->arg, req);
        break;
    }
}

static void async_close(uv_handle_t* handle)
{
    free(handle);
}

static int uv_db_try_close(uv_db_t* handle)
{
    int res = 0;
    if (handle->closing && uv__queue_empty(&handle->queue)) {
        assert_res(handle->db, UV_EINVAL);

        res = unqlite_close(handle->db);
        assert_res(res == UNQLITE_OK, res);

        free(handle);
    }
error:
    return res;
}

static void db_after_work_cb(uv_work_t* work_req, int status)
{
    uv_async_t* async;
    uv_db_req_t* req = container_of(work_req, uv_db_req_t, work_req);
    status = (status < 0) ? status : req->status;

    if (req->cb != NULL) {
        req->cb(status, req->key, req->value, req->arg);
    }

    switch (req->op) {
    case UV_DB_OP_GET:
        if (req->value.base != NULL) {
            free((void*)req->value.base);
        }
        break;
    case UV_DB_OP_KEY:
        if (req->key != NULL) {
            free((void*)req->key);
        }
        break;
    case UV_DB_OP_LIST:
        async = req->work_req.data;
        uv_sem_destroy(req->sem);
        uv_close((uv_handle_t*)async, async_close);
        free(req->sem);
        break;
    }
    uv__queue_remove(&req->node);
    uv_db_try_close(req->handle);
    free(req);
}

int uv_db_init(uv_loop_t* loop, uv_db_t** handle, const char* name)
{
    int res = UV_EINVAL;

    assert_res(handle, UV_EINVAL);
    assert_res(loop, UV_EINVAL);
    assert_res(name, UV_EINVAL);

    *handle = malloc(sizeof(uv_db_t));
    assert_res(*handle, UV_ENOMEM);
    (*handle)->loop = loop;
    res = unqlite_open(&(*handle)->db, name, UNQLITE_OPEN_CREATE);
    assert_res(res == UNQLITE_OK, res);
    uv__queue_init(&(*handle)->queue);
    (*handle)->closing = 0;
error:
    return res;
}

int uv_db_close(uv_db_t* handle)
{
    struct uv__queue* tmp;
    struct uv__queue* q;
    handle->closing = 1;
    uv__queue_foreach_safe(q, tmp, &handle->queue)
    {
        uv_db_req_t* req = container_of(q, uv_db_req_t, node);
        uv_cancel((uv_req_t*)&req->work_req);
    }
    return uv_db_try_close(handle);
}

int uv_db_commit(uv_db_t* handle)
{
    int res = UV_EINVAL;
    assert_res(handle->db, UV_EINVAL);
    res = unqlite_commit(handle->db);
    assert_res(res == UNQLITE_OK, res);

error:
    return res;
}

int uv_db_set(uv_db_t* handle, const char* key, uv_buf_t* value, uv_db_callback cb, void* arg)
{
    int res = UV_EINVAL;
    uv_db_req_t* req = NULL;
    assert_res(handle, UV_EINVAL);
    assert_res(key, UV_EINVAL);
    assert_res(value, UV_EINVAL);

    if (!cb) {
        res = unqlite_kv_store(handle->db, key, -1, value->base, value->len);
        assert_res(res == 0, res);
        goto error;
    }

    req = calloc(sizeof(uv_db_req_t), 1);
    assert_res(req, UV_ENOMEM);

    req->cb = cb;
    req->arg = arg;
    req->key = key;
    req->value.base = value->base;
    req->value.len = value->len;
    req->handle = handle;
    req->op = UV_DB_OP_SET;
    uv__queue_insert_tail(&handle->queue, &req->node);

    res = uv_queue_work(handle->loop, &req->work_req, db_work_cb, db_after_work_cb);
    assert_res(res == 0, res);

    return 0;
error:
    free(req);
    return res;
}

int uv_db_get(uv_db_t* handle, const char* key, uv_buf_t* value, uv_db_callback cb, void* arg)
{
    int res = UV_EINVAL;
    uv_db_req_t* req = NULL;

    // Illegal parameter hit. Please check whether the parameter is correct
    assert_res(handle, UV_EINVAL);
    assert_res(key, UV_EINVAL);

    if (!cb) {
        assert_res(value, UV_EINVAL);
        res = db_get(handle, key, value);
        assert_res(res == 0, res);
        goto error;
    }

    req = calloc(sizeof(uv_db_req_t), 1);
    assert_res(req, UV_ENOMEM);

    req->cb = cb;
    req->arg = arg;
    req->key = key;
    req->handle = handle;
    req->op = UV_DB_OP_GET;
    uv__queue_insert_tail(&handle->queue, &req->node);

    res = uv_queue_work(handle->loop, &req->work_req, db_work_cb, db_after_work_cb);
    assert_res(res == 0, res);

    return 0;
error:
    free(req);
    return res;
}

int uv_db_delete(uv_db_t* handle, const char* key, uv_db_callback cb, void* arg)
{
    int res = UV_EINVAL;
    uv_db_req_t* req = NULL;
    assert_res(handle, UV_EINVAL);
    assert_res(key, UV_EINVAL);

    if (!cb) {
        res = unqlite_kv_delete(handle->db, key, -1);
        goto error;
    }

    req = calloc(sizeof(uv_db_req_t), 1);
    assert_res(req, UV_ENOMEM);

    req->cb = cb;
    req->arg = arg;
    req->key = key;
    req->handle = handle;
    req->op = UV_DB_OP_DELETE;
    uv__queue_insert_tail(&handle->queue, &req->node);

    res = uv_queue_work(handle->loop, &req->work_req, db_work_cb, db_after_work_cb);
    assert_res(res == 0, res);

    return 0;
error:
    free(req);
    return res;
}

int uv_db_key(uv_db_t* handle, int index, char** key, uv_db_callback cb, void* arg)
{
    int res = UV_EINVAL;
    uv_db_req_t* req = NULL;
    assert_res(handle, UV_EINVAL);

    if (!cb) {
        int32_t res;
        res = db_index_to_key(handle, (int32_t*)&index, key);
        assert_res(res == 0, res);
        return index;
    }

    req = calloc(sizeof(uv_db_req_t), 1);
    assert_res(req, UV_ENOMEM);

    req->cb = cb;
    req->arg = arg;
    req->value.len = index;
    req->handle = handle;
    req->op = UV_DB_OP_KEY;
    uv__queue_insert_tail(&handle->queue, &req->node);

    res = uv_queue_work(handle->loop, &req->work_req, db_work_cb, db_after_work_cb);
    assert_res(res == 0, res);

    return 0;
error:
    free(req);
    return res;
}

int uv_db_list(uv_db_t* handle, uv_db_callback cb, void* arg, int is_sync)
{
    int res;
    uv_async_t* async = NULL;
    uv_db_req_t* req = NULL;

    if (is_sync) {
        res = db_list(handle, cb, arg, req);
        return res;
    }

    async = malloc(sizeof(uv_async_t));
    assert_res(async, UV_ENOMEM);
    res = uv_async_init(handle->loop, async, async_cb);
    assert_res(res == 0, res);
    req = calloc(sizeof(uv_db_req_t), 1);
    assert_res(req, UV_ENOMEM);

    req->cb = cb;
    req->arg = arg;
    req->work_req.data = async;
    req->handle = handle;
    req->op = UV_DB_OP_LIST;
    req->sem = malloc(sizeof(uv_sem_t));
    assert_res(req->sem, UV_ENOMEM);
    res = uv_sem_init(req->sem, 0);
    assert_res(res == 0, res);
    uv__queue_insert_tail(&handle->queue, &req->node);

    res = uv_queue_work(handle->loop, &req->work_req, db_work_cb, db_after_work_cb);
    assert_res(res == 0, res);

    return 0;
error:
    free(req);
    free(async);
    return res;
}
