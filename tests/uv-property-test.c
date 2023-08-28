/*
 * Copyright (C) 2020 Xiaomi Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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

static unsigned int kvdb_op_cnt = 0;
static const char test_key[] = "persist.test_kvdb";
static const char test_value[20] = "kvdb test";
static char get_value[20] = { 0 };

static void kvdb_set_data_cb(int status, const char* key, char* value, void* arg)
{
    if (status == 0) {
        printf("kvdb set key(%s)-value(%s) successfully\n", key, value);
    } else {
        printf("kvdb set key(%s)-value(%s) failed! staus %d\n", key, value, status);
    }
}

static void kvdb_get_data_cb(int status, const char* key, char* value, void* arg)
{
    if (status >= 0) {
        printf("kvdb get key(%s)-value(%s) length %d\n", key, value, status);
    } else {
        printf("kvdb get key(%s) failed! staus %d\n", key, status);
    }
}

static void kvdb_delete_data_cb(int status, const char* key, char* value, void* arg)
{
    if (status == 0) {
        printf("kvdb delete key(%s) successfully\n", key);
    } else {
        printf("kvdb delete key(%s) failed! staus %d\n", key, status);
    }
}

static void kvdb_commit_data_cb(int status, const char* key, char* value, void* arg)
{
    if (status == 0) {
        printf("kvdb commit successfully\n");
    } else {
        printf("kvdb commit failed! staus %d\n", status);
    }
}

static void timer_run_cb(uv_timer_t* handle)
{
    uv_loop_t* loop = handle->loop;
    if (kvdb_op_cnt >= 4) {
        uv_stop(loop);
        return;
    }

    kvdb_op_cnt++;

    switch (kvdb_op_cnt) {
    case 1:
        uv_property_set(loop, test_key, test_value, kvdb_set_data_cb, handle);
        break;
    case 2:
        uv_property_commit(loop, kvdb_commit_data_cb, handle);
        break;
    case 3:
        uv_property_get(loop, test_key, get_value, NULL, kvdb_get_data_cb, handle);
        break;
    case 4:
        uv_property_delete(loop, test_key, kvdb_delete_data_cb, handle);
        break;
    default:
        break;
    }
}

int main(int argc, char* argv[])
{
    uv_loop_t* loop = (uv_loop_t*)malloc(sizeof(uv_loop_t));
    uv_timer_t timer_handle;

    uv_loop_init(loop);

    /* Handle kvdb using the Timer loop */

    if (uv_timer_init(loop, &timer_handle) != 0) {
        goto testfail;
    }

    if (uv_timer_start(&timer_handle, timer_run_cb, 1000, 5) != 0) {
        goto testfail;
    }

    uv_run(loop, UV_RUN_DEFAULT);

    printf("UV KVDB TEST PASSED !\n");
    kvdb_op_cnt = 0;

    uv_loop_close(loop);
    free(loop);
    return 0;

testfail:
    printf("UV KVDB TEST FAILED !\n");
    free(loop);
    return 1;
}