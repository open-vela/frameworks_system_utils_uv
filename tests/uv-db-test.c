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
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define DB_NAME "/data/test.db"

uv_buf_t db_value = { "test_value", 11 };

void case1_cb(int status, const char* key, uv_buf_t value, void* cookie)
{
    int res;
    uv_db_t* handle = cookie;
    uv_buf_t buf;

    res = uv_db_get(handle, "test1", &buf, NULL, NULL);
    assert(res == 0);
    res = strcmp(buf.base, value.base);
    assert(res == 0);
    assert(buf.len == value.len);
    // When synchronizing get data, you need to call free to free up memory
    free(buf.base);
}

// Database set test case
int case1(uv_loop_t* loop)
{
    int res;
    uv_db_t* handle;

    unlink(DB_NAME);
    uv_db_init(loop, &handle, DB_NAME);
    res = uv_db_set(handle, "test1", &db_value, case1_cb, handle);
    assert(res == 0);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_db_close(handle);
    return res;
}

void case2_cb(int status, const char* key, uv_buf_t value, void* cookie)
{
    int res;

    res = strcmp(value.base, db_value.base);
    assert(res == 0);
    assert(db_value.len == value.len);
}

// Database set&get test case
int case2(uv_loop_t* loop)
{
    int res;
    uv_db_t* handle;

    unlink(DB_NAME);
    uv_db_init(loop, &handle, DB_NAME);
    res = uv_db_set(handle, "test1", &db_value, NULL, NULL);
    assert(res == 0);
    res = uv_db_get(handle, "test1", NULL, case2_cb, handle);
    assert(res == 0);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_db_close(handle);
    return res;
}

void case3_cb(int status, const char* key, uv_buf_t value, void* cookie)
{
    int res;
    uv_db_t* handle = cookie;
    uv_buf_t buf;

    res = uv_db_get(handle, "test1", &buf, NULL, NULL);
    assert(res == -6);

    free(buf.base);
}

// Database set&delete test case
int case3(uv_loop_t* loop)
{
    int res;
    uv_db_t* handle;

    unlink(DB_NAME);
    uv_db_init(loop, &handle, DB_NAME);
    res = uv_db_set(handle, "test1", &db_value, NULL, NULL);
    assert(res == 0);

    res = uv_db_delete(handle, "test1", case3_cb, handle);
    assert(res == 0);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_db_close(handle);
    return res;
}

// Database get test case, Synchronous mode
void case4_cb(int status, const char* key, uv_buf_t value, void* cookie)
{
    int res;
    uv_db_t* handle = cookie;
    uv_buf_t buf;

    res = uv_db_get(handle, key, &buf, NULL, NULL);
    assert(res == 0);
    res = strcmp(buf.base, db_value.base);
    assert(res == 0);
    assert(db_value.len == buf.len);
    free(buf.base);
}

// Database get key test case, Asynchronous mode
int case4(uv_loop_t* loop)
{
    int res;
    uv_db_t* handle;
    uv_buf_t value = { "test_value", 11 };

    unlink(DB_NAME);
    uv_db_init(loop, &handle, DB_NAME);
    res = uv_db_set(handle, "test1", &value, NULL, NULL);
    assert(res == 0);
    res = uv_db_set(handle, "test2", &value, NULL, NULL);
    assert(res == 0);

    // Asynchronous mode, invalid key, should be set to null
    res = uv_db_key(handle, 0, NULL, case4_cb, handle);
    assert(res == 0);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_db_close(handle);
    return res;
}

void case5_cb(int status, const char* key, uv_buf_t value, void* cookie)
{
    assert(value.len == 1);
}

// Database get length test case, Asynchronous mode
int case5(uv_loop_t* loop)
{
    int res;
    uv_db_t* handle;
    uv_buf_t value = { "test_value", 11 };

    unlink(DB_NAME);
    uv_db_init(loop, &handle, DB_NAME);

    res = uv_db_set(handle, "test1", &value, NULL, NULL);
    assert(res == 0);
    res = uv_db_set(handle, "test2", &value, NULL, NULL);
    assert(res == 0);

    res = uv_db_key(handle, -1, NULL, case5_cb, "key test6");
    assert(res == 0);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_db_close(handle);
    return res;
}

void case6_cb(int status, const char* key, uv_buf_t value, void* cookie)
{
    int res;
    assert(value.len == db_value.len);
    res = strcmp(value.base, db_value.base);
    assert(res == 0);
}

// Traversal database test case, synchronous mode
int case6(uv_loop_t* loop)
{
    int res;
    uv_db_t* handle;
    uv_buf_t value = { "test_value", 11 };

    unlink(DB_NAME);
    uv_db_init(loop, &handle, DB_NAME);

    res = uv_db_set(handle, "test1", &value, NULL, NULL);
    assert(res == 0);
    res = uv_db_set(handle, "test2", &value, NULL, NULL);
    assert(res == 0);

    res = uv_db_list(handle, case6_cb, handle, true);
    assert(res == 0);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_db_close(handle);
    return res;
}

void case7_cb(int status, const char* key, uv_buf_t value, void* cookie)
{
    int res;
    assert(value.len == db_value.len);
    res = strcmp(value.base, db_value.base);
    assert(res == 0);
}

// Traversal database test case, synchronous mode
int case7(uv_loop_t* loop)
{
    int res;
    uv_db_t* handle;
    uv_buf_t value = { "test_value", 11 };

    unlink(DB_NAME);
    uv_db_init(loop, &handle, DB_NAME);

    res = uv_db_set(handle, "test1", &value, NULL, NULL);
    assert(res == 0);
    res = uv_db_set(handle, "test2", &value, NULL, NULL);
    assert(res == 0);

    res = uv_db_list(handle, case7_cb, handle, false);
    assert(res == 0);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_db_close(handle);
    return res;
}

// Database get length test case, synchronous mode
int case8(uv_loop_t* loop)
{
    int res;
    char* key;
    uv_db_t* handle;
    uv_buf_t value = { "test_value", 11 };

    unlink(DB_NAME);
    uv_db_init(loop, &handle, DB_NAME);
    res = uv_db_set(handle, "test1", &value, NULL, NULL);
    assert(res == 0);
    res = uv_db_set(handle, "test2", &value, NULL, NULL);
    assert(res == 0);

    // synchronous mode, invalid key, should be set to null
    res = uv_db_key(handle, 0, &key, NULL, NULL);
    assert(res == 0);
    res = strncmp(key, "test", 4);
    assert(res == 0);
    free(key);

    res = uv_db_set(handle, "test3", &value, NULL, NULL);
    assert(res == 0);

    // get the number of database records
    res = uv_db_key(handle, -1, &key, NULL, NULL);
    assert(res == 2);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_db_close(handle);
    return res;
}

int (*test_case_list[])(uv_loop_t*) = { case1, case2, case3, case4, case5, case6, case7, case8 };
const int test_case_num = sizeof(test_case_list) / sizeof(test_case_list[0]);

int uv_db_test_all(void)
{
    uv_loop_t* loop;

    for (int i = 0; i < test_case_num; i++) {
        printf("\n-------run test case %d ------\n", i + 1);
        loop = malloc(sizeof(uv_loop_t));
        uv_loop_init(loop);
        test_case_list[i](loop);
        uv_loop_close(loop);
        free(loop);
    }

    exit(0);
    return 0;
}

int main(void)
{
    uv_db_test_all();

    return 0;
}
