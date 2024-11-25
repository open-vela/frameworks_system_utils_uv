/****************************************************************************
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <uv_ext.h>

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * uv_request test
 ****************************************************************************/

void request_cb(int state, uv_response_t* response)
{
    if (!state && response->httpcode == 200) {
        if (response->body != NULL) {
            printf("%s\n", response->body);
        } else {
            printf("download file success!\n");
        }
    }
}

int main(int argc, char** argv)
{

    uv_loop_t* loop = malloc(sizeof(uv_loop_t));
    uv_loop_init(loop);
    uv_request_session_t* handle = NULL;
    uv_request_t* fetch = NULL;
    uv_request_t* request = NULL;

    uv_request_init(loop, &handle);

    /*fetch data, GET*/
    uv_request_create(&fetch);
    uv_request_set_url(fetch, "http://httpbin.org/get");
    uv_request_set_atrribute(fetch, UV_REQUEST, NULL);
    uv_request_commit(handle, fetch, request_cb);
    uv_run(loop, UV_RUN_DEFAULT);

    /*fetch data, POST */
    uv_request_create(&fetch);
    uv_request_set_url(fetch, "http://httpbin.org/post");
    uv_request_append_header(fetch, "Connection: keep-alive");
    uv_request_set_data(fetch, "post test", 9);
    uv_request_set_atrribute(fetch, UV_REQUEST, NULL);
    uv_request_commit(handle, fetch, request_cb);
    uv_run(loop, UV_RUN_DEFAULT);

    /*download file*/
    uv_request_create(&request);
    uv_request_set_url(request, "http://www.baidu.com");
    uv_request_set_atrribute(request, UV_DOWNLOAD, "/data/baidu.html");
    uv_request_commit(handle, request, request_cb);
    uv_run(loop, UV_RUN_DEFAULT);

    uv_request_close(handle);
    uv_loop_close(loop);

    return 0;
}
