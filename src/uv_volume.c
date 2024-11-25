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
#include <syslog.h>
#include <uv_ext.h>

/****************************************************************************
 * Pre-processor Definitions
 ****************************************************************************/

#define MEDIA_STREAM_MAX_LEN 20

/****************************************************************************
 * Private Types
 ****************************************************************************/

/* Volume operation */

typedef enum volume_op_e {
    UV_VOLUME_OP_GET = 0, /* Volume get operation */
    UV_VOLUME_OP_SET, /* Volume set operation */
} volume_op_t;

typedef struct uv_volume_req_s {
    uv_work_t work_req; /* uv work request */
    uv_volume_cb cb; /* jse_volume callback function */
    volume_op_t op; /* operation type */
    char* stream; /* volume stream */
    void* arg; /* jse_volume volume handle */
    int* pvolume; /* the set/get volume */
    int status; /* the operation status */
} uv_volume_req_t;

/****************************************************************************
 * Private Function Prototypes
 ****************************************************************************/

static void uv_volume_work_cb(uv_work_t* req);
static void uv_volume_after_work_cb(uv_work_t* req, int status);
static int uv_volume_req_alloc(uv_volume_req_t** uv_volume);

/****************************************************************************
 * Private Data
 ****************************************************************************/

/****************************************************************************
 * Private Functions
 ****************************************************************************/

static void uv_volume_work_cb(uv_work_t* req)
{
    uv_volume_req_t* request = (uv_volume_req_t*)req->data;

    switch (request->op) {
    case UV_VOLUME_OP_GET:
        request->status = media_policy_get_stream_volume(request->stream,
            request->pvolume);
        break;

    case UV_VOLUME_OP_SET:
        request->status = media_policy_set_stream_volume(request->stream,
            *request->pvolume);
        break;

    default:
        break;
    }
}

static void uv_volume_after_work_cb(uv_work_t* req, int status)
{
    uv_volume_req_t* request = (uv_volume_req_t*)req->data;

    /* Get the return status */

    status = (status < 0) ? status : request->status;

    /* Call the function passed from jse_volume */

    request->cb(status, request->arg);

    /* Release memory */

    free(request);
}

static int uv_volume_req_alloc(uv_volume_req_t** uv_volume)
{
    if (!uv_volume) {
        return UV_EINVAL;
    }

    *uv_volume = zalloc(sizeof(uv_volume_req_t) + MEDIA_STREAM_MAX_LEN);
    if (!(*uv_volume)) {
        return UV_ENOMEM;
    }

    (*uv_volume)->stream = (char*)*uv_volume + sizeof(uv_volume_req_t);

    return OK;
}

/****************************************************************************
 * Public Functions
 ****************************************************************************/

/****************************************************************************
 * Name: uv_volume_init
 *
 * Description:
 *   Init the uv_volume.
 *
 * Input Parameters:
 *   uv_volume - the uv_volume handle
 *   loop      - the uv_loop
 *
 * Returned Value:
 *   Zero (OK) on success;
 *   Negative on fail;
 *
 ****************************************************************************/

int uv_volume_init(uv_volume_t* uv_volume, uv_loop_t* loop)
{
    if (!loop || !uv_volume) {
        return UV_EINVAL;
    }

    uv_volume->loop = loop;

    return OK;
}

/****************************************************************************
 * Name: uv_volume_set
 *
 * Description:
 *   Set the specified stream volume.
 *
 * Input Parameters:
 *   uv_volume    - the uv_volume handle
 *   volume       - the set volume
 *   uv_volume_cb - the callback function called after the work finish
 *   stream       - the media stream name
 *   arg          - the jse volume handle
 *
 * Returned Value:
 *   Zero (OK) on success;
 *   Negative on fail;
 *
 ****************************************************************************/

int uv_volume_set(uv_volume_t* uv_volume, int volume, uv_volume_cb cb,
    const char* stream, void* arg)
{
    int ret;
    uv_volume_req_t* request;

    if (!stream) {
        return UV_EINVAL;
    }

    /* synchronous mode */

    if (!cb) {
        return media_policy_set_stream_volume(stream, volume);
    }

    if (!uv_volume || !uv_volume->loop) {
        return UV_EINVAL;
    }

    ret = uv_volume_req_alloc(&request);
    if (ret != 0) {
        return ret;
    }

    request->cb = cb;
    request->arg = arg;
    request->op = UV_VOLUME_OP_SET;
    request->work_req.data = request;
    request->pvolume = &volume;
    strlcpy(request->stream, stream, MEDIA_STREAM_MAX_LEN);

    return uv_queue_work(uv_volume->loop, &request->work_req,
        uv_volume_work_cb, uv_volume_after_work_cb);
}

/****************************************************************************
 * Name: uv_volume_get
 *
 * Description:
 *   Get the specified stream volume.
 *
 * Input Parameters:
 *   uv_volume    - the uv_volume handle
 *   pvolume      - the pointer to get volume
 *   uv_volume_cb - the callback function called after the work finish
 *   stream       - the media stream name
 *   arg          - the jse volume handle
 *
 * Returned Value:
 *   Zero (OK) on success;
 *   Negative on fail;
 *
 ****************************************************************************/

int uv_volume_get(uv_volume_t* uv_volume, int* pvolume, uv_volume_cb cb,
    const char* stream, void* arg)
{
    int ret;
    uv_volume_req_t* request;

    if (!stream) {
        return UV_EINVAL;
    }

    /* synchronous mode */

    if (!cb) {
        return media_policy_get_stream_volume(stream, pvolume);
    }

    if (!uv_volume || !uv_volume->loop) {
        return UV_EINVAL;
    }

    ret = uv_volume_req_alloc(&request);
    if (ret != 0) {
        return ret;
    }

    request->cb = cb;
    request->arg = arg;
    request->op = UV_VOLUME_OP_GET;
    request->work_req.data = request;
    request->pvolume = pvolume;
    strlcpy(request->stream, stream, MEDIA_STREAM_MAX_LEN);

    return uv_queue_work(uv_volume->loop, &request->work_req,
        uv_volume_work_cb, uv_volume_after_work_cb);
}
