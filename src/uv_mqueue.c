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
#include <nuttx/mqueue.h>
#include <stddef.h>
#include <uv/errno.h>
#include <uv_ext.h>

/****************************************************************************
 * Name: uv_mqueue_poll_cb
 *
 * Description:
 *   mqueue poll callback.
 *
 ****************************************************************************/

static void uv_mqueue_poll_cb(uv_poll_t* handle, int status, int events)
{
    uv_mqueue_t* mqueue = (uv_mqueue_t*)handle;
    if (status < 0) {
        mqueue->cb(mqueue, status, NULL, 0);
        return;
    }

    if (events & UV_READABLE) {
        struct mq_attr attr = { 0 };
        int ret = mq_getattr(mqueue->fd, &attr);
        if (ret < 0) {
            mqueue->cb(mqueue, ret, NULL, 0);
            return;
        }
        void* data = mqueue->msg_data ? mqueue->msg_data : alloca(attr.mq_msgsize);
        ssize_t rd_len = 0;
        do {
            rd_len = mq_receive(mqueue->fd, data, attr.mq_msgsize, NULL);
            if (rd_len > 0) {
                mqueue->cb(mqueue, 0, data, rd_len);
                continue;
            }

            if (rd_len < 0 && errno != EAGAIN) {
                mqueue->cb(mqueue, -errno, NULL, 0);
            }

        } while (rd_len > 0);
    }

    if (events & UV_DISCONNECT) {
        mqueue->cb(mqueue, UV_ENOTCONN, NULL, 0);
    }
}

static void uv_mqueue_close_cb(uv_handle_t* handle)
{
    uv_mqueue_t* mqueue = (uv_mqueue_t*)handle;

    if (mqueue->fd >= 0) {
        mq_close(mqueue->fd);
        mqueue->fd = -1;
    }

    if (mqueue->msg_data) {
        free(mqueue->msg_data);
        mqueue->msg_data = NULL;
    }

    if (mqueue->close_cb) {
        mqueue->close_cb(handle);
        mqueue->close_cb = NULL;
    }
}

int uv_mqueue_send(const char* mq_name, void* data, int datasize)
{
    int ret;
    int fd;

    if (NULL == mq_name || NULL == data) {
        return UV_EINVAL;
    }

    fd = mq_open(mq_name, O_WRONLY | O_NONBLOCK);
    if (fd < 0) {
        return -errno;
    }
    ret = mq_send(fd, (const char*)data, datasize, 0);
    if (ret < 0) {
        ret = -errno;
    }

    mq_close(fd);
    return ret;
}

int uv_mqueue_recv(const char* mq_name, void* buff, int buffsize)
{
    int ret;
    int fd;

    if (NULL == mq_name || NULL == buff) {
        return UV_EINVAL;
    }

    fd = mq_open(mq_name, O_RDONLY | O_NONBLOCK);
    if (fd < 0) {
        return -errno;
    }

    ret = mq_receive(fd, (char*)buff, buffsize, NULL);
    if (ret < 0) {
        ret = -errno;
    }

    mq_close(fd);
    return ret;
}

int uv_mqueue_init(uv_loop_t* loop, uv_mqueue_t* mqueue, const char* name, struct mq_attr* attr)
{
    int fd;
    int ret;

    if (!name || !loop) {
        return UV_EINVAL;
    }

    mqueue->fd = -1;
    fd = mq_open(name, O_RDWR | O_CREAT | O_NONBLOCK, 0644, attr);
    if (fd < 0) {
        return -errno;
    }

    mqueue->msg_data = NULL;
    if (attr->mq_msgsize > 128) {
        mqueue->msg_data = malloc(attr->mq_msgsize);
        if (!mqueue->msg_data) {
            mq_close(fd);
            return UV_ENOMEM;
        }
    }

    ret = uv_poll_init(loop, &mqueue->poll, fd);
    if (ret) {
        mq_close(fd);
        return ret;
    }

    mqueue->fd = fd;
    mqueue->cb = NULL;

    return ret;
}

int uv_mqueue_start(uv_mqueue_t* mqueue, uv_mqueue_cb cb)
{
    mqueue->cb = cb;
    int ret = uv_poll_start(&mqueue->poll, UV_DISCONNECT | UV_READABLE, uv_mqueue_poll_cb);
    return ret;
}

int uv_mqueue_stop(uv_mqueue_t* mqueue)
{
    if (!mqueue) {
        return UV_EINVAL;
    }

    return uv_poll_stop(&mqueue->poll);
}

void uv_mqueue_close(uv_mqueue_t* mqueue, uv_close_cb close_cb)
{
    if (!mqueue) {
        return;
    }

    mqueue->close_cb = close_cb;

    uv_close((uv_handle_t*)&mqueue->poll, uv_mqueue_close_cb);
}