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
#include <stddef.h>
#include <fcntl.h>
#include <uv/errno.h>
#include <nuttx/mqueue.h>

int uv_mqueue_async_send(const char *mq_name, void *data, int datasize)
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
  mq_close(fd);
  return ret;
}

int uv_mqueue_async_recv(const char *mq_name, void *buff, int buffsize)
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
  mq_close(fd);
  return ret;
}

int uv_mqueue_async_init(uv_loop_t *loop,
                         uv_poll_t *pollhandle,
                         uv_poll_cb cb,
                         uv_nxmqueue_t *attr)
{
  int fd;
  int ret;
  mode_t mode = 0;
  struct mq_attr mqattr = { 0 };

  if (!attr || !attr->name) {
    return UV_EINVAL;
  }

  mqattr.mq_msgsize = attr->mq_msgsize;
  mqattr.mq_maxmsg  = attr->mq_maxmsg;
  fd = mq_open(attr->name, O_RDWR | O_CREAT | O_NONBLOCK, mode,
                   &mqattr);
  if (fd < 0) {
    return -errno;
  }

  if (!loop) {
    return fd;
  }

  ret = uv_poll_init(loop, pollhandle, fd);
  if (ret) {
    mq_close(fd);
    return ret;
  }

  ret = uv_poll_start(pollhandle, UV_READABLE, cb);
  if (ret) {
    mq_close(fd);
    return ret;
  }

  return ret;
}

int uv_mqueue_async_uninit(const char *name, uv_poll_t *pollhandle)
{
  int ret;

  if (!name) {
    return UV_EINVAL;
  }

  ret = mq_unlink(name);
  if (ret < 0) {
    return ret;
  }

  if (pollhandle) {
    uv_poll_stop(pollhandle);
    uv_close((uv_handle_t*)pollhandle, NULL);
  }

  return ret;
}