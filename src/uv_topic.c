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

#include <alloca.h>
#include <stdlib.h>
#include <uv_ext.h>

/****************************************************************************
 * Name: uv_topic_poll_cb
 *
 * Description:
 *   topic poll callback.
 *
 ****************************************************************************/

static void uv_topic_poll_cb(uv_poll_t *handle, int status, int events) {
  uv_topic_t *topic = (uv_topic_t *)handle;

  if (status < 0) {
    topic->cb(topic, status, NULL, 0);
  } else if (events & UV_READABLE) {
    void *data = topic->data ? topic->data : alloca(topic->datalen);
    ssize_t ret = orb_copy_multi(handle->io_watcher.fd, data, topic->datalen);
    if (ret > 0) {
      topic->cb(topic, 0, data, ret);
    } else if (ret < 0) {
      topic->cb(topic, -errno, NULL, 0);
    }
  } else if (events & UV_DISCONNECT) {
    topic->cb(topic, UV_ENOTCONN, NULL, 0);
  }
}

int uv_topic_subscribe_multi(uv_loop_t *loop, uv_topic_t *topic,
                             orb_id_t meta, int instance, uv_topic_cb cb) {
  struct orb_state state = {};
  int ret;
  int fd;

  if (!loop || !topic || !meta || !cb)
    return UV_EINVAL;
  topic->cb = cb;

  fd = orb_subscribe_multi(meta, instance);
  if (fd < 0)
    return -errno;

  ret = uv_poll_init(loop, &topic->handle, fd);
  if (ret < 0) {
    orb_unsubscribe(fd);
    return ret;
  }

  topic->datalen = meta->o_size;
  orb_get_state(fd, &state);
  if (state.queue_size > 1)
    topic->datalen *= state.queue_size;

  topic->data = NULL;
  if (topic->datalen > 128) {
    topic->data = malloc(topic->datalen);
    if (!topic->data) {
      orb_unsubscribe(fd);
      return UV_ENOMEM;
    }
  }

  ret = uv_poll_start(&topic->handle, UV_READABLE | UV_DISCONNECT, uv_topic_poll_cb);
  if (ret < 0) {
    orb_unsubscribe(fd);
    if (topic->data != NULL) {
      free(topic->data);
      topic->data = NULL;
    }
  }

  return ret;
}

int uv_topic_subscribe(uv_loop_t *loop, uv_topic_t *topic,
                       orb_id_t meta, uv_topic_cb cb) {
  return uv_topic_subscribe_multi(loop, topic, meta, 0, cb);
}

int uv_topic_unsubscribe(uv_topic_t *topic) {
  int ret;

  if (!topic)
    return UV_EINVAL;

  ret = uv_poll_stop(&topic->handle);
  if (ret < 0)
    return ret;

  ret = orb_unsubscribe(topic->handle.io_watcher.fd);
  if (ret < 0)
    ret = -errno;

  if (topic->data != NULL) {
    free(topic->data);
    topic->data = NULL;
  }

  return ret;
}

int uv_topic_set_frequency(uv_topic_t *topic, unsigned int frequency) {
  if (!topic)
    return UV_EINVAL;

  return orb_set_frequency(topic->handle.io_watcher.fd, frequency);
}

int uv_topic_close(uv_topic_t *topic)
{
  uv_close((uv_handle_t *)&topic->handle, NULL);
  return 0;
}
