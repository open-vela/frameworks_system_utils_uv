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
#include <uv/errno.h>
#include <media_api.h>


int uv_audio_create(uv_audio_t *handle, notify_callback_f callback,
                    void* parame) {
  int ret;
  char *pargs = "amovie@src0,volume[s0],amovie@src1,volume[s1],amovie@src2,"
                "volume[s2],[s0][s1][s2]amix=inputs=3:timeout=40:first_input"
                "=-1[d0],[d0]adevsink@pcm0p=format=nuttx:devname="
                "/dev/audio/pcm0p";

  /* init=1, 表示已经初始化过了，无需再次初始化. */
  if (handle->init == 1) {
    return 0;
  }

  ret = media_service_init();
  if (ret < 0) {
    return ret;
  }

  ret = media_service_loadgraph(pargs);
  if (ret < 0) {
    media_service_uninit();
    return ret;
  }

  handle->iofhandle = media_playback_create(NULL);
  if (!handle->iofhandle) {
    media_service_uninit();
    return UV_EINVAL;
  }

  ret = media_playback_set_notify_callback(handle->iofhandle,
                                           parame,
                                           callback);
  if (ret != 0) {
    uv_audio_close(handle);
    media_service_uninit();
    return ret;
  }

  handle->init = 1;
  handle->playback = true;

  return 0;
}

int uv_audio_set_url(uv_audio_t *handle, const char *url) {
  int ret, play = 0;

  if (!handle  || !handle->iofhandle || !url) {
    return UV_EINVAL;
  }

  if (true == handle->autoplay
      || UV_EXT_AUDIO_STATE_PLAY  == handle->playstate
      || UV_EXT_AUDIO_STATE_PAUSE == handle->playstate) {
    uv_audio_stop(handle);
    usleep(100);
    play = 1;
  }

  if (handle->playback) {
    ret = media_playback_set_data_source(handle->iofhandle, url, NULL);
  } else {
    ret = media_capture_set_data_dest(handle->iofhandle, url, NULL);
  }

  if (ret < 0) {
    return ret;
  }

  if (play) {
    ret = uv_audio_prepare(handle);
    if (ret != 0) {
      return ret;
    }

    ret = uv_audio_play(handle);
    if (ret != 0) {
      return 0;
    }
  }

  return 0;
}

int uv_audio_prepare(uv_audio_t *handle) {
  int ret;

  if (!handle  || !handle->iofhandle) {
    return UV_EINVAL;
  }

  if (handle->playback) {
    ret = media_playback_prepare(handle->iofhandle);
  } else {
    ret = media_capture_prepare(handle->iofhandle);
  }

  if (ret < 0) {
    return ret;
  }

  return 0;
}

int uv_audio_play(uv_audio_t *handle) {
  int ret;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  if (handle->playback) {
    ret = media_playback_start(handle->iofhandle);
  } else {
    ret = media_capture_start(handle->iofhandle);
  }

  if (ret != 0) {
    return ret;
  }

  return 0;
}

int uv_audio_set_autoplay(uv_audio_t *handle, bool autoplay) {
  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  handle->autoplay = autoplay;

  if (true == handle->autoplay) {
    if (strlen(handle->url) > 0
        && UV_EXT_AUDIO_STATE_PLAY  != handle->playstate
        && UV_EXT_AUDIO_STATE_PAUSE != handle->playstate) {
      uv_audio_stop(handle);
      uv_audio_set_url(handle, handle->url);
      uv_audio_prepare(handle);
      uv_audio_play(handle);
    }
  }

  return 0;
}

int uv_audio_pause(uv_audio_t *handle) {
  int ret = 0;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  if (handle->playback) {
    ret = media_playback_pause(handle->iofhandle);
  }

  return ret;
}

int uv_audio_stop(uv_audio_t *handle) {
  int ret = 0;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  if (!handle->playback) {
    ret = media_capture_stop(handle->iofhandle);
  }

  if (handle->playback) {
    ret = media_playback_stop(handle->iofhandle);
  }

  if (ret < 0) {
    return ret;
  }

  return ret;
}

int uv_audio_loop(uv_audio_t *handle, bool loop) {
  int ret;
  if (!handle || !handle->iofhandle)
        return UV_EINVAL;

  if (!handle->playback)
      return UV_EINVAL;

  ret = media_playback_set_looping(handle->iofhandle, (int)loop);
  if (ret < 0) {
    return ret;
  }
  handle->loop = loop;

  return 0;
}

int uv_audio_set_volume(uv_audio_t *handle, double volume) {
  int ret;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  ret = media_playback_set_volume(handle->iofhandle, volume);
  if (ret < 0) {
    return ret;
  }

  if (volume > (double)0) {
    handle->volume = volume;
    handle->muted  = false;
  }

  return 0;
}

int uv_audio_get_volume(uv_audio_t *handle, double *volume) {
  int ret;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  ret = media_playback_get_volume(handle->iofhandle, volume);
  if (ret < 0) {
    return ret;
  }

  if (handle->muted == false) {
    handle->volume = *volume;
  }

  return 0;
}

int uv_audio_muted(uv_audio_t *handle, bool muted) {
  int ret;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  if (muted == true) {

    //第一次设置静音或音量为0时，获取音量
    if (!handle->volume) {
      uv_audio_get_volume(handle, &handle->volume);
    }

    ret = uv_audio_set_volume(handle, 0);
    if (ret != 0) {
      return ret;
    }
  } else {
    ret = uv_audio_set_volume(handle, handle->volume);
    if (ret != 0) {
      return ret;
    }
  }

  handle->muted  = muted;
  return 0;
}

int uv_audio_streamtype(uv_audio_t *handle, const char *type) {
  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  snprintf(handle->streamtype, sizeof(handle->streamtype), "%s", type);
  return 0;
}

int uv_audio_set_currenttime(uv_audio_t *handle, int sec) {
  int ret;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  if (!handle->playback) {
    return 0;
  }

  ret = media_playback_seek(handle->iofhandle, sec * 1000);
  if (ret < 0) {
    return ret;
  }

  return 0;
}

int uv_audio_get_currenttime(uv_audio_t *handle, int *sec) {
  int ret;
  int msec;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  if (!handle->playback) {
    return 0;
  }

  ret = media_playback_get_current_position(handle->iofhandle, &msec);
  if (ret < 0) {
    return ret;
  }
  *sec = msec / 1000;

  return 0;
}

int uv_audio_get_duration(uv_audio_t *handle, int *sec) {
  int ret;
  int msec;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  if (!handle->playback) {
    return 0;
  }

  ret = media_playback_get_duration(handle->iofhandle, &msec);
  if (ret < 0) {
    return ret;
  }
  *sec = msec / 1000;

  return 0;
}

int uv_audio_get_isplay(uv_audio_t *handle) {
  int ret;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  if (!handle->playback) {
    return UV_EINVAL;
  }

  ret = media_playback_is_playing(handle->iofhandle);
  if (ret < 0) {
      return ret;
  }

  if (1 == ret) {
    handle->playstate = UV_EXT_AUDIO_STATE_PLAY;
  }

  return 0;
}

int uv_audio_close(uv_audio_t *handle) {
  int ret;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  if (!handle->playback) {
    ret = media_capture_stop(handle->iofhandle);
    if (ret < 0) {
      return ret;
    }
  }

  usleep(1000); // function?

  if (handle->playback) {
    ret = media_playback_destory(handle->iofhandle);
  } else {
    ret = media_capture_destory(handle->iofhandle);
  }

  if (handle->init) {
    media_service_uninit();
  }

  handle->init = 0;

  if (ret != 0) {
    return ret;
  }

  return 0;
}