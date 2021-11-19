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

int uv_audio_create(uv_audio_t *handle, media_event_callback callback,
                    void* parame) {
  int ret;

  /* init=1, The handle has been initialized. */
  if (handle->init == 1) {
    return 0;
  }

  handle->iofhandle = media_player_open("Music");
  if (!handle->iofhandle) {
    return UV_EINVAL;
  }

  ret = media_player_set_event_callback(handle->iofhandle, parame, callback);
  if (ret < 0) {
    return uv_audio_close(handle);
  }

  handle->init = 1;

  return ret;
}

int uv_audio_set_url(uv_audio_t *handle, const char *url) {
  int ret;

  if (!handle  || !handle->iofhandle || !url) {
    return UV_EINVAL;
  }

  if (!(handle->autoplay
      || UV_EXT_AUDIO_STATE_PLAY  == handle->playstate
      || UV_EXT_AUDIO_STATE_PAUSE == handle->playstate)) {
    return 0;
  }

  uv_audio_stop(handle);

  ret = media_player_prepare(handle->iofhandle, url, NULL);
  if (ret < 0) {
    return ret;
  }

  return uv_audio_play(handle);
}

int uv_audio_prepare(uv_audio_t *handle, const char *url) {
  if (!handle  || !handle->iofhandle) {
    return UV_EINVAL;
  }

  return media_player_prepare(handle->iofhandle, url, NULL);
}

int uv_audio_play(uv_audio_t *handle) {
  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  return media_player_start(handle->iofhandle);
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
    }
  }

  return 0;
}

int uv_audio_pause(uv_audio_t *handle) {
  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  return media_player_pause(handle->iofhandle);
}

int uv_audio_stop(uv_audio_t *handle) {
  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  return media_player_stop(handle->iofhandle);
}

int uv_audio_loop(uv_audio_t *handle, bool loop) {
  int ret;

  if (!handle || !handle->iofhandle)
        return UV_EINVAL;

  ret = media_player_set_looping(handle->iofhandle, (int)loop);
  if (ret < 0) {
    return ret;
  }

  handle->loop = loop;

  return ret;
}

int uv_audio_set_volume(uv_audio_t *handle, float volume) {
  int ret;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  ret = media_player_set_volume(handle->iofhandle, volume);
  if (ret < 0) {
    return ret;
  }

  if (volume > (float)0) {
    handle->volume = volume;
    handle->muted  = false;
  }

  return ret;
}

int uv_audio_get_volume(uv_audio_t *handle, float *volume) {
  int ret;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  ret = media_player_get_volume(handle->iofhandle, volume);
  if (ret < 0) {
    return ret;
  }

  if (handle->muted == false) {
    handle->volume = *volume;
  }

  return ret;
}

int uv_audio_muted(uv_audio_t *handle, bool muted) {
  int ret;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  if (muted == true) {

    //Get the volume when mute is set for the first time or the volume is 0
    if (!handle->volume) {
      uv_audio_get_volume(handle, &handle->volume);
    }

    ret = uv_audio_set_volume(handle, 0);
  } else {
    ret = uv_audio_set_volume(handle, handle->volume);
  }

  handle->muted  = muted;
  return ret;
}

int uv_audio_streamtype(uv_audio_t *handle, const char *type) {
  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  snprintf(handle->streamtype, sizeof(handle->streamtype), "%s", type);
  return 0;
}

int uv_audio_set_currenttime(uv_audio_t *handle, int sec) {
  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  return media_player_seek(handle->iofhandle, sec * 1000);
}

int uv_audio_get_currenttime(uv_audio_t *handle, int *sec) {
  int ret;
  int msec;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  ret = media_player_get_position(handle->iofhandle, &msec);
  if (ret < 0) {
    return ret;
  }
  *sec = msec / 1000;

  return ret;
}

int uv_audio_get_duration(uv_audio_t *handle, int *sec) {
  int ret;
  int msec;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  ret = media_player_get_duration(handle->iofhandle, &msec);
  if (ret < 0) {
    return ret;
  }
  *sec = msec / 1000;

  return ret;
}

int uv_audio_get_isplay(uv_audio_t *handle) {
  int ret;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  ret = media_player_is_playing(handle->iofhandle);
  if (ret < 0) {
      return ret;
  }

  if (1 == ret) {
    handle->playstate = UV_EXT_AUDIO_STATE_PLAY;
  }

  return ret;
}

int uv_audio_close(uv_audio_t *handle) {
  int ret;
  int pending_stop = 0;

  if (!handle || !handle->iofhandle) {
    return UV_EINVAL;
  }

  ret =media_player_close(handle->iofhandle, pending_stop);
  if (ret < 0) {
    return ret;
  }

  handle->init = 0;

  return ret;
}
