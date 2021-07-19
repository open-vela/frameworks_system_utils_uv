
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

static uv_audio_t audio;
static int step = 0;

static void audio_notify_callback(void* cookie, int msg,
                                      int ext1, int ext2,
                                      const unsigned char *data, int size)
{
    uv_audio_t *paudio = (uv_audio_t*)cookie;

    if (msg == UV_EXT_AUDIO_EVENT_ERROR) {

    } else if (msg == UV_EXT_AUDIO_EVENT_STARTED) {
      paudio->playstate = UV_EXT_AUDIO_STATE_PLAY;
    } else if (msg == UV_EXT_AUDIO_EVENT_STOPPED) {
      paudio->playstate = UV_EXT_AUDIO_STATE_STOP;
    } else if (msg == UV_EXT_AUDIO_EVENT_COMPLETE) {
      paudio->playstate = UV_EXT_AUDIO_STATE_COMPLETE;
    } else if (msg == UV_EXT_AUDIO_EVENT_EVENT_PREPARED) {
    } else if (msg == UV_EXT_AUDIO_EVENT_PAUSED) {
      paudio->playstate = UV_EXT_AUDIO_STATE_PAUSE;
    }

    printf("%s %s %d eventid=%d\n", __FILE__, __func__, __LINE__, msg);
}

static void audio_timer_run_cb(uv_timer_t* handle) {
  double volume = 0;
  int ret, sec = 0;

  switch (step)
  {
    case 0:
      ret = uv_audio_pause(&audio);
      printf("\nstep[%02d, pause] playstate:%d\n", step, audio.playstate);
      break;
    case 1:
      break;
    case 2:
      ret = uv_audio_play(&audio);
      printf("step[%02d, play] playstate:%d\n", step, audio.playstate);
      break;
    case 3:
      ret = uv_audio_get_volume(&audio, &volume);
      printf("step[%02d, get_volume] playstate:%d, %f %f\n", step,
              audio.playstate, audio.volume, volume);
      break;
    case 4:
      ret = uv_audio_set_volume(&audio, 0.1);
      printf("step[%02d, set_volume] playstate:%d, %f %f\n", step,
              audio.playstate, audio.volume, volume);
      break;
    case 5:
      ret = uv_audio_muted(&audio, true);
      printf("step[%02d, muted true] playstate:%d, %f %d\n", step,
              audio.playstate, audio.volume, audio.muted);
      break;
    case 6:
      ret = uv_audio_muted(&audio, false);
      printf("step[%02d, muted false] playstate:%d, %f %d\n", step,
              audio.playstate, audio.volume, audio.muted);
      break;
    case 7:
      ret = uv_audio_get_currenttime(&audio, &sec);
      printf("step[%02d, get_currenttime] playstate:%d, %d\n", step,
              audio.playstate, sec);
      break;
    case 8:
      ret = uv_audio_set_currenttime(&audio, 5);
      printf("step[%02d, set_currenttime] playstate:%d, %d\n", step,
              audio.playstate, 5);
      break;
    case 9:
      ret = uv_audio_get_duration(&audio, &sec);
      printf("step[%02d, get_duration] playstate:%d, %d\n", step,
              audio.playstate, sec);
      break;
    case 10:
      ret = uv_audio_get_isplay(&audio);
      printf("step[%02d, get_isplay] playstate:%d\n", step, audio.playstate);
      break;
    case 11:
      ret = uv_audio_set_url(&audio, "/data/2.mp3");
      printf("step[%02d, get_isplay] url:%s\n", step, audio.url);
      break;
    case 12:
      ret = uv_audio_play(&audio);
      printf("step[%02d, get_isplay] playstate:%d\n", step, audio.playstate);
      break;
    case 13:
      ret = uv_audio_stop(&audio);
      printf("step[%02d, stop] playstate:%d", step, audio.playstate);
      break;
    default:
      uv_audio_close(&audio);
      uv_close((uv_handle_t*)handle, NULL);
      uv_stop(uv_default_loop());
      break;
  }

  step ++;
  printf("ret=%d\n", ret);
}


int main(int argc, char *argv[])
{
  uv_timer_t audio_timer_handle;

  if (uv_audio_create(&audio, audio_notify_callback, &audio) != 0) {
    goto testfail;
  }

  if (uv_audio_set_url(&audio, "/data/1.mp3") != 0) {
    goto testfail;
  }

  if (uv_audio_play(&audio) != 0) {
    goto testfail;
  }

  printf("url:%s playstate:%d", audio.url, audio.playstate);

  if (uv_timer_init(uv_default_loop(), &audio_timer_handle) != 0) {
    goto testfail;
  }

  if (uv_timer_start(&audio_timer_handle, audio_timer_run_cb, 5000, 5000) != 0) {
    goto testfail;
  }

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);

  printf("TEST PASSED !\n");
  exit(0);

testfail:
  printf("TEST FAILED !\n");
  exit(1);
}