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

static uv_brightness_t brightness;
static int resultflag;

static void timer_run_cb(uv_timer_t* handle) {

    if (uv_brightness_free(&brightness) == 0) {
      resultflag = 1;
    }

    uv_close((uv_handle_t*)handle, NULL);
    uv_stop(uv_default_loop());
}

int main(int argc, char *argv[])
{
  /* app start */

  int ret, lightvalue;
  uv_timer_t timer_handle;

  /* test ordinary brightness interface */

  ret = uv_brightness_init(uv_default_loop(), &brightness);
  if (ret != 0) {
    goto testfail;
  }

  ret = uv_system_brightness_setval(&brightness, 10);
  if (ret != 0) {
    goto testfail;
  }
  printf("set system brightness value: 10\n");

  ret = uv_system_brightness_getval(&brightness, &lightvalue);
  if (ret != 0 && lightvalue != 0) {
    goto testfail;
  }
  printf("get system brightness value: %d\n", lightvalue);

  ret = uv_brightness_setval(&brightness, 20);
  if (ret != 0 && lightvalue != 0) {
    goto testfail;
  }
  printf("set brightness value: 20\n");

  ret = uv_brightness_getval(&brightness, &lightvalue);
  if (ret != 0 && lightvalue != 0) {
    goto testfail;
  }
  printf("set brightness value: %d\n", lightvalue);

  /* test brightness mode */

  resultflag = 0;
  ret = uv_brightness_setmode(&brightness, 1);
  if (ret != 0 && lightvalue != 0) {
    goto testfail;
  }

  if (uv_timer_init(uv_default_loop(), &timer_handle) != 0) {
    goto testfail;
  }

  if (uv_timer_start(&timer_handle, timer_run_cb, 5000, 0) != 0) {
    goto testfail;
  }

  uv_run(uv_default_loop(), UV_RUN_DEFAULT);

  if (!resultflag) {
    goto testfail;
  }

  printf("TEST PASSED !\n");
  exit(0);

testfail:
  printf("TEST FAILED !\n");
  exit(1);

}