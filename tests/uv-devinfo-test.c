/*
 * Copyright (C) 2020 Xiaomi Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
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

int main(int argc, char *argv[])
{
  char devinfo[32];
  int wh, i;

  for (i = UV_EXT_DEVINFO_BRAND; i < UV_EXT_DEVINFO_MAX; i++) {
    if (uv_get_devinfo(devinfo, sizeof(devinfo), i) == 0) {
      printf("[%02d], %s\n", i, devinfo);
    }
  }

  if (uv_get_resolution(&wh, UV_EXT_DEVINFO_SCREENWIDTH) != 0) {
    goto testfail;
  }
  printf("[%02d], %d\n", UV_EXT_DEVINFO_SCREENWIDTH, wh);

  if (uv_get_resolution(&wh, UV_EXT_DEVINFO_SCREENHEIGHT) != 0) {
    goto testfail;
  }
  printf("[%02d], %d\n", UV_EXT_DEVINFO_SCREENHEIGHT, wh);

  printf("TEST PASSED !\n");
  exit(0);

testfail:
  printf("TEST FAILED !\n");
  exit(1);
}