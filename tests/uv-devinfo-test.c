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
  uv_devinfo_t devinfo;

  if (uv_get_devinfo(&devinfo) != 0) {
    goto testfail;
  }

  printf("brand = %s\n", devinfo.brand);
  printf("manufacturer = %s\n", devinfo.manufacturer);
  printf("model = %s\n", devinfo.model);
  printf("product = %s\n", devinfo.product);
  printf("os_type = %s\n", devinfo.os_type);
  printf("os_version_name = %s\n", devinfo.os_version_name);
  printf("os_version_code = %s\n", devinfo.os_version_code);
  printf("lanuage = %s\n", devinfo.lanuage);
  printf("region = %s\n", devinfo.region);
  printf("screenwidth = %d\n", devinfo.screenwidth);
  printf("screenheight = %d\n\n", devinfo.screenheight);

  printf("TEST PASSED !\n");
  exit(0);

testfail:
  printf("TEST FAILED !\n");
  exit(1);
}