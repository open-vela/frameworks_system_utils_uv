/****************************************************************************
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <arpa/inet.h>
#include <system/state.h>
#include <uORB/uORB.h>
#include <uv_ext.h>

/****************************************************************************
 * Public Functions
 ****************************************************************************/

int main(int argc, char** argv)
{
    int ret;
    uint8_t type;

    ret = uv_netstatus_gettype(&type);
    if (ret > 0) {
        printf("network type: %d\n", type);
    } else {
        printf("get network type fail\n");
    }

    return 0;
}
