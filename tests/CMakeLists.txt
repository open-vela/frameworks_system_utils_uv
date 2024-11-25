# ##############################################################################
# apps/system/libuv/ext/tests/CMakeLists.txt
#
# Licensed to the Apache Software Foundation (ASF) under one or more contributor
# license agreements.  See the NOTICE file distributed with this work for
# additional information regarding copyright ownership.  The ASF licenses this
# file to you under the Apache License, Version 2.0 (the "License"); you may not
# use this file except in compliance with the License.  You may obtain a copy of
# the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations under
# the License.
#
# ##############################################################################

if(CONFIG_LIBUV_EXTENSION_TEST)
  nuttx_add_application(
    MODULE
    ${CONFIG_LIBUV_EXTENSION_TEST}
    NAME
    uv_async_queue
    STACKSIZE
    ${CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE}
    PRIORITY
    ${CONFIG_LIBUV_EXTENSION_TEST_PRIORITY}
    SRCS
    uv-async-queue-test.c
    INCLUDE_DIRECTORIES
    ${INCDIR}
    COMPILE_FLAGS
    ${CFLAGS}
    DEPENDS
    libuv)

  if(CONFIG_KVDB)
    nuttx_add_application(
      MODULE
      ${CONFIG_LIBUV_EXTENSION_TEST}
      NAME
      uv_devinfo
      STACKSIZE
      ${CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE}
      PRIORITY
      ${CONFIG_LIBUV_EXTENSION_TEST_PRIORITY}
      SRCS
      uv-devinfo-test.c
      INCLUDE_DIRECTORIES
      ${INCDIR}
      COMPILE_FLAGS
      ${CFLAGS}
      DEPENDS
      libuv)

    nuttx_add_application(
      MODULE
      ${CONFIG_LIBUV_EXTENSION_TEST}
      NAME
      uv_locale
      STACKSIZE
      ${CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE}
      PRIORITY
      ${CONFIG_LIBUV_EXTENSION_TEST_PRIORITY}
      SRCS
      uv-locale-test.c
      INCLUDE_DIRECTORIES
      ${INCDIR}
      COMPILE_FLAGS
      ${CFLAGS}
      DEPENDS
      libuv)

    nuttx_add_application(
      MODULE
      ${CONFIG_LIBUV_EXTENSION_TEST}
      NAME
      uv_property
      STACKSIZE
      ${CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE}
      PRIORITY
      ${CONFIG_LIBUV_EXTENSION_TEST_PRIORITY}
      SRCS
      uv-property-test.c
      INCLUDE_DIRECTORIES
      ${INCDIR}
      COMPILE_FLAGS
      ${CFLAGS}
      DEPENDS
      libuv)
  endif()

  if(CONFIG_CRYPTO_MBEDTLS)
    nuttx_add_application(
      MODULE
      ${CONFIG_LIBUV_EXTENSION_TEST}
      NAME
      uv_aes
      STACKSIZE
      ${CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE}
      PRIORITY
      ${CONFIG_LIBUV_EXTENSION_TEST_PRIORITY}
      SRCS
      uv-aes-test.c
      INCLUDE_DIRECTORIES
      ${INCDIR}
      COMPILE_FLAGS
      ${CFLAGS}
      DEPENDS
      libuv)
  endif()

  if(CONFIG_UORB)
    nuttx_add_application(
      MODULE
      ${CONFIG_LIBUV_EXTENSION_TEST}
      NAME
      uv_topic
      STACKSIZE
      ${CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE}
      PRIORITY
      ${CONFIG_LIBUV_EXTENSION_TEST_PRIORITY}
      SRCS
      uv-topic-test.c
      INCLUDE_DIRECTORIES
      ${INCDIR}
      COMPILE_FLAGS
      ${CFLAGS}
      DEPENDS
      libuv)

    nuttx_add_application(
      MODULE
      ${CONFIG_LIBUV_EXTENSION_TEST}
      NAME
      uv_topicadv
      STACKSIZE
      ${CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE}
      PRIORITY
      ${CONFIG_LIBUV_EXTENSION_TEST_PRIORITY}
      SRCS
      uv-topicadv-test.c
      INCLUDE_DIRECTORIES
      ${INCDIR}
      COMPILE_FLAGS
      ${CFLAGS}
      DEPENDS
      libuv)
  endif()

  if(CONFIG_UTILS_CURL)
    nuttx_add_application(
      MODULE
      ${CONFIG_LIBUV_EXTENSION_TEST}
      NAME
      uv_request
      STACKSIZE
      ${CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE}
      PRIORITY
      ${CONFIG_LIBUV_EXTENSION_TEST_PRIORITY}
      SRCS
      uv-request-test.c
      INCLUDE_DIRECTORIES
      ${INCDIR}
      COMPILE_FLAGS
      ${CFLAGS}
      DEPENDS
      libuv)

    nuttx_add_application(
      MODULE
      ${CONFIG_LIBUV_EXTENSION_TEST}
      NAME
      uv_ncm
      STACKSIZE
      ${CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE}
      PRIORITY
      ${CONFIG_LIBUV_EXTENSION_TEST_PRIORITY}
      SRCS
      uv-ncm-test.c
      INCLUDE_DIRECTORIES
      ${INCDIR}
      COMPILE_FLAGS
      ${CFLAGS}
      DEPENDS
      libuv)
  endif()

  if(CONFIG_MEDIA)
    nuttx_add_application(
      MODULE
      ${CONFIG_LIBUV_EXTENSION_TEST}
      NAME
      uv_audio
      STACKSIZE
      ${CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE}
      PRIORITY
      ${CONFIG_LIBUV_EXTENSION_TEST_PRIORITY}
      SRCS
      uv-audio-test.c
      INCLUDE_DIRECTORIES
      ${INCDIR}
      COMPILE_FLAGS
      ${CFLAGS}
      DEPENDS
      libuv)

    nuttx_add_application(
      MODULE
      ${CONFIG_LIBUV_EXTENSION_TEST}
      NAME
      uv_record
      STACKSIZE
      ${CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE}
      PRIORITY
      ${CONFIG_LIBUV_EXTENSION_TEST_PRIORITY}
      SRCS
      uv-record-test.c
      INCLUDE_DIRECTORIES
      ${INCDIR}
      COMPILE_FLAGS
      ${CFLAGS}
      DEPENDS
      libuv)
  endif()

  if(CONFIG_UTILS_CURL AND CONFIG_UORB)
    nuttx_add_application(
      MODULE
      ${CONFIG_LIBUV_EXTENSION_TEST}
      NAME
      uv_network
      STACKSIZE
      ${CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE}
      PRIORITY
      ${CONFIG_LIBUV_EXTENSION_TEST_PRIORITY}
      SRCS
      uv-network-test.c
      INCLUDE_DIRECTORIES
      ${INCDIR}
      COMPILE_FLAGS
      ${CFLAGS}
      DEPENDS
      libuv)
  endif()

  if(CONFIG_UNQLITE)
    nuttx_add_application(
      MODULE
      ${CONFIG_LIBUV_EXTENSION_TEST}
      NAME
      uv_db
      STACKSIZE
      ${CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE}
      PRIORITY
      ${CONFIG_LIBUV_EXTENSION_TEST_PRIORITY}
      SRCS
      uv-db-test.c
      INCLUDE_DIRECTORIES
      ${INCDIR}
      COMPILE_FLAGS
      ${CFLAGS}
      DEPENDS
      libuv)
  endif()
endif()
