# ##############################################################################
# apps/system/libuv/ext/CMakeLists.txt
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

if(CONFIG_LIBUV_EXTENSION)

  set(LIBUV_EXT_SRC_DIR ${CMAKE_CURRENT_LIST_DIR}/src)
  set(LIBUV_EXT_TEST_DIR ${CMAKE_CURRENT_LIST_DIR}/tests)

  list(APPEND EXT_SRCS ${LIBUV_EXT_SRC_DIR}/uv_mqueue.c
       ${LIBUV_EXT_SRC_DIR}/uv_async_queue.c
       ${LIBUV_EXT_SRC_DIR}/uv_brightness.c)

  list(APPEND EXT_EXPORT_INCDIR ${CMAKE_CURRENT_LIST_DIR}/include)

  if(CONFIG_KVDB)
    list(APPEND EXT_SRCS ${LIBUV_EXT_SRC_DIR}/uv_devinfo.c
         ${LIBUV_EXT_SRC_DIR}/uv_locale.c ${LIBUV_EXT_SRC_DIR}/uv_property.c)
  endif()

  if(CONFIG_CRYPTO_MBEDTLS)
    list(APPEND EXT_SRCS ${LIBUV_EXT_SRC_DIR}/uv_aes.c
         ${LIBUV_EXT_SRC_DIR}/uv_crypto.c)
  endif()

  if(CONFIG_UNQLITE)
    list(APPEND EXT_SRCS ${LIBUV_EXT_SRC_DIR}/uv_db.c)
    list(APPEND EXT_INCDIR ${NUTTX_APPS_DIR}/external/unqlite/unqlite)
  endif()

  if(CONFIG_UORB)
    list(APPEND EXT_SRCS ${LIBUV_EXT_SRC_DIR}/uv_topic.c
         ${LIBUV_EXT_TEST_DIR}/uv_topicadv.c)
  endif()

  if(CONFIG_UTILS_CURL)
    list(APPEND EXT_SRCS ${LIBUV_EXT_SRC_DIR}/uv_request.c
         ${LIBUV_EXT_SRC_DIR}/uv_networkcache.c
         ${LIBUV_EXT_SRC_DIR}/uv_networkstatus.c)

  endif()

  if(CONFIG_MEDIA)
    list(APPEND EXT_SRCS ${LIBUV_EXT_SRC_DIR}/uv_audio.c
         ${LIBUV_EXT_SRC_DIR}/uv_record.c ${LIBUV_EXT_SRC_DIR}/uv_volume.c)
  endif()

  if(CONFIG_LIB_ZLIB AND CONFIG_CRYPTO_MBEDTLS)
    list(APPEND EXT_SRCS ${LIBUV_EXT_SRC_DIR}/app_verify.c)
    list(APPEND EXT_INCDIR ${NUTTX_APPS_DIR}/system/zlib/zlib/contrib/minizip
         ${NUTTX_APPS_DIR}/system/zlib/zlib)
  endif()

endif()
