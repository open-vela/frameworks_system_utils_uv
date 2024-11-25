############################################################################
# frameworks/system/utils/uv/Makefile
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.  The
# ASF licenses this file to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance with the
# License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
# License for the specific language governing permissions and limitations
# under the License.
#
############################################################################

include $(APPDIR)/Make.defs

CFLAGS += -I$(APPDIR)/system/libuv/libuv/src
CFLAGS += -I$(APPDIR)/system/libuv/libuv/src/unix
CFLAGS += -I$(APPDIR)/system/libuv/libuv/test

CFLAGS += -Wno-shadow -Wno-dangling-pointer
CFLAGS += -DDEF_THREADPOOL_SIZE=CONFIG_LIBUV_THREADPOOL_SIZE
CFLAGS += -DDEF_THREADPOOL_STACKSIZE=CONFIG_LIBUV_THREAD_STACKSIZE
CFLAGS += -DDEF_THREADPOOL_PRIORITY=CONFIG_LIBUV_THREADPOOL_PRIORITY
CFLAGS += -DMAX_EPOLL_EVENTS=CONFIG_LIBUV_MAX_EPOLL_EVENTS
CFLAGS += -DPREP_EVENT_SIZE=CONFIG_LIBUV_PREP_EVENT_SIZE
CFLAGS += -DDEF_STREAM_READ_BUF_SIZE=CONFIG_LIBUV_STREAM_READ_BUF_SIZE

include tests/Makefile

VPATH += tests
VPATH += src
DEPPATH += --dep-path src

CSRCS += uv_mqueue.c
CSRCS += uv_async_queue.c

ifeq ($(CONFIG_KVDB), y)
CSRCS += uv_devinfo.c
endif

ifeq ($(CONFIG_CRYPTO_MBEDTLS), y)
CSRCS += uv_aes.c
endif

CSRCS += uv_brightness.c

ifeq ($(CONFIG_KVDB), y)
CSRCS += uv_locale.c
endif

ifeq ($(CONFIG_KVDB), y)
CSRCS += uv_property.c
endif

ifeq ($(CONFIG_UNQLITE), y)
CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/external/unqlite/unqlite
CSRCS += uv_db.c
endif

ifeq ($(CONFIG_CRYPTO_MBEDTLS), y)
CSRCS += uv_crypto.c
endif

ifeq ($(CONFIG_UORB), y)
CSRCS += uv_topic.c
CSRCS += uv_topicadv.c
endif

ifeq ($(CONFIG_LIB_CURL),y)
CSRCS += uv_request.c
CSRCS += uv_networkcache.c
endif

ifeq ($(CONFIG_MEDIA), y)
CSRCS += uv_audio.c
CSRCS += uv_record.c
CSRCS += uv_volume.c
endif

ifeq ($(CONFIG_LIB_CURL), y)
CSRCS += uv_networkstatus.c
endif

ifeq ($(CONFIG_LIB_ZLIB)$(CONFIG_CRYPTO_MBEDTLS), yy)
CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/system/zlib/zlib/contrib/minizip
CFLAGS += ${INCDIR_PREFIX}$(APPDIR)/system/zlib/zlib
CSRCS += app_verify.c
endif

include $(APPDIR)/Application.mk
