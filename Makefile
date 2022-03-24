############################################################################
# system/libuv/ext/Makefile
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

ifneq ($(CONFIG_LIBUV_EXTENSION),)

include ext/tests/Makefile

VPATH += ext/src
DEPPATH += --dep-path ext/src

CSRCS += uv_devinfo.c
CSRCS += uv_mqueue.c

ifeq ($(CONFIG_LIB_MBEDTLS), y)
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
CFLAGS += ${shell $(INCDIR) $(INCDIROPT) "$(CC)" $(APPDIR)/external/unqlite}
CSRCS += uv_db.c
endif

ifeq ($(CONFIG_LIB_MBEDTLS), y)
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

ifeq ($(CONFIG_MIWEAR_COMMON), y)
CSRCS += uv_miwear.c
endif

ifeq ($(CONFIG_MEDIA), y)
CSRCS += uv_audio.c
CSRCS += uv_record.c
endif

ifeq ($(CONFIG_LIB_CURL)$(CONFIG_UORB), yy)
CSRCS += uv_networkstatus.c
endif

ifeq ($(CONFIG_MIWEAR_APPS), y)
CFLAGS += ${shell $(INCDIR) $(INCDIROPT) "$(CC)" $(APPDIR)/external/zlib/contrib/minizip}
CFLAGS += ${shell $(INCDIR) $(INCDIROPT) "$(CC)" $(APPDIR)/external/zlib}
CSRCS += app_verify.c
endif

endif #CONFIG_LIBUV_EXTENSION
