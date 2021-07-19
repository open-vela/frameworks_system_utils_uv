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

ifeq ($(CONFIG_LIB_MBEDTLS), y)
CSRCS += uv_aes.c
endif

ifeq ($(CONFIG_LCD_DEV)$(CONFIG_UORB), yy)
CSRCS += uv_brightness.c
endif

ifeq ($(CONFIG_KVDB), y)
CSRCS += uv_locale.c
endif

ifeq ($(CONFIG_KVDB), y)
CSRCS += uv_property.c
endif

ifeq ($(CONFIG_LIB_MBEDTLS), y)
CSRCS += uv_rsa.c
endif

ifeq ($(CONFIG_UORB), y)
CSRCS += uv_topic.c
endif

ifeq ($(CONFIG_LIB_CURL),y)
CSRCS += uv_request.c
endif

ifeq ($(CONFIG_MIWEAR_APPS), y)
CSRCS += uv_miwear.c
endif

ifeq ($(CONFIG_MEDIA_SERVICE), y)
CSRCS += uv_audio.c
endif

endif #CONFIG_LIBUV_EXTENSION

include $(APPDIR)/Application.mk

