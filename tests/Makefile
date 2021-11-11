############################################################################
# Copyright (C) 2021 Xiaomi Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
############################################################################

ifneq ($(CONFIG_LIBUV_EXTENSION_TEST),)

VPATH += ext/tests
DEPPATH += --dep-path ext/tests

PRIORITY  = $(CONFIG_LIBUV_EXTENSION_TEST_PRIORITY)
STACKSIZE = $(CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE)
MODULE    = $(CONFIG_LIBUV_EXTENSION_TEST)

PROGNAME += uv_devinfo
MAINSRC  += uv-devinfo-test.c

ifeq ($(CONFIG_LIB_MBEDTLS), y)
PROGNAME += uv_aes
MAINSRC  += uv-aes-test.c
endif

ifeq ($(CONFIG_LCD_DEV)$(CONFIG_UORB), yy)
PROGNAME += uv_brightness
MAINSRC  += uv-brightness-test.c
endif

ifeq ($(CONFIG_KVDB), y)
PROGNAME += uv_locale
MAINSRC  += uv-locale-test.c
endif

ifeq ($(CONFIG_LIB_CURL), y)
PROGNAME += uv_request
MAINSRC  += uv-request-test.c
endif

ifeq ($(CONFIG_KVDB), y)
PROGNAME += uv_property
MAINSRC  += uv-property-test.c
endif

ifeq ($(CONFIG_LIB_MBEDTLS), y)
PROGNAME += uv_rsa
MAINSRC  += uv-rsa-test.c
endif

ifeq ($(CONFIG_UORB), y)
PROGNAME += uv_topic
MAINSRC  += uv-topic-test.c
endif

ifeq ($(CONFIG_MIWEAR_APPS), y)
PROGNAME += miwear_server
MAINSRC  += uv-miwear-server-test.c
PROGNAME += miwear_client
MAINSRC  += uv-miwear-client-test.c
endif

ifeq ($(CONFIG_MEDIA), y)
PROGNAME += uv_audio
MAINSRC  += uv-audio-test.c
endif

ifeq ($(CONFIG_LIB_CURL)$(CONFIG_UORB),yy)
PROGNAME += uv_network
MAINSRC  += uv-network-test.c
endif

ifeq ($(CONFIG_MIWEAR_APPS), y)
PROGNAME += app_verify
MAINSRC  += app-verify-test.c
endif

ifeq ($(CONFIG_LIB_CURL), y)
PROGNAME += uv_ncm
MAINSRC  += uv-ncm-test.c
endif

ifeq ($(CONFIG_UNQLITE), y)
PROGNAME += uv_db
MAINSRC  += uv-db-test.c
endif

depend::
	$(Q) touch $(addprefix  ext/tests/,$(MAINSRC) )

endif #CONFIG_LIBUV_EXTENSION_TEST
