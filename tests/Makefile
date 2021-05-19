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

include $(APPDIR)/Make.defs

PRIORITY  = $(CONFIG_LIBUV_EXTENSION_TEST_PRIORITY)
STACKSIZE = $(CONFIG_LIBUV_EXTENSION_TEST_TASK_STACKSIZE)
MODULE    = $(CONFIG_LIBUV_EXTENSION_TEST)

PROGNAME += uv_aes
MAINSRC  += uv-aes-test.c

PROGNAME += uv_rsa
MAINSRC  += uv-rsa-test.c

PROGNAME += uv_topic
MAINSRC  += uv-topic-test.c

PROGNAME += uv_kvdb
MAINSRC  += uv-kvdb-test.c

include $(APPDIR)/Application.mk
