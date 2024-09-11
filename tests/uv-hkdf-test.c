/*
 * Copyright (C) 2024 Xiaomi Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
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

#include <stdio.h>
#include <uv_ext.h>

static void usage(void)
{
    printf("usage: uv_hkdf\n");
}

int main(int argc, char* argv[])
{
    uint8_t salt[13] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c
    };
    size_t salt_len = 13;
    uint8_t ikm[21] = {
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b, 0x0b,
        0x0b, 0x0b, 0x0b, 0x0b, 0x0b
    };
    size_t ikm_len = 21;
    uint8_t info[10] = {
        0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7,
        0xf8, 0xf9
    };
    size_t info_len = 10;
    uint8_t expected_result[] = {
        0x8a, 0x34, 0x3e, 0xbf, 0x7a, 0xf1, 0x54, 0xae,
        0xf7, 0x4e, 0xb9, 0xbe, 0xfa, 0x06, 0x12, 0x7a,
        0xef, 0xc8, 0x1c, 0xe0, 0x4d, 0xf1, 0x81, 0xd1,
        0x0c, 0xec, 0xa1, 0x08, 0x53, 0xed, 0xa9, 0xec
    };

    uint8_t okm[32] = { 0 };
    size_t okm_len = 32;
    int i;

    if (argc != 1) {
        usage();
        return -1;
    }

    printf("test start\n");

    if (uv_hkdf_key_derivation("SHA256", salt, salt_len, ikm, ikm_len, info, info_len, okm, okm_len) != 0) {
        printf("uv_hkdf_key_derivation failed\n");
        return -1;
    }

    printf("okm: ");
    for (i = 0; i < okm_len; i++) {
        printf("%02x", okm[i]);
    }
    printf("\n");

    printf("expected okm: ");
    for (i = 0; i < 32; i++) {
        printf("%02x", expected_result[i]);
    }
    printf("\n");

    if (memcmp(okm, expected_result, okm_len) != 0) {
        printf("uv_hkdf_key_derivation failed\n");
        return -1;
    }

    printf("test pass\n");

    return 0;
}
