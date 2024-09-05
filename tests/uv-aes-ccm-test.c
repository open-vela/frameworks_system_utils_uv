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

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <uv_ext.h>

#define NB_TESTS 3
#define CCM_SELFTEST_PT_MAX_LEN 24
#define CCM_SELFTEST_CT_MAX_LEN 32

static const unsigned char g_key_test_data[] = {
    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
    0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f
};

static const unsigned char g_iv_test_data[] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b
};

static const unsigned char g_aad_test_data[] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13
};

static const unsigned char g_msg_test_data[CCM_SELFTEST_PT_MAX_LEN] = {
    0x20,
    0x21,
    0x22,
    0x23,
    0x24,
    0x25,
    0x26,
    0x27,
    0x28,
    0x29,
    0x2a,
    0x2b,
    0x2c,
    0x2d,
    0x2e,
    0x2f,
    0x30,
    0x31,
    0x32,
    0x33,
    0x34,
    0x35,
    0x36,
    0x37,
};
static const size_t g_iv_len_test_data[NB_TESTS] = { 7, 8, 12 };
static const size_t g_add_len_test_data[NB_TESTS] = { 8, 16, 20 };
static const size_t g_msg_len_test_data[NB_TESTS] = { 4, 16, 24 };
static const size_t g_tag_len_test_data[NB_TESTS] = { 4, 6, 8 };
static const unsigned char g_res_test_data[NB_TESTS][CCM_SELFTEST_CT_MAX_LEN] = {
    { 0x71, 0x62, 0x01, 0x5b, 0x4d, 0xac, 0x25, 0x5d },
    { 0xd2, 0xa1, 0xf0, 0xe0, 0x51, 0xea, 0x5f, 0x62,
        0x08, 0x1a, 0x77, 0x92, 0x07, 0x3d, 0x59, 0x3d,
        0x1f, 0xc6, 0x4f, 0xbf, 0xac, 0xcd },
    { 0xe3, 0xb2, 0x01, 0xa9, 0xf5, 0xb7, 0x1a, 0x7a,
        0x9b, 0x1c, 0xea, 0xec, 0xcd, 0x97, 0xe7, 0x0b,
        0x61, 0x76, 0xaa, 0xd9, 0xa4, 0x42, 0x8a, 0xa5,
        0x48, 0x43, 0x92, 0xfb, 0xc1, 0xb0, 0x99, 0x51 }
};

static void usage(void)
{
    printf("usage: uv_aes_ccm \n");
}

int main(int argc, char* argv[])
{
    if (argc > 1) {
        usage();
        return -1;
    }

    uv_aes_t ctx;
    unsigned char plaintext[CCM_SELFTEST_PT_MAX_LEN];
    unsigned char ciphertext[CCM_SELFTEST_CT_MAX_LEN];
    size_t i, j;
    int ret = 0, ciphertext_len = 0, plaintext_len = 0;

    printf("aes-128-ccm test start\n");
    printf("key: ");
    for (j = 0; j < sizeof(g_key_test_data) / sizeof(g_key_test_data[0]); j++) {
        printf("%02x", g_key_test_data[j]);
    }
    printf("\n");

    if ((ret = uv_aes_init(&ctx, MBEDTLS_CIPHER_AES_128_CCM, MBEDTLS_PADDING_NONE)) != 0) {
        printf("uv_aes_init : init error\n");
        return -1;
    }

    if ((ret = uv_aes_set_key(&ctx, MBEDTLS_ENCRYPT, g_key_test_data, 8 * sizeof(g_key_test_data))) != 0) {
        printf("uv_aes_set_key : set key error\n");
        goto exit;
    }

    for (i = 0; i < NB_TESTS; i++) {
        memset(plaintext, 0, CCM_SELFTEST_PT_MAX_LEN);
        memset(ciphertext, 0, CCM_SELFTEST_CT_MAX_LEN);
        memcpy(plaintext, g_msg_test_data, g_msg_len_test_data[i]);
        plaintext_len = g_msg_len_test_data[i];
        ciphertext_len = g_msg_len_test_data[i] + g_tag_len_test_data[i];

        printf("raw data: ");
        for (j = 0; j < plaintext_len; j++) {
            printf("%02x", plaintext[j]);
        }
        printf("\n");

        printf("iv: ");
        for (j = 0; j < g_iv_len_test_data[i]; j++) {
            printf("%02x", g_iv_test_data[j]);
        }
        printf("\n");

        printf("aad: ");
        for (j = 0; j < g_add_len_test_data[i]; j++) {
            printf("%02x", g_aad_test_data[j]);
        }
        printf("\n");

        if ((ret = uv_aes_auth_encrypt(&ctx, g_iv_test_data, g_iv_len_test_data[i], (unsigned char*)g_aad_test_data, g_add_len_test_data[i],
                 g_tag_len_test_data[i], plaintext, plaintext_len, ciphertext, ciphertext_len, (size_t*)&ciphertext_len))
            != 0) {
            printf("uv_aes_auth_encrypt : encrypt error\n");
            goto exit;
        }

        printf("ciphertext: ");
        for (j = 0; j < ciphertext_len; j++) {
            printf("%02x", ciphertext[j]);
        }
        printf("\n");

        printf("tag length : %d\n", g_tag_len_test_data[i]);

        if (memcmp(ciphertext, g_res_test_data[i], g_msg_len_test_data[i] + g_tag_len_test_data[i]) != 0) {
            printf("uv_aes_auth_encrypt : wrong ciphertext \n");
            goto exit;
        }

        memset(plaintext, 0, CCM_SELFTEST_PT_MAX_LEN);
        if ((ret = uv_aes_auth_decrypt(&ctx, g_iv_test_data, g_iv_len_test_data[i], (unsigned char*)g_aad_test_data, g_add_len_test_data[i],
                       g_tag_len_test_data[i], ciphertext, ciphertext_len, plaintext, plaintext_len, (size_t*)&plaintext_len)
                    != 0)) {
            printf("uv_aes_auth_decrypt : decrypt error\n");
            goto exit;
        }

        printf("plaintext: ");
        for (j = 0; j < plaintext_len; j++) {
            printf("%02x", plaintext[j]);
        }
        printf("\n");

        if (memcmp(plaintext, g_msg_test_data, g_msg_len_test_data[i]) != 0) {
            printf("uv_aes_auth_decrypt : wrong plaintext\n");
            goto exit;
        }

        printf("aes-128-ccm : test-%d pass\n", i);
    }

exit:
    uv_aes_free(&ctx);

    return ret;
}
