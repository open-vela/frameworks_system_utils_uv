/*
 * Copyright (C) 2020 Xiaomi Corporation
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

static const char* g_raw[] = {
    "This a string for test",
    "1122334455667788",
};

static const uint8_t g_key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static const size_t g_key_size[] = {
    16,
    24,
    32,
    16,
    24,
    32,
};

static const uint8_t g_iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

static const size_t g_iv_size = 16;

static const int g_crypto_mode[] = {
    MBEDTLS_CIPHER_AES_128_ECB,
    MBEDTLS_CIPHER_AES_192_ECB,
    MBEDTLS_CIPHER_AES_256_ECB,
    MBEDTLS_CIPHER_AES_128_CBC,
    MBEDTLS_CIPHER_AES_192_CBC,
    MBEDTLS_CIPHER_AES_256_CBC,
};

static const int g_padding_mode[] = {
    MBEDTLS_PADDING_PKCS7,
    MBEDTLS_PADDING_NONE,
};

static int aes_non_auth_test(const char* data, const uint8_t* key, size_t key_size, const uint8_t* iv, size_t iv_size, int mode, int padding)
{
    uint8_t encrypt[64] = { 0 };
    size_t encrypt_size = 64;
    uint8_t plaint[64] = { 0 };
    size_t plaint_size = 64;
    uv_aes_t ctx;

    /* encryption */
    printf("encryption starts\n");
    if (uv_aes_init(&ctx, mode, padding) != 0) {
        printf("uv_aes_init : init error\n");
        return -1;
    }

    printf("test type: %s\n", ctx.aes_context.cipher_info->name);

    if (uv_aes_set_key(&ctx, MBEDTLS_ENCRYPT, key, key_size * 8) != 0) {
        printf("uv_aes_set_key : set key error\n");
        goto testfail;
    }

    if (uv_aes_set_iv(&ctx, iv, 0, iv_size) != 0) {
        printf("uv_aes_set_iv : set iv error\n");
        goto testfail;
    }

    if (uv_aes_encrypt(&ctx, data, strlen((const char*)data), encrypt, &encrypt_size) != 0) {
        printf("uv_aes_encrypt : encrypt error\n");
        goto testfail;
    }

    uv_aes_free(&ctx);

    printf("encryption success\n");

    /* decryption */

    printf("decryption starts\n");
    if (uv_aes_init(&ctx, mode, padding) != 0) {
        printf("uv_aes_init : init error\n");
        return -1;
    }

    if (uv_aes_set_key(&ctx, MBEDTLS_DECRYPT, key, key_size * 8) != 0) {
        printf("uv_aes_set_key : set key error\n");
        goto testfail;
    }

    if (uv_aes_set_iv(&ctx, iv, 0, iv_size) != 0) {
        printf("uv_aes_set_iv : set iv error\n");
        goto testfail;
    }

    if (uv_aes_decrypt(&ctx, encrypt, encrypt_size, plaint, &plaint_size) != 0) {
        printf("uv_aes_decrypt : decrypt error\n");
        goto testfail;
    }

    plaint[plaint_size] = '\0';
    printf("plaint : %s, plaint_size = %d\n", plaint, plaint_size);
    if (memcmp(data, plaint, strlen((const char*)data)) != 0) {
        printf("decrypt error\n");
        goto testfail;
    } else {
        printf("decrypt success\n");
    }

    uv_aes_free(&ctx);
    return 0;

testfail:
    uv_aes_free(&ctx);
    return -1;
}

static void usage(void)
{
    printf("usage: uv_aes\n");
}

int main(int argc, char* argv[])
{
    if (argc > 1) {
        usage();
        return -1;
    }

    int ret, i, j, fail_count;

    fail_count = 0;
    for (i = 0; i < sizeof(g_crypto_mode) / sizeof(g_crypto_mode[0]); i++) {
        for (j = 0; j < sizeof(g_padding_mode) / sizeof(g_padding_mode[0]); j++) {
            if (g_crypto_mode[i] != MBEDTLS_CIPHER_AES_128_ECB && g_crypto_mode[i] != MBEDTLS_CIPHER_AES_192_ECB && g_crypto_mode[i] != MBEDTLS_CIPHER_AES_256_ECB) {
                ret = aes_non_auth_test(g_raw[j], g_key, g_key_size[i], g_iv, g_iv_size, g_crypto_mode[i], g_padding_mode[j]);
            } else {
                ret = aes_non_auth_test(g_raw[j], g_key, g_key_size[i], NULL, 0, g_crypto_mode[i], g_padding_mode[j]);
            }

            if (ret != 0) {
                fail_count++;
                printf("TEST FAILED ! mode : %d , padding : %d\n", g_crypto_mode[i], g_padding_mode[j]);
            }
        }
    }

    if (fail_count == 0) {
        printf("ALL TEST SUCCESS !\n");
    } else {
        printf("SOME TEST FAILED !\n");
    }

    return 0;
}
