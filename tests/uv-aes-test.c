
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

#include <stdlib.h>
#include <string.h>
#include <uv_ext.h>

static int crypto_mode[] = {
    MBEDTLS_CIPHER_AES_128_ECB, /**< MBEDTLS is fail */
    MBEDTLS_CIPHER_AES_192_ECB, /**< MBEDTLS is fail */
    MBEDTLS_CIPHER_AES_256_ECB, /**< MBEDTLS is fail */
    MBEDTLS_CIPHER_AES_128_CBC,
    MBEDTLS_CIPHER_AES_192_CBC,
    MBEDTLS_CIPHER_AES_256_CBC,
    MBEDTLS_CIPHER_AES_128_CFB128,
    MBEDTLS_CIPHER_AES_192_CFB128,
    MBEDTLS_CIPHER_AES_256_CFB128,
    MBEDTLS_CIPHER_AES_128_CTR,
    MBEDTLS_CIPHER_AES_192_CTR,
    MBEDTLS_CIPHER_AES_256_CTR,
    MBEDTLS_CIPHER_AES_128_GCM,
    MBEDTLS_CIPHER_AES_192_GCM,
    MBEDTLS_CIPHER_AES_256_GCM,
};

static int padding_mode[] = {
    MBEDTLS_PADDING_PKCS7,
    MBEDTLS_PADDING_ONE_AND_ZEROS,
    MBEDTLS_PADDING_ZEROS_AND_LEN,
    MBEDTLS_PADDING_ZEROS,
};

static void help(void)
{
    printf("usage:  uv_aes <mode> <data> \n");
    printf("<mode>: 1 = base64, 0 = no base64 \n");
    printf("<data>: a string of data \n");
}

int main(int argc, char* argv[])
{
    if (argc != 3) {
        help();
        return -1;
    }

    int mode = atoi(argv[1]);
    const unsigned char* pstr = (unsigned char*)argv[2];
    unsigned char pstrbuff[1024] = { 0 };
    size_t pstrbufflen;
    unsigned char decbuff[1024] = { 0 };
    size_t decbufflen;
    int i, j;

    if (mode) {
        const unsigned char key[64] = "MTIzNDU2Nzg5"; // 123456789
        const unsigned char iv[64] = "MTIzNDU2Nzg5";
        uv_aes_t ctx;

        for (i = 0; i < sizeof(crypto_mode) / sizeof(crypto_mode[0]); i++) {
            for (j = 0; j < sizeof(padding_mode) / sizeof(padding_mode[0]); j++) {

                /* encryption */

                memset(&ctx, 0, sizeof(uv_aes_t));
                memset(pstrbuff, 0, sizeof(pstrbuff));

                if (uv_aes_init(&ctx, crypto_mode[i], padding_mode[j]) != 0) {
                    goto testfail;
                }
                printf("\ntest type: %s\n", ctx.aes_context.cipher_info->name);

                if (uv_aes_set_key_base64(&ctx, MBEDTLS_ENCRYPT, key,
                        ctx.aes_context.cipher_info->key_bitlen)
                    != 0) {
                    goto testfail;
                }

                if (ctx.aes_context.cipher_info->iv_size != 0 && uv_aes_set_iv_base64(&ctx, iv, 0, ctx.aes_context.cipher_info->iv_size) != 0) {
                    goto testfail;
                }

                if (uv_aes_encrypt_base64(&ctx, pstr, strlen((const char*)pstr),
                        pstrbuff, sizeof(pstrbuff), &pstrbufflen)
                    != 0) {
                    goto testfail;
                }

                uv_aes_free(&ctx);

                /* decryption */

                memset(&ctx, 0, sizeof(uv_aes_t));
                memset(decbuff, 0, sizeof(decbuff));

                if (uv_aes_init(&ctx, crypto_mode[i], padding_mode[j]) != 0) {
                    goto testfail;
                }

                if (uv_aes_set_key_base64(&ctx, MBEDTLS_DECRYPT, key,
                        ctx.aes_context.cipher_info->key_bitlen)
                    != 0) {
                    goto testfail;
                }

                if (ctx.aes_context.cipher_info->iv_size != 0 && uv_aes_set_iv_base64(&ctx, iv, 0, ctx.aes_context.cipher_info->iv_size) != 0) {
                    goto testfail;
                }

                if (uv_aes_decrypt_base64(&ctx, pstrbuff, pstrbufflen, decbuff, &decbufflen) != 0) {
                    goto testfail;
                }

                uv_aes_free(&ctx);

                decbuff[decbufflen] = '\0';
                printf("result: %s, len=%d\n", decbuff, decbufflen);
            }
        }
    } else {
        const unsigned char key[32] = "1234567890123";
        const unsigned char iv[32] = "1234567890123";
        uv_aes_t ctx;

        for (i = 0; i < sizeof(crypto_mode) / sizeof(crypto_mode[0]); i++) {
            for (j = 0; j < sizeof(padding_mode) / sizeof(padding_mode[0]); j++) {

                /* encryption */

                memset(&ctx, 0, sizeof(uv_aes_t));
                memset(pstrbuff, 0, sizeof(pstrbuff));

                if (uv_aes_init(&ctx, crypto_mode[i], padding_mode[j]) != 0) {
                    goto testfail;
                }
                printf("\ntest type: %s\n", ctx.aes_context.cipher_info->name);

                if (uv_aes_set_key(&ctx, MBEDTLS_ENCRYPT, key,
                        ctx.aes_context.cipher_info->key_bitlen)
                    != 0) {
                    goto testfail;
                }

                if (ctx.aes_context.cipher_info->iv_size != 0 && uv_aes_set_iv(&ctx, iv, 0, ctx.aes_context.cipher_info->iv_size) != 0) {
                    goto testfail;
                }

                if (uv_aes_encrypt(&ctx, pstr, strlen((const char*)pstr), pstrbuff, &pstrbufflen) != 0) {
                    goto testfail;
                }

                uv_aes_free(&ctx);

                /* decryption */

                memset(&ctx, 0, sizeof(uv_aes_t));
                memset(decbuff, 0, sizeof(decbuff));

                if (uv_aes_init(&ctx, crypto_mode[i], padding_mode[j]) != 0) {
                    goto testfail;
                }

                if (uv_aes_set_key(&ctx, MBEDTLS_DECRYPT, key,
                        ctx.aes_context.cipher_info->key_bitlen)
                    != 0) {
                    goto testfail;
                }

                if (ctx.aes_context.cipher_info->iv_size != 0 && uv_aes_set_iv(&ctx, iv, 0, ctx.aes_context.cipher_info->iv_size) != 0) {
                    goto testfail;
                }

                if (uv_aes_decrypt(&ctx, pstrbuff, pstrbufflen, decbuff, &decbufflen) != 0) {
                    goto testfail;
                }

                uv_aes_free(&ctx);

                decbuff[decbufflen] = '\0';
                printf("result: %s, len=%d\n", decbuff, decbufflen);
            }
        }
    }
    printf("TEST PASSED !\n");
    exit(0);

testfail:
    printf("TEST FAILED !\n");
    exit(1);
}
