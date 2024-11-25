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

#include <mbedtls/md.h>
#include <mbedtls/rsa.h>
#include <string.h>
#include <uv_ext.h>

static int padding_mode[] = {
    MBEDTLS_RSA_PKCS_V15, /**< Use PKCS#1 v1.5 encoding. */
    MBEDTLS_RSA_PKCS_V21 /**< Use PKCS#1 v2.1 encoding. */
};

static int hashid_mode[] = {
    MBEDTLS_MD_MD2, /**< The MD2 message digest. MBEDTLS_RSA_PKCS_V21 is fail */
    MBEDTLS_MD_MD4, /**< The MD4 message digest. MBEDTLS_RSA_PKCS_V21 is fail */
    MBEDTLS_MD_MD5, /**< The MD5 message digest. */
    MBEDTLS_MD_SHA1, /**< The SHA-1 message digest. */
    MBEDTLS_MD_SHA224, /**< The SHA-224 message digest. */
    MBEDTLS_MD_SHA256, /**< The SHA-256 message digest. */
    MBEDTLS_MD_SHA384, /**< The SHA-384 message digest. */
    MBEDTLS_MD_SHA512, /**< The SHA-512 message digest. MBEDTLS_RSA_PKCS_V21 is fail */
    MBEDTLS_MD_RIPEMD160, /**< The RIPEMD-160 message digest. */
};

static void help(void)
{
    printf("usage:  uv_rsa <mode> <data> \n");
    printf("<mode>: 1 = base64, 0 = no base64 \n");
    printf("<data>: a string of data \n");
}

static const unsigned char pubkey[] = "-----BEGIN PUBLIC KEY-----\n\
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCEXjbgdXF/LFtJwCgUyAg+9DRH\n\
TlVm5WMiCGSh7x6f5JUHv1dGipLrS1/tNcTqw4iSb2NHG0IgEXnRuw9BFD5PRFTg\n\
VmPtKo0N4XelaK0maC+svcNJRKRuhFwIoimfV4ZKnnehVockMhIVje/+Fg3TvKTy\n\
Nqr/PoD6nZpaLZiTEwIDAQAB\n\
-----END PUBLIC KEY-----\n";

static const unsigned char prikey[] = "-----BEGIN RSA PRIVATE KEY-----\n\
MIICXAIBAAKBgQCEXjbgdXF/LFtJwCgUyAg+9DRHTlVm5WMiCGSh7x6f5JUHv1dG\n\
ipLrS1/tNcTqw4iSb2NHG0IgEXnRuw9BFD5PRFTgVmPtKo0N4XelaK0maC+svcNJ\n\
RKRuhFwIoimfV4ZKnnehVockMhIVje/+Fg3TvKTyNqr/PoD6nZpaLZiTEwIDAQAB\n\
AoGAAJrFjro6mHrFYqLZYVmV4A5m0WSO3fdyP8zgrh9UznomzBrtn8mGPkOL3p4o\n\
62w/4BtYzWcBzaUGyhRxT2TI8WYI87LUuEREcQ1fTSOSXb1urSBiKJknWj5YRhrc\n\
2nTLkaXtI8aALcHVZ3xofN52f3kMqZ57V9sL4SeKBEFaoaECQQCa9udfaXSxw3IE\n\
M1YbLGKJr237cjdxiM8tcmk7gHYJgr7v2YcU+d9UGySpukqjzpzOEhQDtrqNdb+n\n\
laHVlfXLAkEA2qu92q7Xae2KWUIpfvWqYmvP0AqryOMfUDLJwsbSXxjVF/4k040M\n\
aTrNIc8e9n6OjYgIjVstjVm9dCliydpu2QJAHauQeVAzq6WEOxGpNuK0qzAPmskv\n\
nGlZYZY6V84sy31hGYNIvddpzyyzRFwK1npEw5/qfRuLdHJLE8cuiTqBKQJBANpV\n\
eG8M/BDMGMMeiIg3ijRTKV+0B+nAvNc6nrFYC1zgUoRuQR7pSmcXSxJi16uOmY8/\n\
MCrTyxvDaqK9X+Hjs6ECQFmMxcGnPxsP71jPQ9XVKd4lkmzcskqtMATm6N8ng+fG\n\
zyrMcXTwGgtWaQVBWuOCTSXvagFq4/deaZuvucWmlgQ=\n\
-----END RSA PRIVATE KEY-----\n";

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
        uv_rsa_t ctx;

        for (i = 0; i < sizeof(padding_mode) / sizeof(padding_mode[0]); i++) {
            for (j = 0; j < sizeof(hashid_mode) / sizeof(hashid_mode[0]); j++) {

                printf("\ntest type: padding=%d hash=%d\n", padding_mode[i], hashid_mode[j]);

                /* encryption */

                memset(&ctx, 0, sizeof(uv_rsa_t));
                memset(pstrbuff, 0, sizeof(pstrbuff));

                if (uv_rsa_parse_key(&ctx, MBEDTLS_RSA_PUBLIC, pubkey, sizeof(pubkey)) != 0) {
                    printf("uv_rsa_parse_key fail\n");
                    goto testfail;
                }

                if (uv_rsa_set_padding(&ctx, padding_mode[i], hashid_mode[j]) != 0) {
                    printf("uv_rsa_set_padding fail\n");
                    goto testfail;
                }

                if (uv_rsa_encrypt_base64(&ctx, pstr, pstrbuff, &pstrbufflen, sizeof(pstrbuff)) != 0) {
                    printf("encrypt fail. \n");
                    goto testfail;
                }

                uv_rsa_free(&ctx);

                /* decryption */

                memset(&ctx, 0, sizeof(uv_rsa_t));
                memset(decbuff, 0, sizeof(decbuff));

                if (uv_rsa_parse_key(&ctx, MBEDTLS_RSA_PRIVATE, prikey, sizeof(prikey)) != 0) {
                    printf("uv_rsa_parse_key fail\n");
                    goto testfail;
                }

                if (uv_rsa_set_padding(&ctx, padding_mode[i], hashid_mode[j]) != 0) {
                    printf("uv_rsa_set_padding fail\n");
                    goto testfail;
                }

                if (uv_rsa_decrypt_base64(&ctx, pstrbuff, pstrbufflen, decbuff,
                        &decbufflen, sizeof(decbuff))
                    != 0) {
                    printf("uv_rsa_base64_decrypt fail\n");
                    goto testfail;
                }

                uv_rsa_free(&ctx);

                printf("result: %s, len=%d\n", decbuff, decbufflen);
            }
        }
    } else {
        uv_rsa_t ctx;

        for (i = 0; i < sizeof(padding_mode) / sizeof(padding_mode[0]); i++) {
            for (j = 0; j < sizeof(hashid_mode) / sizeof(hashid_mode[0]); j++) {

                printf("\ntest type: padding=%d hash=%d\n", padding_mode[i], hashid_mode[j]);

                /* encryption */

                memset(&ctx, 0, sizeof(uv_rsa_t));
                memset(pstrbuff, 0, sizeof(pstrbuff));

                if (uv_rsa_parse_key(&ctx, MBEDTLS_RSA_PUBLIC, pubkey, sizeof(pubkey)) != 0) {
                    printf("uv_rsa_parse_key fail\n");
                    goto testfail;
                }

                if (uv_rsa_set_padding(&ctx, padding_mode[i], hashid_mode[j]) != 0) {
                    printf("uv_rsa_set_padding fail\n");
                    goto testfail;
                }

                if (uv_rsa_encrypt(&ctx, strlen((const char*)pstr), pstr, pstrbuff) != 0) {
                    printf("encrypt fail. \n");
                    goto testfail;
                }

                uv_rsa_free(&ctx);

                /* decryption */

                memset(&ctx, 0, sizeof(uv_rsa_t));
                memset(decbuff, 0, sizeof(decbuff));

                if (uv_rsa_parse_key(&ctx, MBEDTLS_RSA_PRIVATE, prikey, sizeof(prikey)) != 0) {
                    printf("uv_rsa_parse_key fail\n");
                    goto testfail;
                }

                if (uv_rsa_set_padding(&ctx, padding_mode[i], hashid_mode[j]) != 0) {
                    printf("uv_rsa_set_padding fail\n");
                    goto testfail;
                }

                if (uv_rsa_decrypt(&ctx, &decbufflen, pstrbuff, decbuff, sizeof(decbuff)) != 0) {
                    printf("uv_rsa_base64_decrypt fail\n");
                    goto testfail;
                }

                uv_rsa_free(&ctx);

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