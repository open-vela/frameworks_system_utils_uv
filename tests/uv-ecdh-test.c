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
    printf("usage: uv_ecdh \n");
}

static int test_ecdh_compute_shared_key_1(void)
{
    int ret, i;
    uv_ecp_t ctx_1;
    uv_ecp_t ctx_2;
    unsigned char prikey_1[256] = { 0 };
    size_t prikey_1_size = 32;
    unsigned char pubkey_1[256] = { 0 };
    size_t pubkey_1_size = 65;
    const unsigned char prikey_2[] = {
        0x52, 0x78, 0x85, 0xEE, 0xCA, 0xCF, 0xBF, 0x54,
        0x56, 0x52, 0xEA, 0xC3, 0xFB, 0xC3, 0x50, 0x8F,
        0x53, 0xEC, 0x2A, 0x95, 0xE0, 0xAC, 0x2E, 0x7C,
        0x10, 0xF4, 0x5B, 0x75, 0x70, 0xE1, 0xED, 0x76
    };
    size_t prikey_2_size = 32;
    const unsigned char pubkey_2[] = {
        0x04, 0x50, 0x47, 0x61, 0xB1, 0x84, 0xBE, 0x09,
        0x6F, 0xFE, 0x59, 0x2D, 0x48, 0x81, 0x94, 0x9D,
        0xED, 0x6E, 0x66, 0xF7, 0x2A, 0x0A, 0x33, 0xC3,
        0x83, 0x4D, 0x08, 0x0D, 0xFC, 0xCB, 0x6C, 0x2D,
        0xF3, 0xC9, 0xFC, 0xA9, 0xC9, 0xB7, 0xE9, 0xA2,
        0x37, 0x79, 0x4E, 0xBB, 0x52, 0xD1, 0xCA, 0x80,
        0xB2, 0xF9, 0x01, 0xFA, 0x52, 0xFD, 0xEE, 0x28,
        0x56, 0xD9, 0xE8, 0xE8, 0xB3, 0xEF, 0x47, 0xB8,
        0xF9
    };
    size_t pubkey_2_size = 65;
    unsigned char pubkey_2_read[256] = { 0 };
    size_t pubkey_read_size = 32;
    unsigned char sharedkey_1[32] = { 0 };
    size_t sharedkey_1_len = 32;
    unsigned char sharedkey_2[32] = { 0 };
    size_t sharedkey_2_len = 32;

    ret = uv_ecdh_init(&ctx_1, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        printf("uv_ecdh_init failed\n");
        return -1;
    }

    ret = uv_ecdh_init(&ctx_2, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        printf("uv_ecdh_init failed\n");
        return -1;
    }

    ret = uv_ecdh_gen_keypair(&ctx_1);
    if (ret != 0) {
        printf("uv_ecdh_gen_keypair failed\n");
        goto free_and_exit;
    }

    ret = uv_ecdh_get_privkey(&ctx_1, prikey_1, prikey_1_size);
    if (ret != 0) {
        printf("uv_ecdh_get_privkey failed\n");
        goto free_and_exit;
    }
    printf("prikey_1 size is %zu\n", prikey_1_size);
    printf("prikey_1: ");
    for (i = 0; i < prikey_1_size; i++) {
        printf("%02x", prikey_1[i]);
    }
    printf("\n");

    ret = uv_ecdh_get_pubkey(&ctx_1, MBEDTLS_ECP_DP_SECP256R1, pubkey_1, 256, &pubkey_1_size);
    if (ret != 0) {
        printf("uv_ecdh_get_pubkey failed\n");
        goto free_and_exit;
    }
    printf("pubkey_1 size is %zu\n", pubkey_1_size);
    printf("pubkey_1:");
    for (i = 0; i < pubkey_1_size; i++) {
        printf("%02x", pubkey_1[i]);
    }
    printf("\n");

    printf("prikey_2 size is %zu\n", prikey_2_size);
    printf("prikey_2: ");
    for (i = 0; i < prikey_2_size; i++) {
        printf("%02x", prikey_2[i]);
    }
    printf("\n");

    ret = uv_ecdh_gen_keypair_from_binary(&ctx_2, MBEDTLS_ECP_DP_SECP256R1, prikey_2, sizeof(prikey_2));
    if (ret != 0) {
        printf("uv_ecdh_gen_keypair_from_binary failed\n");
        goto free_and_exit;
    }

    ret = uv_ecdh_get_pubkey(&ctx_2, MBEDTLS_ECP_DP_SECP256R1, pubkey_2_read, 256, &pubkey_read_size);
    if (ret != 0) {
        printf("uv_ecdh_get_pubkey failed\n");
        goto free_and_exit;
    }
    printf("pubkey_read_size is %zu\n", pubkey_read_size);
    printf("pubkey_2_read: ");
    for (i = 0; i < pubkey_read_size; i++) {
        printf("%02x", pubkey_2_read[i]);
    }
    printf("\n");

    if (memcmp(pubkey_2, pubkey_2_read, pubkey_read_size) == 0) {
        printf("compare pubkey2 success\n");
    } else {
        printf("compare pubkey2 failed\n");
        ret = -1;
        goto free_and_exit;
    }

    ret = uv_ecdh_compute_sharedkey(&ctx_1, pubkey_2_read, pubkey_read_size, sharedkey_1, &sharedkey_1_len);
    if (ret != 0) {
        printf("uv_ecdh_compute_sharedkey failed\n");
        goto free_and_exit;
    }
    printf("Sharedkey_1 Length: %zu\n", sharedkey_1_len);
    printf("Sharedkey_1: ");
    for (i = 0; i < sharedkey_1_len; i++) {
        printf("%02x", sharedkey_1[i]);
    }
    printf("\n");

    ret = uv_ecdh_compute_sharedkey(&ctx_2, pubkey_1, pubkey_1_size, sharedkey_2, &sharedkey_2_len);
    if (ret != 0) {
        printf("uv_ecdh_compute_sharedkey failed\n");
        goto free_and_exit;
    }
    printf("Sharedkey_2 Length: %zu\n", sharedkey_2_len);
    printf("Sharedkey_2: ");
    for (i = 0; i < sharedkey_2_len; i++) {
        printf("%02x", sharedkey_2[i]);
    }
    printf("\n");

    if (memcmp(sharedkey_1, sharedkey_2, sharedkey_1_len) != 0) {
        printf("Sharedkey_1 and Sharedkey_2 is not equal\n");
        ret = -1;
        goto free_and_exit;
    }

free_and_exit:
    uv_ecdh_free(&ctx_1);
    uv_ecdh_free(&ctx_2);

    return ret;
}

static int test_ecdh_compute_shared_key_2(void)
{
    int ret, i;
    uv_ecp_t ctx_1;
    uv_ecp_t ctx_2;
    const unsigned char prikey_1[] = {
        0x88, 0x19, 0x4f, 0x5f, 0xc7, 0x29, 0x14, 0xc1,
        0x90, 0x84, 0x3a, 0xdb, 0xd6, 0x57, 0x6c, 0x68,
        0x87, 0x79, 0x2d, 0x73, 0xaf, 0x82, 0xd1, 0x84,
        0x4a, 0xba, 0xe5, 0x9c, 0xd2, 0x43, 0xe9, 0xdb
    };
    size_t prikey_1_size = 32;
    const unsigned char pubkey_1[] = {
        0x04, 0x6f, 0x9b, 0xe3, 0x4e, 0x87, 0xb1, 0x1d,
        0xa6, 0x36, 0xd3, 0x2f, 0x18, 0xa4, 0xc4, 0xb1,
        0x60, 0x58, 0xbc, 0x6b, 0xed, 0x7a, 0xda, 0x5b,
        0x58, 0x08, 0x09, 0xd7, 0xc3, 0xb4, 0x48, 0x54,
        0x85, 0x57, 0x59, 0xbb, 0x4a, 0xb3, 0x5a, 0x73,
        0x50, 0x3b, 0x5a, 0x55, 0x1e, 0xb5, 0xd9, 0x15,
        0x96, 0x24, 0xcf, 0x04, 0x51, 0xd7, 0xb8, 0xbf,
        0x9a, 0xa1, 0x60, 0x88, 0xd5, 0x72, 0xf0, 0x1a,
        0x6b
    };
    size_t pubkey_1_size = 65;
    unsigned char pubkey_1_read[256] = { 0 };
    size_t pubkey_1_read_size = 32;
    const unsigned char prikey_2[] = {
        0x52, 0x78, 0x85, 0xee, 0xca, 0xcf, 0xbf, 0x54,
        0x56, 0x52, 0xea, 0xc3, 0xfb, 0xc3, 0x50, 0x8f,
        0x53, 0xec, 0x2a, 0x95, 0xe0, 0xac, 0x2e, 0x7c,
        0x10, 0xf4, 0x5b, 0x75, 0x70, 0xe1, 0xed, 0x76
    };
    size_t prikey_2_size = 32;
    const unsigned char pubkey_2[] = {
        0x04, 0x50, 0x47, 0x61, 0xb1, 0x84, 0xbe, 0x09,
        0x6f, 0xfe, 0x59, 0x2d, 0x48, 0x81, 0x94, 0x9d,
        0xed, 0x6e, 0x66, 0xf7, 0x2a, 0x0a, 0x33, 0xc3,
        0x83, 0x4d, 0x08, 0x0d, 0xfc, 0xcb, 0x6c, 0x2d,
        0xf3, 0xc9, 0xfc, 0xa9, 0xc9, 0xb7, 0xe9, 0xa2,
        0x37, 0x79, 0x4e, 0xbb, 0x52, 0xd1, 0xca, 0x80,
        0xb2, 0xf9, 0x01, 0xfa, 0x52, 0xfd, 0xee, 0x28,
        0x56, 0xd9, 0xe8, 0xe8, 0xb3, 0xef, 0x47, 0xb8,
        0xf9
    };
    size_t pubkey_2_size = 65;
    unsigned char pubkey_2_read[256] = { 0 };
    size_t pubkey_2_read_size = 32;
    unsigned char sharedkey_1[32] = { 0 };
    size_t sharedkey_1_len = 32;
    unsigned char sharedkey_2[32] = { 0 };
    size_t sharedkey_2_len = 32;

    ret = uv_ecdh_init(&ctx_1, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        printf("uv_ecdh_init failed\n");
        return -1;
    }

    ret = uv_ecdh_init(&ctx_2, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        printf("uv_ecdh_init failed\n");
        return -1;
    }

    printf("prikey_1 size is %zu\n", prikey_1_size);
    printf("prikey_1: ");
    for (i = 0; i < prikey_1_size; i++) {
        printf("%02x", prikey_1[i]);
    }
    printf("\n");

    ret = uv_ecdh_gen_keypair_from_binary(&ctx_1, MBEDTLS_ECP_DP_SECP256R1, prikey_1, sizeof(prikey_1));
    if (ret != 0) {
        printf("uv_ecdh_gen_keypair_from_binary failed\n");
        goto free_and_exit;
    }
    ret = uv_ecdh_get_pubkey(&ctx_1, MBEDTLS_ECP_DP_SECP256R1, pubkey_1_read, 256, &pubkey_1_read_size);
    if (ret != 0) {
        printf("uv_ecdh_get_pubkey failed\n");
        goto free_and_exit;
    }
    printf("pubkey_1_read_size is %zu\n", pubkey_1_read_size);
    printf("pubkey_1_read: ");
    for (i = 0; i < pubkey_1_read_size; i++) {
        printf("%02x", pubkey_1_read[i]);
    }
    printf("\n");

    if (memcmp(pubkey_1, pubkey_1_read, pubkey_1_read_size) == 0) {
        printf("compare pubkey1 success\n");
    } else {
        printf("compare pubkey1 failed\n");
        ret = -1;
        goto free_and_exit;
    }

    printf("prikey_2 size is %zu\n", prikey_2_size);
    printf("prikey_2: ");
    for (i = 0; i < prikey_2_size; i++) {
        printf("%02x", prikey_2[i]);
    }
    printf("\n");

    ret = uv_ecdh_gen_keypair_from_binary(&ctx_2, MBEDTLS_ECP_DP_SECP256R1, prikey_2, sizeof(prikey_2));
    if (ret != 0) {
        printf("uv_ecdh_gen_keypair_from_binary failed\n");
        goto free_and_exit;
    }

    ret = uv_ecdh_get_pubkey(&ctx_2, MBEDTLS_ECP_DP_SECP256R1, pubkey_2_read, 256, &pubkey_2_read_size);
    if (ret != 0) {
        printf("uv_ecdh_get_pubkey failed\n");
        goto free_and_exit;
    }
    printf("pubkey_2_read_size is %zu\n", pubkey_2_read_size);
    printf("pubkey_2_read: ");
    for (i = 0; i < pubkey_2_read_size; i++) {
        printf("%02x", pubkey_2_read[i]);
    }
    printf("\n");

    if (memcmp(pubkey_2, pubkey_2_read, pubkey_2_read_size) == 0) {
        printf("compare pubkey2 success\n");
    } else {
        printf("compare pubkey2 failed\n");
        ret = -1;
        goto free_and_exit;
    }

    ret = uv_ecdh_compute_sharedkey(&ctx_1, pubkey_2_read, pubkey_2_read_size, sharedkey_1, &sharedkey_1_len);
    if (ret != 0) {
        printf("uv_ecdh_compute_sharedkey failed\n");
        goto free_and_exit;
    }
    printf("Sharedkey_1 Length: %zu\n", sharedkey_1_len);
    printf("Sharedkey_1: ");
    for (i = 0; i < sharedkey_1_len; i++) {
        printf("%02x", sharedkey_1[i]);
    }
    printf("\n");

    ret = uv_ecdh_compute_sharedkey(&ctx_2, pubkey_1_read, pubkey_1_read_size, sharedkey_2, &sharedkey_2_len);
    if (ret != 0) {
        printf("uv_ecdh_compute_sharedkey failed\n");
        goto free_and_exit;
    }
    printf("Sharedkey_2 Length: %zu\n", sharedkey_2_len);
    printf("Sharedkey_2: ");
    for (i = 0; i < sharedkey_2_len; i++) {
        printf("%02x", sharedkey_2[i]);
    }
    printf("\n");

    if (memcmp(sharedkey_1, sharedkey_2, sharedkey_2_len) != 0) {
        printf("Sharedkey_1 and Sharedkey_2 is not equal\n");
        ret = -1;
        goto free_and_exit;
    }

free_and_exit:
    uv_ecdh_free(&ctx_1);
    uv_ecdh_free(&ctx_2);

    return ret;
}

static int test_ecdh_compute_shared_key_3(void)
{
    int ret, i;
    uv_ecp_t ctx_1;
    uv_ecp_t ctx_2;
    unsigned char prikey_1[256] = { 0 };
    size_t prikey_1_size = 32;
    unsigned char pubkey_1[256] = { 0 };
    size_t pubkey_1_size = 32;
    unsigned char prikey_2[256] = { 0 };
    size_t prikey_2_size = 32;
    unsigned char pubkey_2[256] = { 0 };
    size_t pubkey_2_size = 32;
    unsigned char sharedkey_1[32] = { 0 };
    size_t sharedkey_1_len = 32;
    unsigned char sharedkey_2[32] = { 0 };
    size_t sharedkey_2_len = 32;

    ret = uv_ecdh_init(&ctx_1, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        printf("uv_ecdh_init failed\n");
        return -1;
    }

    ret = uv_ecdh_init(&ctx_2, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        printf("uv_ecdh_init failed\n");
        return -1;
    }

    ret = uv_ecdh_gen_keypair(&ctx_1);
    if (ret != 0) {
        printf("uv_ecdh_gen_keypair failed\n");
        goto free_and_exit;
    }

    ret = uv_ecdh_get_privkey(&ctx_1, prikey_1, prikey_1_size);
    if (ret != 0) {
        printf("uv_ecdh_get_privkey failed\n");
        goto free_and_exit;
    }
    printf("prikey_1 size is %zu\n", prikey_1_size);
    printf("prikey_1: ");
    for (i = 0; i < prikey_1_size; i++) {
        printf("%02x", prikey_1[i]);
    }
    printf("\n");

    ret = uv_ecdh_get_pubkey(&ctx_1, MBEDTLS_ECP_DP_SECP256R1, pubkey_1, 256, &pubkey_1_size);
    if (ret != 0) {
        printf("uv_ecdh_get_pubkey failed\n");
        goto free_and_exit;
    }
    printf("pubkey_1 size is %zu\n", pubkey_1_size);
    printf("pubkey_1: ");
    for (i = 0; i < pubkey_1_size; i++) {
        printf("%02x", pubkey_1[i]);
    }
    printf("\n");

    ret = uv_ecdh_gen_keypair(&ctx_2);
    if (ret != 0) {
        printf("uv_ecdh_gen_keypair failed\n");
        goto free_and_exit;
    }

    ret = uv_ecdh_get_privkey(&ctx_2, prikey_2, prikey_2_size);
    if (ret != 0) {
        printf("uv_ecdh_get_privkey failed\n");
        goto free_and_exit;
    }
    printf("prikey_2_size is %zu\n", prikey_2_size);
    printf("prikey_2: ");
    for (i = 0; i < prikey_2_size; i++) {
        printf("%02x", prikey_2[i]);
    }
    printf("\n");

    ret = uv_ecdh_get_pubkey(&ctx_2, MBEDTLS_ECP_DP_SECP256R1, pubkey_2, 256, &pubkey_2_size);
    if (ret != 0) {
        printf("uv_ecdh_get_pubkey failed\n");
        goto free_and_exit;
    }
    printf("pubkey_2_size is %zu\n", pubkey_2_size);
    printf("pubkey_2: ");
    for (i = 0; i < pubkey_2_size; i++) {
        printf("%02x", pubkey_2[i]);
    }
    printf("\n");

    ret = uv_ecdh_compute_sharedkey(&ctx_1, pubkey_2, pubkey_2_size, sharedkey_1, &sharedkey_1_len);
    if (ret != 0) {
        printf("uv_ecdh_compute_sharedkey failed\n");
        goto free_and_exit;
    }
    printf("Sharedkey_1 Length: %zu\n", sharedkey_1_len);
    printf("Sharedkey_1: ");
    for (i = 0; i < sharedkey_1_len; i++) {
        printf("%02x", sharedkey_1[i]);
    }
    printf("\n");

    ret = uv_ecdh_compute_sharedkey(&ctx_2, pubkey_1, pubkey_1_size, sharedkey_2, &sharedkey_2_len);
    if (ret != 0) {
        printf("uv_ecdh_compute_sharedkey failed\n");
        goto free_and_exit;
    }
    printf("Sharedkey_2 Length: %zu\n", sharedkey_2_len);
    printf("Sharedkey_2: ");
    for (i = 0; i < sharedkey_2_len; i++) {
        printf("%02x", sharedkey_2[i]);
    }
    printf("\n");

    if (memcmp(sharedkey_1, sharedkey_2, sharedkey_1_len) != 0) {
        printf("Sharedkey_1 and Sharedkey_2 is not equal\n");
        ret = -1;
        goto free_and_exit;
    }

free_and_exit:
    uv_ecdh_free(&ctx_1);
    uv_ecdh_free(&ctx_2);

    return ret;
}

int test_ecdh_compute_shared_key_4(void)
{
    int ret, i;
    const char* test_pri_pem = "-----BEGIN EC PRIVATE KEY-----\r\n"
                               "MHcCAQEEIIcex4mqXsQamUKTVf8vXmTAJrQvGjh5mXG8p9+OR4xAoAoGCCqGSM49\r\n"
                               "AwEHoUQDQgAEqJ2HQjPpc6fDwE/vSa6U35USXawkTo98y4U6NsAl+rOGuqMPEFXf\r\n"
                               "P1Srm/Jrzwa/RuppRL5kgyAsGJTUmwZEzQ==\r\n"
                               "-----END EC PRIVATE KEY-----\r\n";
    unsigned char prikey[256] = { 0 };
    size_t prikey_size = 32;
    unsigned char pubkey[256] = { 0 };
    size_t pubkey_size = 65;
    size_t pubkey_out_size = 0;

    ret = uv_ecdh_gen_keypair_from_pem(MBEDTLS_ECP_DP_SECP256R1, (const char*)test_pri_pem, strlen(test_pri_pem), prikey, prikey_size, pubkey, pubkey_size, &pubkey_out_size);
    if (ret != 0 || pubkey_out_size != pubkey_size) {
        printf("uv_ecdh_gen_keypair_from_pem failed\n");
        return -1;
    }

    printf("prikey size is %zu\n", prikey_size);
    printf("prikey: ");
    for (i = 0; i < prikey_size; i++) {
        printf("%02x", prikey[i]);
    }
    printf("\n");

    printf("pubkey size is %zu\n", pubkey_size);
    printf("pubkey: ");
    for (i = 0; i < pubkey_size; i++) {
        printf("%02x", pubkey[i]);
    }
    printf("\n");

    return 0;
}

int main(int argc, char* argv[])
{
    if (argc != 1) {
        usage();
        return -1;
    }

    printf("test start.\n");

    /* test-1 steps:
        1. Alice : genreate keypair random
        2. Bob : genreate keypair manually by input pre-defined prikey
        3. Bob : compare the pubkey with pre-defined pre-defined pubkey
        4. Alice : compute sharedkey by Bob's pubkey
        5. Bob : compute sharedkey by Alice's pubkey
        6. Alice and Bob : compare the sharedkey
    */
    if (test_ecdh_compute_shared_key_1() != 0) {
        printf("test_ecdh_compute_shared_key_1 failed\n");
        return -1;
    }
    printf("test_ecdh_compute_shared_key_1 success \n\n\n");

    /* test-2 steps:
        1. Alice : genreate keypair manually by input pre-defined prikey
        2. Bob : genreate keypair manually by input pre-defined  prikey
        3. Alice : compare the pubkey with pre-defined pubkey
        4. Bob : compare the pubkey with pre-defined pubkey
        5. Alice : compute sharedkey by Bob's pubkey
        6. Bob : compute sharedkey by Alice's pubkey
        7. Alice and Bob : compare the sharedkey
    */
    if (test_ecdh_compute_shared_key_2() != 0) {
        printf("test_ecdh_compute_shared_key_2 failed\n");
        return -1;
    }
    printf("test_ecdh_compute_shared_key_2 success \n\n\n");

    /* test-3 steps:
        1. Alice : genreate keypair random
        2. Bob : genreate keypair random
        3. Alice : compute sharedkey by Bob's pubkey
        4. Bob : compute sharedkey by Alice's pubkey
        5. Alice and Bob : compare the sharedkey
    */
    if (test_ecdh_compute_shared_key_3() != 0) {
        printf("test_ecdh_compute_shared_key_3 failed\n");
        return -1;
    }
    printf("test_ecdh_compute_shared_key_3 success \n\n\n");

    /* test-4 steps:
        1. Alice: generate keypair by input pem format key
    */
    if (test_ecdh_compute_shared_key_4() != 0) {
        printf("test_ecdh_compute_shared_key_4 failed\n");
        return -1;
    }
    printf("test_ecdh_compute_shared_key_4 success \n\n\n");

    printf("test over, all test passed.\n");

    return 0;
}