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

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pem.h>
#include <mbedtls/pk.h>
#include <uv_ext.h>

int uv_ecdh_init(uv_ecp_t* ctx, int group_id)
{
    if (!ctx) {
        return UV_EINVAL;
    }

    mbedtls_ecp_keypair_init(ctx);

    int ret = mbedtls_ecp_group_load(&ctx->grp, group_id);
    if (ret != 0) {
        uv_ecdh_free(ctx);
    }

    return ret;
}

int uv_ecdh_get_pubkey(uv_ecp_t* ctx, int group_id, void* pubkey, size_t pubkey_len, size_t* out_size)
{
    if (!ctx || !pubkey || !out_size || pubkey_len == 0) {
        return UV_EINVAL;
    }

    int format;

    int ret = mbedtls_ecp_check_pubkey(&ctx->grp, &ctx->Q);
    if (ret != 0) {
        *out_size = 0;
        return ret;
    }

    if (group_id == MBEDTLS_ECP_DP_SECP224R1 || group_id == MBEDTLS_ECP_DP_SECP224K1) {
        format = MBEDTLS_ECP_PF_COMPRESSED;
    } else {
        format = MBEDTLS_ECP_PF_UNCOMPRESSED;
    }

    memset(pubkey, 0, pubkey_len);
    return mbedtls_ecp_point_write_binary(&ctx->grp, &ctx->Q, format, out_size, pubkey, pubkey_len);
}

int uv_ecdh_get_privkey(uv_ecp_t* ctx, void* privkey, size_t privkey_len)
{
    if (!ctx || !privkey || privkey_len == 0) {
        return UV_EINVAL;
    }

    int ret;

    ret = mbedtls_ecp_check_privkey(&ctx->grp, &ctx->d);
    if (ret != 0) {
        return ret;
    }

    memset(privkey, 0, privkey_len);
    return mbedtls_ecp_write_key(ctx, privkey, privkey_len);
}

int uv_ecdh_gen_keypair(uv_ecp_t* ctx)
{
    if (!ctx) {
        return UV_EINVAL;
    }

    int ret;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char* pers = "-ecp";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        goto free_drbg_entropy_and_exit;
    }

    ret = mbedtls_ecp_gen_keypair(&ctx->grp, &ctx->d, &ctx->Q, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        goto free_drbg_entropy_and_exit;
    }

free_drbg_entropy_and_exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

int uv_ecdh_gen_keypair_from_binary(uv_ecp_t* ctx, int group_id, const void* prikey, size_t prikey_size)
{
    if (!ctx || !prikey || prikey_size == 0) {
        return UV_EINVAL;
    }

    int ret;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char* pers = "-ecp";

    ret = mbedtls_ecp_read_key(group_id, ctx, prikey, prikey_size);
    if (ret != 0) {
        return ret;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        goto free_drbg_entropy_and_exit;
    }

    ret = mbedtls_ecp_mul(&ctx->grp, &ctx->Q, &ctx->d, &ctx->grp.G, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        goto free_drbg_entropy_and_exit;
    }

free_drbg_entropy_and_exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

int uv_ecdh_gen_keypair_from_pem(int group_id,
    const void* prikey_pem, size_t prikey_pem_len,
    void* prikey, size_t prikey_size,
    void* pubkey, size_t pubkey_size, size_t* pubkey_out_size)
{
    if (!prikey_pem || prikey_pem_len == 0 || !prikey || prikey_size == 0 || !pubkey || pubkey_size == 0 || !pubkey_out_size) {
        return UV_EINVAL;
    }

    int ret;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char* pers = "-ecp-pem";

    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        goto free_and_exit;
    }

    ret = mbedtls_pk_parse_key(&pk, prikey_pem, prikey_pem_len + 1, NULL, 0, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        goto free_and_exit;
    }

    mbedtls_ecp_keypair* ctx = mbedtls_pk_ec(pk);
    if (ctx == NULL) {
        ret = UV_EINVAL;
        goto free_and_exit;
    }

    ret = uv_ecdh_get_privkey(ctx, prikey, prikey_size);
    if (ret != 0) {
        goto free_and_exit;
    }

    ret = mbedtls_ecp_mul(&ctx->grp, &ctx->Q, &ctx->d, &ctx->grp.G, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        goto free_and_exit;
    }

    ret = uv_ecdh_get_pubkey(ctx, group_id, pubkey, pubkey_size, pubkey_out_size);
    if (ret != 0) {
        goto free_and_exit;
    }

free_and_exit:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

int uv_ecdh_compute_sharedkey(uv_ecp_t* ctx, const void* pubkey, size_t pubkey_len, void* sharedkey, size_t* sharedkey_len)
{
    if (!ctx || !pubkey || pubkey_len == 0 || !sharedkey || !sharedkey_len || *sharedkey_len == 0) {
        return UV_EINVAL;
    }

    int ret;
    mbedtls_ecdh_context ecdh_ctx;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char* pers = "-ecp";

    mbedtls_ecdh_init(&ecdh_ctx);
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        goto free_ecdh_and_drbg_entropy_then_exit;
    }

    ret = mbedtls_ecdh_get_params(&ecdh_ctx, ctx, MBEDTLS_ECDH_OURS);
    if (ret != 0) {
        goto free_ecdh_and_drbg_entropy_then_exit;
    }

#if defined(MBEDTLS_ECP_RESTARTABLE)
    ret = mbedtls_ecp_point_read_binary(&ecdh_ctx.grp, &ecdh_ctx.Qp, pubkey, pubkey_len);
#else
    ret = mbedtls_ecp_point_read_binary(&ecdh_ctx.ctx.mbed_ecdh.grp, &ecdh_ctx.ctx.mbed_ecdh.Qp, pubkey, pubkey_len);
#endif
    if (ret != 0) {
        goto free_ecdh_and_drbg_entropy_then_exit;
    }

    memset(sharedkey, 0, *sharedkey_len);
    ret = mbedtls_ecdh_calc_secret(&ecdh_ctx, sharedkey_len, sharedkey, *sharedkey_len, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        goto free_ecdh_and_drbg_entropy_then_exit;
    }

free_ecdh_and_drbg_entropy_then_exit:
    mbedtls_ecdh_free(&ecdh_ctx);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    return ret;
}

int uv_ecdh_write_pem_from_binary(const void* keyData, size_t keyData_len, void* pem, size_t pem_size, size_t* out_len)
{
    if (!keyData || keyData_len == 0 || !pem || pem_size == 0 || !out_len) {
        return UV_EINVAL;
    }

    return mbedtls_pem_write_buffer("-----BEGIN EC PRIVATE KEY-----\n", "-----END EC PRIVATE KEY-----\n", keyData, keyData_len, pem, pem_size, out_len);
}

void uv_ecdh_free(uv_ecp_t* ctx)
{
    if (!ctx) {
        return;
    }

    mbedtls_ecp_keypair_free(ctx);
}
