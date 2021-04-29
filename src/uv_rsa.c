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

#include <alloca.h>
#include <uv_ext.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/platform.h>
#include <mbedtls/pk_internal.h>
#include <mbedtls/base64.h>
#include <string.h>

int uv_rsa_parse_key(uv_rsa_t *ctx, int mode, const unsigned char *key, int keylen) {
  if (!ctx || !key)
    return UV_EINVAL;

  uv_pk_context_t *pctx = &ctx->pk_context;
  int ret;

  mbedtls_pk_init(pctx);
  switch (mode) {
    case MBEDTLS_RSA_PUBLIC:
      ret = mbedtls_pk_parse_public_key(pctx, key, keylen);
      break;
    case MBEDTLS_RSA_PRIVATE:
      ret = mbedtls_pk_parse_key(pctx, key, keylen, NULL, 0);
      break;
    default:
      return UV_EINVAL;
  }

  return ret;
}

int uv_rsa_set_padding(uv_rsa_t *ctx, int padding, int hash_id) {
  if (!ctx)
    return UV_EINVAL;

  uv_pk_context_t *pkctx = &ctx->pk_context;
  uv_rsa_context_t **rsactx = &ctx->rsa_context;

  *rsactx = mbedtls_pk_rsa((*pkctx));
  if (!(*rsactx)) {
    return UV_EFAULT;
  }

  mbedtls_rsa_set_padding(*rsactx, padding, hash_id);

  return 0;
}

int uv_rsa_encrypt(uv_rsa_t *ctx,
                   size_t ilen,
                   const unsigned char *input,
                   unsigned char *output) {
  if (!ctx || !input || !output)
    return UV_EINVAL;

  uv_rsa_context_t *pctx = ctx->rsa_context;
  mbedtls_ctr_drbg_context drbg;
  mbedtls_entropy_context entropy;
  int ret;

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&drbg);
  mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *)"encript",
                               strlen("encript"));

  switch( pctx->padding ) {
    case MBEDTLS_RSA_PKCS_V15:
      ret = mbedtls_rsa_rsaes_pkcs1_v15_encrypt(pctx, mbedtls_ctr_drbg_random,
                                            &drbg, MBEDTLS_RSA_PUBLIC, ilen, input, output);
      break;
    case MBEDTLS_RSA_PKCS_V21:
      ret = mbedtls_rsa_rsaes_oaep_encrypt(pctx, mbedtls_ctr_drbg_random,
                                  &drbg, MBEDTLS_RSA_PUBLIC, NULL, 0, ilen, input, output);
      break;
    default:
      return UV_EINVAL;
  }

  return ret;
}

int uv_rsa_decrypt(uv_rsa_t *ctx,
                   size_t *olen,
                   const unsigned char *input,
                   unsigned char *output,
                   size_t output_max_len) {
  if (!ctx || (!output_max_len && !output) || !input || !olen)
    return UV_EINVAL;

  uv_rsa_context_t *pctx = ctx->rsa_context;
  mbedtls_ctr_drbg_context drbg;
  mbedtls_entropy_context entropy;
  int ret;

  mbedtls_entropy_init(&entropy);
  mbedtls_ctr_drbg_init(&drbg);
  mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &entropy,
                               (const unsigned char *)"decrypt",
                               strlen("decrypt"));
  switch (pctx->padding) {
    case MBEDTLS_RSA_PKCS_V15:
      ret = mbedtls_rsa_rsaes_pkcs1_v15_decrypt(pctx, mbedtls_ctr_drbg_random,
                              &drbg, MBEDTLS_RSA_PRIVATE, olen, input, output,output_max_len);
      break;
    case MBEDTLS_RSA_PKCS_V21:
      ret = mbedtls_rsa_rsaes_oaep_decrypt(pctx, mbedtls_ctr_drbg_random,
                      &drbg, MBEDTLS_RSA_PRIVATE, NULL, 0, olen, input, output,output_max_len);
      break;
    default:
      return UV_EINVAL;
  }

  return ret;
}

int uv_rsa_encrypt_base64(uv_rsa_t *ctx,
                          const unsigned char *input,
                          unsigned char *output,
                          size_t *olen,
                          size_t buffsize) {
  if (!ctx || !input || !output)
    return UV_EINVAL;

  int ret;
  unsigned char *buff = alloca(ctx->rsa_context->len * 2);

  if (!buff) {
    return UV_EFAULT;
  }

  memset(buff, 0, sizeof(buff));
  ret = uv_rsa_encrypt(ctx, strlen((const char *)input), input, buff);
  if (ret != 0) {
    return ret;
  }

  ret = mbedtls_base64_encode(output, buffsize, olen, buff, ctx->rsa_context->len);
  if (ret != 0) {
    return ret;
  }

  return ret;
}

int uv_rsa_decrypt_base64(uv_rsa_t *ctx,
                          const unsigned char *input,
                          size_t inlen,
                          unsigned char *output,
                          size_t *olen,
                          size_t buffsize) {
  if (!ctx || !input || !output)
    return UV_EINVAL;

  int ret;
  size_t len;
  unsigned char *buff = alloca(ctx->rsa_context->len * 2);

  if (!buff) {
    return UV_EFAULT;
  }

  memset(buff, 0, sizeof(buff));
  ret = mbedtls_base64_decode(buff, ctx->rsa_context->len * 2, &len, input, inlen);
  if (ret != 0) {
    return ret;
  }

  ret = uv_rsa_decrypt(ctx, olen, buff, output, buffsize);
  if (ret != 0) {
    return ret;
  }

  return ret;
}

void uv_rsa_free(uv_rsa_t *ctx) {
  if (ctx) {
    mbedtls_rsa_free(ctx->rsa_context);
    mbedtls_pk_free(&ctx->pk_context);
  }
}