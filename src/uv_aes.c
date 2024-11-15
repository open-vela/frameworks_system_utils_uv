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
#include <mbedtls/base64.h>
#include <mbedtls/cipher.h>
#include <mbedtls/platform.h>
#include <string.h>

#include <uv_ext.h>

static void add_pkcs_padding(unsigned char* ptr, size_t len, size_t data_len)
{
    size_t padding_len = len - data_len;

    memset(ptr + data_len, padding_len, padding_len);
}

static int get_pkcs_padding(unsigned char *input,
                            size_t input_len,
                            size_t *data_len)
{
    size_t i, pad_idx;
    unsigned char padding_len, bad = 0;

    if (NULL == data_len || NULL == input) {
        return MBEDTLS_ERR_CIPHER_BAD_INPUT_DATA;
    }

    padding_len = input[input_len - 1];
    *data_len = input_len - padding_len;

    /* Avoid logical || since it results in a branch */

    bad |= input_len < padding_len;

    bad |= 0 == padding_len;

    /*
     * The number of bytes checked must be independent of padding_len,
     * so input_len is chosen, which is usually 8 or 16 (one block)
     */

    pad_idx = input_len - padding_len;

    for (i = 0; input_len > i; i++) {
        bad |= (i >= pad_idx) * (input[i] ^ padding_len);
    }

    return MBEDTLS_ERR_CIPHER_INVALID_PADDING * (bad != 0);
}

int uv_aes_init(uv_aes_t* ctx, int aestype, int mode)
{
    if (!ctx)
        return UV_EINVAL;

    const mbedtls_cipher_info_t* info;
    uv_aes_context_t* pctx = &ctx->aes_context;

    mbedtls_cipher_init(pctx);
    info = mbedtls_cipher_info_from_type(aestype);
    if (!info) {
        return UV_EFAULT;
    }

    if (mbedtls_cipher_setup(pctx, info)) {
        return UV_EFAULT;
    }

    if (MBEDTLS_MODE_ECB == pctx->cipher_info->mode) {
        if (MBEDTLS_PADDING_PKCS7 == mode) {
            pctx->add_padding = add_pkcs_padding;
            pctx->get_padding = get_pkcs_padding;
        }
    } else {
        mbedtls_cipher_set_padding_mode(pctx, mode);
    }

    return 0;
}

int uv_aes_set_iv(uv_aes_t* ctx,
    const unsigned char* iv,
    int ivoffset,
    int iv_len)
{
    if (!ctx || !(iv_len == 0 || iv != NULL))
        return UV_EINVAL;

    const unsigned char* pivoffset = iv + ivoffset;
    uv_aes_context_t* pctx = &ctx->aes_context;

    return mbedtls_cipher_set_iv(pctx, pivoffset, iv_len);
}

int uv_aes_set_iv_base64(uv_aes_t* ctx,
    const unsigned char* iv,
    int ivoffset,
    int iv_len)
{
    if (!ctx || !iv)
        return UV_EINVAL;

    unsigned char ivbuff[64] = { 0 };
    size_t ivlen;
    int ret;

    ret = mbedtls_base64_decode(ivbuff, sizeof(ivbuff), &ivlen, iv, strlen((const char*)iv));
    if (ret != 0) {
        return ret;
    }

    return uv_aes_set_iv(ctx, ivbuff, ivoffset, iv_len);
}

int uv_aes_set_key(uv_aes_t* ctx,
    int optype,
    const unsigned char* key,
    int key_bitlen)
{
    if (!ctx || !key)
        return UV_EINVAL;

    uv_aes_context_t* pctx = &ctx->aes_context;

    return mbedtls_cipher_setkey(pctx, key, key_bitlen, optype);
}

int uv_aes_set_key_base64(uv_aes_t* ctx,
    int optype,
    const unsigned char* key,
    int key_bitlen)
{
    if (!ctx || !key)
        return UV_EINVAL;

    unsigned char keybuff[64] = { 0 };
    size_t keylen;
    int ret;

    ret = mbedtls_base64_decode(keybuff, sizeof(keybuff), &keylen, key, strlen((const char*)key));
    if (ret != 0) {
        return ret;
    }

    return uv_aes_set_key(ctx, optype, keybuff, key_bitlen);
}

int uv_aes_encrypt(uv_aes_t* ctx,
    const unsigned char* input,
    size_t ilen,
    unsigned char* output,
    size_t* olen)
{
    if (!ctx || !input || !ilen || !output || !olen) {
        return UV_EINVAL;
    }

    uv_aes_context_t* pctx = &ctx->aes_context;
    int ret;
    size_t len, outlen = 0, i, block_size, blocks, remaining;
    unsigned char* block;

    block_size = mbedtls_cipher_get_block_size(pctx);
    if (block_size == 0) {
        return MBEDTLS_ERR_CIPHER_INVALID_CONTEXT;
    }

    blocks = ilen / block_size;

    for (i = 0; i < blocks; i++) {
        ret = mbedtls_cipher_update(pctx, input, block_size, output, &len);
        if (ret != 0) {
            return ret;
        }

        input += len;
        output += len;
        outlen += len;
    }

    /* process the remaining data */

    remaining = ilen - outlen;
    if (remaining != 0 && pctx->add_padding != NULL) {
        if (MBEDTLS_MODE_ECB == pctx->cipher_info->mode) {
            block = alloca(block_size);
            memcpy(block, input, remaining);
            pctx->add_padding(block, block_size, remaining);
            ret = mbedtls_cipher_update(pctx, block, block_size, output, &len);
        } else if (MBEDTLS_MODE_CBC == pctx->cipher_info->mode) {
            ret = mbedtls_cipher_update(pctx, input, remaining, output, &len);
        }

        if (ret != 0) {
            return ret;
        }

        output += len;
        outlen += len;
    }

    /* If encrypt one block length (16 bytes) exactly, need to add a fully filled block */

    if (MBEDTLS_MODE_ECB == pctx->cipher_info->mode && ilen == block_size &&
        pctx->add_padding != NULL) {
        block = (unsigned char*)alloca(block_size);
        memset(block, 0, block_size);
        pctx->add_padding(block, block_size, 0);
        ret = mbedtls_cipher_update(pctx, block, block_size, output, &len);
        if (ret != 0) {
            return ret;
        }

        output += len;
        outlen += len;
    }

    ret = mbedtls_cipher_finish(pctx, output, &len);
    if (ret != 0) {
        return ret;
    }

    outlen += len;
    *olen = outlen;

    return ret;
}

int uv_aes_decrypt(uv_aes_t* ctx,
    const unsigned char* input,
    size_t ilen,
    unsigned char* output,
    size_t* olen)
{
    if (!ctx || !input || !ilen || !output || !olen) {
        return UV_EINVAL;
    }

    uv_aes_context_t* pctx = &ctx->aes_context;
    int ret, outlen = 0;
    size_t len;

    if (MBEDTLS_MODE_ECB == pctx->cipher_info->mode) {
        size_t i, blocks, block_size;

        block_size = mbedtls_cipher_get_block_size(pctx);
        if (block_size == 0) {
            return MBEDTLS_ERR_CIPHER_INVALID_CONTEXT;
        }

        blocks = ilen / block_size;

        for (i = 0; i < blocks - 1; i++) {
            ret = mbedtls_cipher_update(pctx, input, block_size, output, &len);
            if (ret != 0) {
                return ret;
            }

            input += len;
            output += len;
            outlen += len;
        }

        ret = mbedtls_cipher_update(pctx, input, block_size, output, &len);
        if (ret != 0) {
            return ret;
        }

        pctx->get_padding(output, block_size, &len);
        output += len;
        outlen += len;
    } else {
        ret = mbedtls_cipher_update(pctx, input, ilen, output, &len);
        if (ret != 0) {
            return ret;
        }

        outlen += len;
    }

    ret = mbedtls_cipher_finish(pctx, output + (char)outlen, &len);
    if (ret != 0) {
        return ret;
    }
    outlen += len;
    *olen = outlen;

    return ret;
}

int uv_aes_encrypt_base64(uv_aes_t* ctx,
    const unsigned char* input,
    size_t ilen,
    unsigned char* output,
    int outsize,
    size_t* olen)
{
    int ret;
    size_t outlen = 0;
    unsigned char* buff = alloca(outsize);

    if (!buff) {
        return UV_EFAULT;
    }

    ret = uv_aes_encrypt(ctx, input, ilen, buff, &outlen);
    if (ret != 0)
        return ret;

    return mbedtls_base64_encode(output, outsize, olen, buff, outlen);
}

int uv_aes_decrypt_base64(uv_aes_t* ctx,
    const unsigned char* input,
    size_t ilen,
    unsigned char* output,
    size_t* olen)
{
    int ret;
    size_t len;
    unsigned char* buff = alloca(ilen);

    if (!buff) {
        return UV_EFAULT;
    }

    ret = mbedtls_base64_decode(buff, ilen, &len, input, ilen);
    if (ret != 0) {
        return ret;
    }

    return uv_aes_decrypt(ctx, buff, len, output, olen);
}

void uv_aes_free(uv_aes_t* ctx)
{
    mbedtls_cipher_free(&ctx->aes_context);
}