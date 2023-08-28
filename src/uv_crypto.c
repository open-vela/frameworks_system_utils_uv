#include "uv_ext.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mbedtls/base64.h"
#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/pk.h"

#define UV_EXT_OK 0
#define UV_EXT_ERROR_INTERNAL -1
#define UV_EXT_ERROR_INVALID -2

#define crypto_debug(format, ...) \
    uv_ext_log(LOG_DEBUG, crypto, format, ##__VA_ARGS__)

#define crypto_info(format, ...) \
    uv_ext_log(LOG_INFO, crypto, format, ##__VA_ARGS__)

#define crypto_error(format, ...) \
    uv_ext_log(LOG_ERR, crypto, format, ##__VA_ARGS__)

int uv_rsa(uv_buf_t key, uv_buf_t text, uv_buf_t* output, int mode)
{
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char* pers = "-pkcs";
    int ret;
    int len;

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        crypto_error("mbedtls_ctr_drbg_seed failed -0x%04x\n", ret);
        goto exit;
    }

    ret = mbedtls_pk_parse_key(&pk, (const unsigned char*)key.base, key.len + 1, NULL, 0,
        mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)key.base, key.len + 1);
    }

    if (ret != 0) {
        crypto_error("Could not parse key, returned -0x%04x\n", (unsigned int)-ret);
        goto exit;
    }

    len = mbedtls_pk_get_bitlen(&pk);
    output->base = malloc(len);
    if (mode == UV_EXT_DECRYPT) {
        ret = mbedtls_pk_decrypt(&pk, (const unsigned char*)text.base, text.len,
            (unsigned char*)output->base, &output->len, len,
            mbedtls_ctr_drbg_random, &ctr_drbg);
    } else {
        ret = mbedtls_pk_encrypt(&pk, (const unsigned char*)text.base, text.len,
            (unsigned char*)output->base, &output->len, len,
            mbedtls_ctr_drbg_random, &ctr_drbg);
    }

    if (ret != 0) {
        crypto_error("rsa encrypt returned -0x%04x\n", (unsigned int)-ret);
        free(output->base);
        output->base = NULL;
        goto exit;
    }

exit:
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

int uv_md(const char* type, uv_buf_t input, uv_buf_t* output)
{
    const mbedtls_md_info_t* info;

    output->len = 0;
    info = mbedtls_md_info_from_string(type);
    if (info == NULL) {
        return UV_EINVAL;
    }

    output->len = mbedtls_md_get_size(info);
    output->base = malloc(output->len + 1);
    if (output->base == NULL) {
        return UV_ENOMEM;
    }

    if (mbedtls_md(info, (const unsigned char*)input.base, input.len, (unsigned char*)output->base) != 0) {
        free(output->base);
        output->base = NULL;
        return UV_EINVAL;
    }
    return 0;
}

int uv_md_hmac(const char* type, uv_buf_t input, uv_buf_t* output, uv_buf_t* key)
{
    const mbedtls_md_info_t* info;

    output->len = 0;
    info = mbedtls_md_info_from_string(type);
    if (info == NULL) {
        return UV_EINVAL;
    }

    output->len = mbedtls_md_get_size(info);
    output->base = malloc(output->len + 1);
    if (output->base == NULL) {
        return UV_ENOMEM;
    }

    if (mbedtls_md_hmac(info, (const unsigned char*)key->base, key->len,
            (const unsigned char*)input.base, input.len,
            (unsigned char*)output->base)
        != 0) {
        free(output->base);
        output->base = NULL;
        return UV_EINVAL;
    }

    return 0;
}

int uv_md_file(const char* type, const char* path, int batchsize, uv_buf_t* output)
{
    int ret = UV_EXT_OK;
    FILE* f;
    size_t n;
    mbedtls_md_context_t ctx;
    const mbedtls_md_info_t* info;
    unsigned char* batchbuf;

    output->len = 0;
    info = mbedtls_md_info_from_string(type);
    if (info == NULL) {
        return UV_EINVAL;
    }

    batchbuf = malloc(batchsize);
    if (batchbuf == NULL) {
        return UV_ENOMEM;
    }

    if ((f = fopen(path, "rb")) == NULL) {
        ret = UV_EIO;
        goto errout_with_batch;
    }

    mbedtls_md_init(&ctx);

    if ((ret = mbedtls_md_setup(&ctx, info, 0)) != 0) {
        ret = UV_EINVAL;
        goto errout_with_file;
    }

    if ((ret = mbedtls_md_starts(&ctx)) != 0) {
        ret = UV_EINVAL;
        goto errout_with_ctx;
    }

    while ((n = fread(batchbuf, 1, batchsize, f)) > 0) {
        if ((ret = mbedtls_md_update(&ctx, batchbuf, n)) != 0) {
            ret = UV_EINVAL;
            goto errout_with_ctx;
        }
    }

    output->len = mbedtls_md_get_size(info);
    output->base = malloc(output->len + 1);
    if (output->base == NULL) {
        ret = UV_ENOMEM;
        goto errout_with_ctx;
    }

    if (ferror(f) != 0) {
        ret = UV_EIO;
    } else if (mbedtls_md_finish(&ctx, (unsigned char*)output->base) != 0) {
        ret = UV_EINVAL;
    }

    if (ret != 0) {
        free(output->base);
        output->base = NULL;
    }

errout_with_ctx:
    mbedtls_md_free(&ctx);
errout_with_file:
    fclose(f);
errout_with_batch:
    free(batchbuf);
    return ret;
}

int uv_base64_encode(uv_buf_t input, uv_buf_t* output)
{
    int res;
    ssize_t len = (input.len / 3 + 1) * 4 + 1;
    output->base = malloc(len);
    res = mbedtls_base64_encode((unsigned char*)output->base, len, &output->len, (const unsigned char*)input.base, input.len);
    return res;
}

int uv_base64_decode(uv_buf_t input, uv_buf_t* output)
{
    ssize_t len = (input.len / 4) * 3;
    output->base = malloc(len);
    return mbedtls_base64_decode((unsigned char*)output->base, len, &output->len, (const unsigned char*)input.base, input.len);
}

int uv_sign(const char* md_type, uv_buf_t key, uv_buf_t text, uv_buf_t* output, int type)
{
    const mbedtls_md_info_t* info;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    uv_buf_t md = { 0 };
    const char* pers = "-pkcs";
    int ret;

    info = mbedtls_md_info_from_string(md_type);
    if (info == NULL) {
        return UV_EINVAL;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        crypto_error("mbedtls_ctr_drbg_seed failed -0x%04x\n", ret);
        goto exit;
    }

    ret = mbedtls_pk_parse_key(&pk, (const unsigned char*)key.base, key.len + 1, NULL, 0,
        mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)key.base, key.len + 1);
    }

    if (ret != 0) {
        crypto_error("Could not parse key, returned -0x%04x\n", (unsigned int)-ret);
        goto exit;
    }

    if (type == UV_EXT_TYPE_BUFFER) {
        ret = uv_md(md_type, text, &md);
    } else {
        ret = uv_md_file(md_type, text.base, 1024, &md);
    }

    if (ret != 0) {
        crypto_error("Digest calculation failed\n");
        goto exit;
    }

    crypto_info("Sign mdtype=%s, type=%d\n", md_type, mbedtls_md_get_type(info));

    output->base = malloc(MBEDTLS_PK_SIGNATURE_MAX_SIZE);
    ret = mbedtls_pk_sign(&pk, mbedtls_md_get_type(info), (const unsigned char*)md.base, 0,
        (unsigned char*)output->base, MBEDTLS_PK_SIGNATURE_MAX_SIZE, &output->len, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        crypto_error("mbedtls_pk_sign returned -0x%04x\n", (unsigned int)-ret);
        goto exit;
    }

exit:
    free(md.base);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return ret;
}

int uv_verify(const char* md_type, uv_buf_t key, uv_buf_t text, uv_buf_t sign, int type)
{
    const mbedtls_md_info_t* info;
    mbedtls_pk_context pk;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char* pers = "-pkcs";
    uv_buf_t md = { 0 };
    int ret;

    info = mbedtls_md_info_from_string(md_type);
    if (info == NULL) {
        return UV_EINVAL;
    }

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);

    ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
        (const unsigned char*)pers, strlen(pers));
    if (ret != 0) {
        crypto_error("mbedtls_ctr_drbg_seed failed -0x%04x\n", ret);
        goto exit;
    }

    ret = mbedtls_pk_parse_key(&pk, (const unsigned char*)key.base, key.len + 1, NULL, 0,
        mbedtls_ctr_drbg_random, &ctr_drbg);
    if (ret != 0) {
        ret = mbedtls_pk_parse_public_key(&pk, (const unsigned char*)key.base, key.len + 1);
    }

    if (ret != 0) {
        crypto_error("Could not parse key, returned -0x%04x\n", (unsigned int)-ret);
        goto exit;
    }

    if (type == UV_EXT_TYPE_BUFFER) {
        ret = uv_md(md_type, text, &md);
    } else {
        ret = uv_md_file(md_type, text.base, 1024, &md);
    }

    if (ret != 0) {
        crypto_error("Digest calculation failed\n");
        goto exit;
    }

    crypto_info("Verify mdtype=%s, type=%d\n", md_type, mbedtls_md_get_type(info));

    ret = mbedtls_pk_verify(&pk, mbedtls_md_get_type(info), (const unsigned char*)md.base, md.len,
        (const unsigned char*)sign.base, sign.len);

    if (ret != 0) {
        crypto_error("rsa verify failed returned -0x%04x\n", (unsigned int)-ret);
        goto exit;
    }

exit:
    free(md.base);
    mbedtls_pk_free(&pk);
    return ret;
}

void uv_hexify(uv_buf_t input, uv_buf_t* output)
{
    char* obuf = malloc(input.len * 2 + 1);
    const unsigned char* ibuf = (const unsigned char*)input.base;
    int len = input.len;
    output->base = obuf;
    output->len = input.len * 2;
    output->base[output->len] = '\0';

    unsigned char l, h;

    while (len != 0) {
        h = *ibuf / 16;
        l = *ibuf % 16;

        if (h < 10)
            *obuf++ = '0' + h;
        else
            *obuf++ = 'a' + h - 10;

        if (l < 10)
            *obuf++ = '0' + l;
        else
            *obuf++ = 'a' + l - 10;

        ++ibuf;
        len--;
    }
}
