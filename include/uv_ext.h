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

#ifndef __SYSTEM_LIBUV_EXT_INCLUDE_UV_EXT_H
#define __SYSTEM_LIBUV_EXT_INCLUDE_UV_EXT_H

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <uv.h>
#include <mbedtls/cipher.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * devinfo
 ****************************************************************************/

#define UV_EXT_DEVINFO_BRAND            1
#define UV_EXT_DEVINFO_MANUFACTURER     2
#define UV_EXT_DEVINFO_MODEL            3
#define UV_EXT_DEVINFO_PRODUCT          4
#define UV_EXT_DEVINFO_OSTYPE           5
#define UV_EXT_DEVINFO_OSVERSIONNAME    6
#define UV_EXT_DEVINFO_OSVERSIONCODE    7
#define UV_EXT_DEVINFO_LANGUAGE         8
#define UV_EXT_DEVINFO_REGION           9
#define UV_EXT_DEVINFO_SCREENWIDTH      10
#define UV_EXT_DEVINFO_SCREENHEIGHT     11
#define UV_EXT_DEVINFO_MAX              12
/****************************************************************************
 * Name: uv_get_devinfo
 *
 * Description:
 *   get device information.
 *
 * Input Parameters:
 *   devinfo  - handle.
 *   id       - device information id.
 *              1: brand 2: manufacturer 3: model 4: product 5: os_type
 *              6: os_version_name 7: os_version_code 8: language
 *              9: region
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_get_devinfo(char *devinfo, int size, int id);

/****************************************************************************
 * Name: uv_get_devinfo
 *
 * Description:
 *   get screen resolution.
 *
 * Input Parameters:
 *   devinfo  - handle.
 *   id       - device information id.
 *              10: screenwidth 11: screenheight
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_get_resolution(int *wh, int id);

/****************************************************************************
 * Name: uv_get_devinfo
 *
 * Description:
 *   get screen resolution.
 *
 * Input Parameters:
 *   vsersioncode   - versioncode.
 *   id             - device information id.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_get_versioncode(int *vsersioncode, int id);

/****************************************************************************
 * locale
 ****************************************************************************/

typedef struct uv_locale_s uv_locale_t;

struct uv_locale_s {
  const char *language;
  const char *country_region;
};

int uv_getlocale(uv_locale_t *locale);

/****************************************************************************
 * AES encryption and decryption
 ****************************************************************************/

#ifdef CONFIG_LIB_MBEDTLS

typedef mbedtls_cipher_context_t uv_aes_context_t;

typedef struct uv_aes_s {
  uv_handle_t handle;
  uv_aes_context_t aes_context;
}uv_aes_t;

/****************************************************************************
 * Name: uv_aes_init
 *
 * Description:
 *   AES contex initialization, set the AES type and padding mode.
 *
 ****************************************************************************/

int uv_aes_init(uv_aes_t *ctx, int aestype, int mode);

/****************************************************************************
 * Name: uv_aes_set_iv
 *
 * Description:
 *   sets the initialization vector (IV) or nonce.
 *
 ****************************************************************************/

int uv_aes_set_iv(uv_aes_t *ctx,
                  const unsigned char *iv,
                  int ivoffset,
                  int iv_len);

/****************************************************************************
 * Name: uv_aes_set_iv_base64
 *
 * Description:
 *   sets the initialization vector (IV) or nonce. The IV is a base64
 * encoded string
 *
 ****************************************************************************/

int uv_aes_set_iv_base64(uv_aes_t *ctx,
                         const unsigned char *iv,
                         int ivoffset,
                         int iv_len);

/****************************************************************************
 * Name: uv_aes_set_key
 *
 * Description:
 *   sets the key to use with the given context.
 *
 ****************************************************************************/

int uv_aes_set_key(uv_aes_t *ctx,
                   int optype,
                   const unsigned char *key,
                   int key_bitlen);

/****************************************************************************
 * Name: uv_aes_set_key_base64
 *
 * Description:
 *   sets the key to use with the given context. The key is a base64
 * encoded string
 *
 ****************************************************************************/

int uv_aes_set_key_base64(uv_aes_t *ctx,
                          int optype,
                          const unsigned char *key,
                          int key_bitlen);

/****************************************************************************
 * Name: uv_aes_encrypt
 *
 * Description:
 *   aes encryption.
 *
 ****************************************************************************/

int uv_aes_encrypt(uv_aes_t *ctx,
                   const unsigned char *input,
                   size_t ilen,
                   unsigned char *output,
                   size_t *olen);

/****************************************************************************
 * Name: uv_aes_encrypt
 *
 * Description:
 *   aes decryption.
 *
 ****************************************************************************/

int uv_aes_decrypt(uv_aes_t *ctx,
                   const unsigned char *input,
                   size_t ilen,
                   unsigned char *output,
                   size_t *olen);

/****************************************************************************
 * Name: uv_aes_encrypt_base64
 *
 * Description:
 *   AES encryption. The text content to be encrypted should be a piece of
 * plain text. base64 encoding output.
 *
 ****************************************************************************/

int uv_aes_encrypt_base64(uv_aes_t *ctx,
                          const unsigned char *input,
                          size_t ilen,
                          unsigned char *output,
                          int outsize,
                          size_t *olen);

/****************************************************************************
 * Name: uv_aes_decrypt_base64
 *
 * Description:
 *   AES decryption. The text content to be decrypted should be base64 encoded.
 *
 ****************************************************************************/

int uv_aes_decrypt_base64(uv_aes_t *ctx,
                          const unsigned char *input,
                          size_t ilen,
                          unsigned char *output,
                          size_t *olen);

/****************************************************************************
 * Name: uv_aes_free
 *
 * Description:
 *   Frees and clears the cipher-specific context of ctx. Freeing ctx itself
 * remains the responsibility of the caller.
 *
 ****************************************************************************/

void uv_aes_free(uv_aes_t *ctx);

#endif

/****************************************************************************
 * RSA encryption and decryption
 ****************************************************************************/

#ifdef CONFIG_LIB_MBEDTLS

typedef mbedtls_pk_context uv_pk_context_t;
typedef mbedtls_rsa_context uv_rsa_context_t;

typedef struct uv_rsa_s {
  uv_handle_t handle;
  uv_pk_context_t pk_context;
  uv_rsa_context_t *rsa_context;
}uv_rsa_t;

/****************************************************************************
 * Name: uv_rsa_parse_key
 *
 * Description:
 *   Parse a public/private key in PEM or DER format.
 *
 ****************************************************************************/

int uv_rsa_parse_key(uv_rsa_t *ctx,
                     int mode,
                     const unsigned char *key,
                     int keylen);

/****************************************************************************
 * Name: uv_rsa_set_padding
 *
 * Description:
 *   This function sets padding for RSA context.
 *
 ****************************************************************************/

int uv_rsa_set_padding(uv_rsa_t *ctx, int padding, int hash_id);

/****************************************************************************
 * Name: uv_rsa_encrypt
 *
 * Description:
 *    This function performs a PKCS#1 v2.1 OAEP encryption operation
 * (RSAES-OAEP-ENCRYPT) or a PKCS#1 v1.5 encryption operation
 * (RSAES-PKCS1-v1_5-ENCRYPT).
 *
 ****************************************************************************/

int uv_rsa_encrypt(uv_rsa_t *ctx,
                   size_t ilen,
                   const unsigned char *input,
                   unsigned char *output);

/****************************************************************************
 * Name: uv_rsa_decrypt
 *
 * Description:
 *    This function performs a PKCS#1 v2.1 OAEP decryption operation
 * (RSAES-OAEP-ENCRYPT) or a PKCS#1 v1.5 decryption operation
 * (RSAES-PKCS1-v1_5-ENCRYPT).
 *
 ****************************************************************************/

int uv_rsa_decrypt(uv_rsa_t *ctx,
                   size_t *olen,
                   const unsigned char *input,
                   unsigned char *output,
                   size_t output_max_len);

/****************************************************************************
 * Name: uv_rsa_encrypt_base64
 *
 * Description:
 *    Performs an RSA encryption operation and outputs it in Base64 encode.
 *
 ****************************************************************************/

int uv_rsa_encrypt_base64(uv_rsa_t *ctx,
                          const unsigned char *input,
                          unsigned char *output,
                          size_t *olen,
                          size_t buffsize);

/****************************************************************************
 * Name: uv_rsa_decrypt_base64
 *
 * Description:
 *    Perform an RSA decryption operation.The text content to be decrypted
 * should be base64 encoded
 *
 ****************************************************************************/

int uv_rsa_decrypt_base64(uv_rsa_t *ctx,
                          const unsigned char *input,
                          size_t inlen,
                          unsigned char *output,
                          size_t *olen,
                          size_t buffsize);

/****************************************************************************
 * Name: uv_rsa_free
 *
 * Description:
 *    This function frees the components of an RSA key.
 *
 ****************************************************************************/

void uv_rsa_free(uv_rsa_t *ctx);

#endif

/****************************************************************************
 * topic
 ****************************************************************************/

#ifdef CONFIG_UORB

typedef struct uv_topic_s uv_topic_t;
typedef void (*uv_topic_cb)(uv_topic_t *topic, int status,
                            void *data, size_t datalen);

struct uv_topic_s {
  uv_poll_t handle;
  uv_topic_cb cb;
  size_t datalen;
  void *data;
};

/****************************************************************************
 * Name: uv_topic_subscribe
 *
 * Description:
 *   topic subscription.
 *
 ****************************************************************************/

int uv_topic_subscribe(uv_loop_t *loop, uv_topic_t *topic,
                       const char *name, uv_topic_cb cb);

/****************************************************************************
 * Name: uv_topic_unsubscribe
 *
 * Description:
 *   topic unsubscribe.
 *
 ****************************************************************************/

int uv_topic_unsubscribe(uv_topic_t *topic);

/****************************************************************************
 * Name: uv_topic_set_frequency
 *
 * Description:
 *   set topic sampling rate. The maximum sampling value of all subscribers
 *   of this topic is valid.
 *
 ****************************************************************************/

int uv_topic_set_frequency(uv_topic_t *topic, unsigned int frequency);

#endif

/****************************************************************************
 * property
 ****************************************************************************/

#ifdef CONFIG_KVDB

typedef void (*uv_property_cb)(int status, const char *key, char *value, void *arg);

/****************************************************************************
 * Name: uv_property_get
 *
 * Description:
 *   Retrieve Key-Values from database.
 *
 ****************************************************************************/

int uv_property_get(uv_loop_t *loop, const char *key, char *value,
                    const char *default_value, uv_property_cb cb, void *arg);

/****************************************************************************
 * Name: uv_property_set
 *
 * Description:
 *   Store Key-Values to database.
 *
 ****************************************************************************/

int uv_property_set(uv_loop_t *loop, const char *key, const char *value,
                    uv_property_cb cb, void *arg);

/****************************************************************************
 * Name: uv_property_delete
 *
 * Description:
 *   Delete a KV pair by key.
 *
 ****************************************************************************/

int uv_property_delete(uv_loop_t *loop, const char *key, uv_property_cb cb,
                       void *arg);

/****************************************************************************
 * Name: property_commit
 *
 * Description:
 *   Actively commit all property changes
 *
 ****************************************************************************/

int uv_property_commit(uv_loop_t *loop, uv_property_cb cb, void *arg);

#endif

#ifdef __cplusplus
}
#endif

#endif /* __SYSTEM_LIBUV_EXT_INCLUDE_UV_EXT_H */
