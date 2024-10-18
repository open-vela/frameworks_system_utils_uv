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

#include <stdint.h>
#include <nuttx/nuttx.h>
#include <uv.h>

#include <uv_async_queue.h>

#ifdef CONFIG_CRYPTO_MBEDTLS
#include <mbedtls/cipher.h>
#include <mbedtls/pk.h>
#include <mbedtls/rsa.h>
#endif

#ifdef CONFIG_MEDIA
#include <media_api.h>
#endif

#ifdef CONFIG_UORB
#include <system/state.h>
#endif

#ifdef CONFIG_KVDB
#include <kvdb.h>
#endif

#include <mqueue.h>
#include <syslog.h>

#define UV_EXT_OK 0
#define UV_EXT_ERROR_INTERNAL -1
#define UV_EXT_ERROR_INVALID -2

#define uv_ext_log(level, module, format, ...) \
    syslog(level, "[" #module ":%d]" format "\n", __LINE__, ##__VA_ARGS__)

#define uv_log_debug(module, format, ...) \
    uv_ext_log(LOG_DEBUG, module, format, ##__VA_ARGS__)

#define uv_log_info(module, format, ...) \
    uv_ext_log(LOG_INFO, module, format, ##__VA_ARGS__)

#define uv_log_error(module, format, ...) \
    uv_ext_log(LOG_ERR, module, format, ##__VA_ARGS__)

#ifdef __cplusplus
extern "C" {
#endif

/****************************************************************************
 * devinfo
 ****************************************************************************/

#define UV_EXT_DEVINFO_SCREENWIDTH 1
#define UV_EXT_DEVINFO_SCREENHEIGHT (UV_EXT_DEVINFO_SCREENWIDTH + 1)
#define UV_EXT_DEVINFO_SCREENSHAPE (UV_EXT_DEVINFO_SCREENHEIGHT + 1)
#define UV_EXT_DEVINFO_OSVERSIONCODE (UV_EXT_DEVINFO_SCREENSHAPE + 1)
#define UV_EXT_DEVINFO_BRAND (UV_EXT_DEVINFO_OSVERSIONCODE + 1)
#define UV_EXT_DEVINFO_MANUFACTURER (UV_EXT_DEVINFO_BRAND + 1)
#define UV_EXT_DEVINFO_MODEL (UV_EXT_DEVINFO_MANUFACTURER + 1)
#define UV_EXT_DEVINFO_PRODUCT (UV_EXT_DEVINFO_MODEL + 1)
#define UV_EXT_DEVINFO_OSTYPE (UV_EXT_DEVINFO_PRODUCT + 1)
#define UV_EXT_DEVINFO_OSVERSIONNAME (UV_EXT_DEVINFO_OSTYPE + 1)
#define UV_EXT_DEVINFO_LANGUAGE (UV_EXT_DEVINFO_OSVERSIONNAME + 1)
#define UV_EXT_DEVINFO_REGION (UV_EXT_DEVINFO_LANGUAGE + 1)
#define UV_EXT_DEVINFO_DID (UV_EXT_DEVINFO_REGION + 1)
#define UV_EXT_DEVINFO_SERIAL (UV_EXT_DEVINFO_DID + 1)
#define UV_EXT_DEVINFO_MAX (UV_EXT_DEVINFO_SERIAL + 1)

#define UV_EXT_DEVINFO_MAXLEN (32 + 1)

typedef struct uv_devinfo_s uv_devinfo_t;

struct uv_devinfo_s {
    char brand[UV_EXT_DEVINFO_MAXLEN];
    char manufacturer[UV_EXT_DEVINFO_MAXLEN];
    char model[UV_EXT_DEVINFO_MAXLEN];
    char product[UV_EXT_DEVINFO_MAXLEN];
    char ostype[UV_EXT_DEVINFO_MAXLEN];
    char osversionname[UV_EXT_DEVINFO_MAXLEN];
    char language[UV_EXT_DEVINFO_MAXLEN];
    char region[UV_EXT_DEVINFO_MAXLEN];
    char did[UV_EXT_DEVINFO_MAXLEN];
    char screenshape[UV_EXT_DEVINFO_MAXLEN];
    char devicetype[UV_EXT_DEVINFO_MAXLEN];
    int osversioncode;
    int screenwidth;
    int screenheight;
    float screendensity;
#ifdef CONFIG_QUICKAPP_TEST_FRAMEWORK
    uint8_t bpp;
#endif
};

/****************************************************************************
 * Name: uv_devinfobuff
 *
 * Description:
 *   Get the device information passed by string variable.
 *
 * Input Parameters:
 *   devinfo  - data handle.
 *   size     - buff size
 *   id       - device information ID.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_devinfobuff(char* buff, int size, int item);

/****************************************************************************
 * Name: uv_getdevinfonumber
 *
 * Description:
 *   Get the device information passed by integer variable.
 *
 * Input Parameters:
 *   num  - data handle.
 *   item - device information ID.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_getdevinfonumber(int* num, int item);

/****************************************************************************
 * Name: uv_getdeviceinfo
 *
 * Description:
 *   Get all device information.
 *
 * Input Parameters:
 *   info   - data handle
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_getdeviceinfo(uv_devinfo_t* info);

/****************************************************************************
 * locale
 ****************************************************************************/

#define UV_EXT_LOCALE_LANG_KEY "persist.locale"
#define UV_EXT_LOCALE_MAX_SIZE 10

typedef struct uv_locale_s uv_locale_t;

struct uv_locale_s {
    char language[UV_EXT_LOCALE_MAX_SIZE];
    char country_region[UV_EXT_LOCALE_MAX_SIZE];
};

int uv_getlocale(uv_locale_t* locale);

/****************************************************************************
 * AES encryption and decryption
 ****************************************************************************/

#ifdef CONFIG_CRYPTO_MBEDTLS

typedef mbedtls_cipher_context_t uv_aes_context_t;

typedef struct uv_aes_s {
    uv_handle_t handle;
    uv_aes_context_t aes_context;
} uv_aes_t;

/****************************************************************************
 * Name: uv_aes_init
 *
 * Description:
 *   AES contex initialization, set the AES type and padding mode.
 *
 ****************************************************************************/

int uv_aes_init(uv_aes_t* ctx, int aestype, int mode);

/****************************************************************************
 * Name: uv_aes_set_iv
 *
 * Description:
 *   sets the initialization vector (IV) or nonce.
 *
 ****************************************************************************/

int uv_aes_set_iv(uv_aes_t* ctx,
    const unsigned char* iv,
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

int uv_aes_set_iv_base64(uv_aes_t* ctx,
    const unsigned char* iv,
    int ivoffset,
    int iv_len);

/****************************************************************************
 * Name: uv_aes_set_key
 *
 * Description:
 *   sets the key to use with the given context.
 *
 ****************************************************************************/

int uv_aes_set_key(uv_aes_t* ctx,
    int optype,
    const unsigned char* key,
    int key_bitlen);

/****************************************************************************
 * Name: uv_aes_set_key_base64
 *
 * Description:
 *   sets the key to use with the given context. The key is a base64
 * encoded string
 *
 ****************************************************************************/

int uv_aes_set_key_base64(uv_aes_t* ctx,
    int optype,
    const unsigned char* key,
    int key_bitlen);

/****************************************************************************
 * Name: uv_aes_encrypt
 *
 * Description:
 *   aes encryption.
 *
 ****************************************************************************/

int uv_aes_encrypt(uv_aes_t* ctx,
    const unsigned char* input,
    size_t ilen,
    unsigned char* output,
    size_t* olen);

/****************************************************************************
 * Name: uv_aes_encrypt
 *
 * Description:
 *   aes decryption.
 *
 ****************************************************************************/

int uv_aes_decrypt(uv_aes_t* ctx,
    const unsigned char* input,
    size_t ilen,
    unsigned char* output,
    size_t* olen);

/****************************************************************************
 * Name: uv_aes_encrypt_base64
 *
 * Description:
 *   AES encryption. The text content to be encrypted should be a piece of
 * plain text. base64 encoding output.
 *
 ****************************************************************************/

int uv_aes_encrypt_base64(uv_aes_t* ctx,
    const unsigned char* input,
    size_t ilen,
    unsigned char* output,
    int outsize,
    size_t* olen);

/****************************************************************************
 * Name: uv_aes_decrypt_base64
 *
 * Description:
 *   AES decryption. The text content to be decrypted should be base64 encoded.
 *
 ****************************************************************************/

int uv_aes_decrypt_base64(uv_aes_t* ctx,
    const unsigned char* input,
    size_t ilen,
    unsigned char* output,
    size_t* olen);

/****************************************************************************
 * Name: uv_aes_free
 *
 * Description:
 *   Frees and clears the cipher-specific context of ctx. Freeing ctx itself
 * remains the responsibility of the caller.
 *
 ****************************************************************************/

void uv_aes_free(uv_aes_t* ctx);

#endif

/****************************************************************************
 * cipher
 ****************************************************************************/

#ifdef CONFIG_CRYPTO_MBEDTLS

#define UV_EXT_TYPE_BUFFER 0
#define UV_EXT_TYPE_FILE 1

#define UV_EXT_DECRYPT 0
#define UV_EXT_ENCRYPT 1

/****************************************************************************
 * Name: uv_base64_encode
 ****************************************************************************/

int uv_base64_encode(uv_buf_t input, uv_buf_t* output);

/****************************************************************************
 * Name: uv_base64_decode
 ****************************************************************************/

int uv_base64_decode(uv_buf_t input, uv_buf_t* output);

/****************************************************************************
 * Name: uv_sign
 ****************************************************************************/

int uv_sign(const char* md_type, uv_buf_t key, uv_buf_t text, uv_buf_t* output, int type);

/****************************************************************************
 * Name: uv_verify
 ****************************************************************************/

int uv_verify(const char* md_type, uv_buf_t key, uv_buf_t text, uv_buf_t md, int type);

/****************************************************************************
 * Name: uv_md
 ****************************************************************************/

int uv_md(const char* type, uv_buf_t input, uv_buf_t* output);

/****************************************************************************
 * Name: uv_md_file
 ****************************************************************************/

int uv_md_file(const char* type, const char* path, int batchsize, uv_buf_t* output);

/****************************************************************************
 * Name: uv_md_hmac
 ****************************************************************************/

int uv_md_hmac(const char* type, uv_buf_t input, uv_buf_t* output, uv_buf_t* key);

/****************************************************************************
 * Name: uv_rsa
 ****************************************************************************/

int uv_rsa(uv_buf_t key, uv_buf_t text, uv_buf_t* output, int mode);

/****************************************************************************
 * Name: uv_rsa
 ****************************************************************************/

void uv_hexify(uv_buf_t input, uv_buf_t* output);

#endif

/****************************************************************************
 * topic
 ****************************************************************************/

#ifdef CONFIG_UORB

typedef struct uv_topic_s uv_topic_t;
typedef void (*uv_topic_cb)(uv_topic_t* topic, int status,
    void* data, size_t datalen);

struct uv_topic_s {
    uv_poll_t handle;
    uv_topic_cb cb;
    size_t datalen;
    uintptr_t flags;
    int fd;
    orb_id_t meta;
    void* meta_data;
};

/****************************************************************************
 * Name: uv_topic_publish
 *
 * Description:
 *   topic publish.
 *
 ****************************************************************************/

int uv_topic_publish(orb_id_t meta, void* data);

/****************************************************************************
 * Name: uv_topic_subscribe_multi
 *
 * Description:
 *   topic subscription with instance.
 *
 ****************************************************************************/

int uv_topic_subscribe_multi(uv_loop_t* loop, uv_topic_t* topic,
    orb_id_t meta, int instance, uv_topic_cb cb);

/****************************************************************************
 * Name: uv_topic_subscribe
 *
 * Description:
 *   topic subscription.
 *
 ****************************************************************************/

int uv_topic_subscribe(uv_loop_t* loop, uv_topic_t* topic,
    orb_id_t meta, uv_topic_cb cb);

/****************************************************************************
 * Name: uv_topic_unsubscribe
 *
 * Description:
 *   topic unsubscribe.
 *
 ****************************************************************************/

int uv_topic_unsubscribe(uv_topic_t* topic);

/****************************************************************************
 * Name: uv_topic_set_frequency
 *
 * Description:
 *   set topic sampling rate. The maximum sampling value of all subscribers
 *   of this topic is valid.
 *
 ****************************************************************************/

int uv_topic_set_frequency(uv_topic_t* topic, unsigned int frequency);

/****************************************************************************
 * Name: uv_topic_get_frequency
 *
 * Description:
 *   get topic sampling rate.
 *
 ****************************************************************************/

int uv_topic_get_frequency(uv_topic_t* topic, unsigned int* frequency);

/****************************************************************************
 * Name: uv_topic_set_interval
 *
 * Description:
 *   Set the minimum interval between which updates seen for a subscription.
 *
 ****************************************************************************/

int uv_topic_set_interval(uv_topic_t* topic, unsigned int interval);

/****************************************************************************
 * Name: uv_topic_get_interval
 *
 * Description:
 *   Get the minimum interval between which updates seen for a subscription.
 *
 ****************************************************************************/

int uv_topic_get_interval(uv_topic_t* topic, unsigned int* interval);

/****************************************************************************
 * Name: uv_topic_close
 *
 * Description:
 *   Call uv_close internally, used for simple case when `topic` is static.
 *   If `topic` is dynamically alloced, use uv_close directly and free memory
 *   in `close_cb`.
 ****************************************************************************/

int uv_topic_close(uv_topic_t* topic);

#endif

/****************************************************************************
 * property
 ****************************************************************************/

#ifdef CONFIG_KVDB

typedef void (*uv_property_cb)(int status, const char* key, char* value, void* arg);

/****************************************************************************
 * Name: uv_property_get
 *
 * Description:
 *   Retrieve Key-Values from database.
 *
 ****************************************************************************/

int uv_property_get(uv_loop_t* loop, const char* key, char* value,
    const char* default_value, uv_property_cb cb, void* arg);

/****************************************************************************
 * Name: uv_property_set
 *
 * Description:
 *   Store Key-Values to database.
 *
 ****************************************************************************/

int uv_property_set(uv_loop_t* loop, const char* key, const char* value,
    uv_property_cb cb, void* arg);

/****************************************************************************
 * Name: uv_property_clear
 *
 * Description:
 *   Delete all the KV pair in database.
 *
 ****************************************************************************/

int uv_property_clear(uv_loop_t* loop, uv_property_cb cb, void* arg);

/****************************************************************************
 * Name: uv_property_delete
 *
 * Description:
 *   Delete a KV pair by key.
 *
 ****************************************************************************/

int uv_property_delete(uv_loop_t* loop, const char* key, uv_property_cb cb,
    void* arg);

/****************************************************************************
 * Name: property_commit
 *
 * Description:
 *   Actively commit all property changes
 *
 ****************************************************************************/

int uv_property_commit(uv_loop_t* loop, uv_property_cb cb, void* arg);

#endif

/****************************************************************************
 * brightness
 ****************************************************************************/

/****************************************************************************
 * Type: uv_brightness_cb_t
 *
 * Description:
 *   brightness setting completion callback
 *
 * Input Parameters:
 *   status      - brightness setting completion callback
 *   val         - brightness setting return result
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

typedef void (*uv_brightness_cb_t)(int status, int val, void* data);

typedef void* uv_brightness_handle_t;

typedef struct uv_sysbrightness_s {
    int (*init)(uv_loop_t* loop, uv_brightness_handle_t* handle);
    int (*close)(uv_brightness_handle_t handle);
    int (*setval)(uv_brightness_handle_t handle, int val, uv_brightness_cb_t cb, void* data);
    int (*getval)(uv_brightness_handle_t handle, uv_brightness_cb_t cb, void* data);
    int (*setmode)(uv_brightness_handle_t handle, int val, uv_brightness_cb_t cb, void* data);
    int (*getmode)(uv_brightness_handle_t handle, uv_brightness_cb_t cb, void* data);
    int (*keepscreenon)(uv_brightness_handle_t handle, bool val, uv_brightness_cb_t cb, void* data);
    int (*recovery)(uv_brightness_handle_t handle, uv_brightness_cb_t cb, void* data);
    int (*turnon)(uv_brightness_handle_t handle, uv_brightness_cb_t cb, void* data);
} uv_sysbrightness_ops_t;

/****************************************************************************
 * Name: uv_sysbrightness_register
 *
 * Description:
 *   Register system brightness interface.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_sysbrightness_register(uv_sysbrightness_ops_t* brightness);

/****************************************************************************
 * Name: uv_brightness_recovery
 *
 * Description:
 *   Recovery the system brightness value.
 *
 * Input Parameters:
 *   cb      - brightness setting completion callback
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_recovery(uv_brightness_handle_t handle,
    uv_brightness_cb_t cb, void* data);

/****************************************************************************
 * Name: uv_brightness_setval
 *
 * Description:
 *   Set screen brightness.The system brightness value does not change.
 *
 * Input Parameters:
 *   handle  - brightness handle. There can only be one per application.
 *   val     - brightness value. 0 - CONFIG_LCD_MAXPOWER.
 *   cb      - brightness setting completion callback
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_setval(uv_brightness_handle_t handle, int val,
    uv_brightness_cb_t cb, void* data);

/****************************************************************************
 * Name: uv_brightness_getval
 *
 * Description:
 *   Gets the screen brightness. Does not change the system brightness value
 * Input Parameters:
 *   handle  - brightness handle. There can only be one per application.
 *   cb      - brightness setting completion callback
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_getval(uv_brightness_handle_t handle,
    uv_brightness_cb_t cb, void* data);

/****************************************************************************
 * Name: uv_brightness_setmode
 *
 * Description:
 *   Setting Brightness Mode.
 *
 * Input Parameters:
 *   handle  - brightness handle. There can only be one per application.
 *   mode    - brightness mode. 0: Manual 1: Automatic
 *   cb      - brightness setting completion callback
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_setmode(uv_brightness_handle_t handle, int mode,
    uv_brightness_cb_t cb, void* data);

/****************************************************************************
 * Name: uv_brightness_getmode
 *
 * Description:
 *   Get Brightness Mode.
 *
 * Input Parameters:
 *   handle  - brightness handle. There can only be one per application.
 *   cb      - brightness setting completion callback
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_getmode(uv_brightness_handle_t handle,
    uv_brightness_cb_t cb, void* data);

/****************************************************************************
 * Name: uv_brightness_turnon
 *
 * Description:
 *   turn on the screen
 *
 * Input Parameters:
 *   handle  - brightness handle. There can only be one per application.
 *   cb      - brightness setting completion callback
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_turnon(uv_brightness_handle_t handle,
    uv_brightness_cb_t cb, void* data);

/****************************************************************************
 * Name: uv_brightness_setkeepon
 *
 * Description:
 *   Set whether to keep on light.
 *   Note: Currently there is only constant light.
 *
 * Input Parameters:
 *   handle  - brightness handle. There can only be one per application.
 *   keep    - Keep the screen always bright. 0: false 1: true
 *   cb      - brightness setting completion callback
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_setkeepon(uv_brightness_handle_t handle, bool keep,
    uv_brightness_cb_t cb, void* data);

/****************************************************************************
 * Name: uv_brightness_init
 *
 * Description:
 *   Brightness initialization.
 *   Note: Each application calls the initialization function only once.
 *
 * Input Parameters:
 *   loop    - event loop.
 *   handle  - brightness handle. There can only be one per application.
 *   cb      - brightness setting completion callback
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_init(uv_loop_t* loop, uv_brightness_handle_t* handle);

/****************************************************************************
 * Name: uv_brightness_close
 *
 * Description:
 *   Brightness close.
 *   Note: Each application is called when it finally closes.
 *
 * Input Parameters:
 *   handle  - brightness handle. There can only be one per application.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_close(uv_brightness_handle_t handle);

#if defined(CONFIG_LIB_CURL) || defined(MOCK_LIBUV_FEATURE)

struct uv_response_s {
    long httpcode;
    char* headers;
    char* body;
    size_t size;
    void* userp;
};

enum uv_request_type_e {
    UV_REQUEST,
    UV_DOWNLOAD,
    UV_DOWNLOAD_PROGRESS,
    UV_UPLOAD,
    UV_UPLOAD_TASK
};

enum uv_request_state_e {
    UV_REQUEST_DONE,
    UV_REQUEST_ERROR
};

typedef struct uv_request_session_s uv_request_session_t;
typedef struct uv_request_s uv_request_t;
typedef struct uv_response_s uv_response_t;

typedef void (*uv_request_cb)(int state, uv_response_t* response);

struct data_block_s {
    uint8_t* data;
    ssize_t size;
};

/****************************************************************************
 * Name: uv_request_init
 *
 * Description:
 *   Initialize the request global environment
 *
 ****************************************************************************/

int uv_request_init(uv_loop_t* loop, uv_request_session_t** handle);

/****************************************************************************
 * Name: uv_request_close
 *
 * Description:
 *   Release memory
 *
 ****************************************************************************/

int uv_request_close(uv_request_session_t* handle);

/****************************************************************************
 * Name: uv_request_create
 *
 * Description:
 *   Add url request
 * Note:
 *   The request pointer can be reused, you need to call uv_request_delete after use .
 *
 ****************************************************************************/

int uv_request_create(uv_request_t** request);

/****************************************************************************
 * Name: uv_request_delete
 *
 * Description:
 *   Release uv_request_t n memory
 *
 ****************************************************************************/

int uv_request_delete(uv_request_t* request);

/****************************************************************************
 * Name: uv_request_set_url
 *
 * Description:
 *   set url
 *
 ****************************************************************************/

int uv_request_set_url(uv_request_t* request, const char* url);

/****************************************************************************
 *
 * Name: uv_request_get_url
 ****************************************************************************/

const char* uv_request_get_url(uv_request_t* request);

typedef struct uv_request_header_s {
    int currentIndex;
    char** data;
} uv_request_header_t;

/****************************************************************************
 *
 * Name: uv_request_get_header_list
 ****************************************************************************/

uv_request_header_t uv_request_get_header_list(uv_request_t* request);

/****************************************************************************
 * Name: uv_request_append_header
 *
 * Description:
 *   append http request header
 *
 ****************************************************************************/

int uv_request_append_header(uv_request_t* request, const char* header);

/****************************************************************************
 * Name: uv_request_escape
 *
 * Description:
 *    URL encodes the given string
 *
 ****************************************************************************/

char* uv_request_escape(uv_request_t* request, const void* data, ssize_t size);

/****************************************************************************
 * Name: uv_request_append_header
 *
 * Description:
 *   Set post data
 *
 ****************************************************************************/

int uv_request_set_data(uv_request_t* request, const void* data, ssize_t size);

/****************************************************************************
 * Name: uv_request_set_userp
 *
 * Description:
 *   Set user data point
 *
 ****************************************************************************/

int uv_request_set_userp(uv_request_t* request, void* userp);

/****************************************************************************
 * Name: uv_request_get_userp
 *
 * Description:
 *   Get user data point
 *
 ****************************************************************************/

void* uv_request_get_userp(uv_request_t* request);

/****************************************************************************
 * Name: uv_request_get_header
 *
 * Description:
 *   Include header in the returned data
 *
 ****************************************************************************/
int uv_request_get_header(uv_request_t* request);

/****************************************************************************
 * Name: uv_request_set_method
 *
 * Description:
 *   set fetch methodb
 *
 ****************************************************************************/

int uv_request_set_method(uv_request_t* request, const char* method);

/****************************************************************************
 * Name: uv_request_set_atrribute
 *
 * Description:
 *   set request atrribute
 *
 ****************************************************************************/

int uv_request_set_atrribute(uv_request_t* request, int type, void* data);

/****************************************************************************
 * Name: uv_request
 *
 * Description:
 *   Process request
 *
 ****************************************************************************/

int uv_request_commit(uv_request_session_t* handle, uv_request_t* request, uv_request_cb cb);

/****************************************************************************
 * Name: uv_request_set_verbose
 *
 * Description:
 *   ask libcurl to show us the verbose output
 *
 ****************************************************************************/

int uv_request_set_verbose(uv_request_t* request);

/****************************************************************************
 * Name: uv_request_set_formdata_file
 *
 * Description:
 *   upload file in formdata format
 *
 ****************************************************************************/

int uv_request_set_formdata_file(uv_request_t* request, const char* name,
    const char* filename, const char* filepath);

/****************************************************************************
 * Name: uv_request_set_formdata_buf
 *
 * Description:
 *   upload buffer in formdata format
 *
 ****************************************************************************/

int uv_request_set_formdata_buf(uv_request_t* request, const char* name,
    const char* filename, const char* buffer,
    int len);

/****************************************************************************
 * Name: uv_request_set_timeout
 *
 * Description:
 *   add settimeout function
 *
 ****************************************************************************/

int uv_request_set_timeout(uv_request_t* request, long timeout);

typedef struct uv_ncm_s uv_ncm_t;
typedef void* uv_ncm_handle_t;
typedef void (*uv_ncm_cb_t)(int, const char*, void*);

typedef enum {
    UV_NCM_RES_ERROR,
    UV_NCM_RES_LOCAL_PATH,
    UV_NCM_RES_DOWNLOAD_START,
    UV_NCM_RES_CACHE_HIT
} uv_ncm_res_t;

typedef struct uv_ncm_cfg_s {
    const char** res_path;
    const char* path;
    uv_ncm_cb_t cb;
    void* userp;
} uv_ncm_cfg_t;

/****************************************************************************
 * Name: uv_ncm_init
 *
 * Description:
 *    Network cache management initialization
 *
 * Input Parameters:
 *   loop     - the loop that data transfer uses.
 *   cache_path   - file cache path.
 *
 * Returned Value:
 *   ncm structure pointer.  NULL is fail
 ****************************************************************************/

uv_ncm_t* uv_ncm_init(uv_loop_t* loop, const char* cache_path);

/****************************************************************************
 * Name: uv_ncm_close
 *
 * Description:
 *    Network cache management deinit
 *
 * Input Parameters:
 *   ncm     - ncm structure pointer.
 *
 * Returned Value:
 *   None
 ****************************************************************************/

int uv_ncm_close(uv_ncm_t* ncm);

/****************************************************************************
 * Name: uv_ncm_get_resource
 *
 * Description:
 *    Get resources from the network or cache
 *
 * Input Parameters:
 *   ncm      - ncm structure pointer.
 *   cfg      - network cache configure, include the following attributes
 *     path     - file path or url, The URL must start with HTTP
 *     fallback - user data point , If it is a path or exists in the cache,
 *                the real path is returned directly .otherwise, fallback is returned
 *     cb       - Callback function executed when the file download is complete，
 *                If it is NULL, use blocking mode to download
 *     userp    - user data point
 *   handle   -  resource handle
 * Returned Value:
 *   real path or fallback
 ****************************************************************************/

uv_ncm_res_t uv_ncm_get_resource(uv_ncm_t* ncm, const uv_ncm_cfg_t* cfg, uv_ncm_handle_t* handle);

/****************************************************************************
 * Name: uv_ncm_get_cache
 *
 * Description:
 *    Query whether cache exists
 *
 * Input Parameters:
 *   ncm      - ncm structure pointer.
 *   path     - file path  url, The URL must start with HTTP
 * Returned Value:
 *   real path or fallback
 ****************************************************************************/

const char* uv_ncm_get_cache(uv_ncm_t* ncm, const char* path);

/****************************************************************************
 * Name: uv_ncm_cfg_init
 *
 * Description:
 *   Initialize network cache configure structure
 *
 * Input Parameters:
 *   cfg      - network or cache configure, include the following attributes
 * Returned Value:
 *   None
 ****************************************************************************/

void uv_ncm_cfg_init(uv_ncm_cfg_t* cfg);

/****************************************************************************
 * Name: uv_ncm_cancel
 *
 * Description:
 *    Cancel cache download callback
 *
 * Input Parameters:
 *   handle     -  resource handle
 *
 * Returned Value:
 *   None
 ****************************************************************************/

void uv_ncm_cancel(uv_ncm_handle_t handle);

#endif

#ifdef CONFIG_UV_MIWEAR

typedef uint8_t miwear_message_type_t;

#define MIWEAR_MESSAGE_NEED_REPLY_MASK 0x80

#define MIWEAR_MESSAGE_TYPE_CLIENT_ID 0
#define MIWEAR_MESSAGE_TYPE_RESPONSE 1
#define MIWEAR_MESSAGE_TYPE_STATUS 2
#define MIWEAR_MESSAGE_TYPE_DATA (3 | MIWEAR_MESSAGE_NEED_REPLY_MASK)
/**
 * Send a custom type message, receiver could identify message through this type.
 * Ored the mask MIWEAR_MESSAGE_NEED_REPLY_MASK if this message needs response
 * to confirm it's received.
 */
#define MIWEAR_MESSAGE_TYPE_CUSTOM 10

#define MIWEAR_STATUS_CLIENT_ID_SENT 1 /* Client sent out ID to server. */
#define MIWEAR_STATUS_CONNECT_FAILED 2 /* Failed to connect server */
#define MIWEAR_STATUS_CONNECTION_CLOSED 3 /* Connection closed */
#define MIWEAR_STATUS_CLIENT_ONLINE 4 /* A new client connected to server. */
#define MIWEAR_STATUS_PHONE_CONNECTED 5 /* Phone app connected */
#define MIWEAR_STATUS_PHONE_DISCONNECTED 6 /* Phone app disconnected */
#define MIWEAR_STATUS_PHONE_UNINSTALLED 7 /* Phone app uninstalled */

typedef struct message_status_data_s {
    int status; /* Miwear status value. */
    void* parameter; /* Parameter for some status. */
} uv_miwear_status_t;

typedef struct message_header_s {
    miwear_message_type_t type;
    uint32_t len;
    uint32_t id;
    int32_t uservalue;
} uv_miwear_header_t;

typedef struct uv_miwear_msg_s {
    uv_miwear_header_t header;
    void* data;
} uv_miwear_message_t;

typedef struct uv_miwear_s uv_miwear_t;

typedef void (*uv_miwear_sent_cb)(uv_miwear_t* miwear, int status,
    uv_miwear_message_t* msg, void* cb_para);
typedef void (*uv_miwear_recv_cb)(uv_miwear_t* miwear, int status,
    uv_miwear_message_t* msg, const char* client);

struct uv_miwear_s {
    union {
        struct server* server;
        struct client* client;
    };
    uv_miwear_recv_cb cb; /* Callback will be made when received data. */
    bool is_server; /* To mark this instance is for a server or client. */
    void* reader; /* a message reader to collect packet from pipe stream */
    void* data; /* User data. */
};

/****************************************************************************
 * Name: uv_miwear_connect
 *
 * Description:
 *   Connect to miwear to send and receive data to/from phone.
 *   Connect must be made before sending data to miwear.
 *
 * Input Parameters:
 *   loop     - the loop that data transfer uses.
 *   miwear   - the handler to miwear. Each connection uses one handle.
 *   pkg_name - the quickapp package name. Used by miwear to identify which
 *              quickapp is sending/receiving data.
 *   cb       - the callback function. This callback will be called when
 *              received data from miwear. The data originally comes from
 *              3rd-party app on phone.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_miwear_connect(uv_loop_t* loop, uv_miwear_t* miwear,
    const char* pkg_name, uv_miwear_recv_cb cb);

/****************************************************************************
 * Name: uv_miwear_send
 *
 * Description:
 *   Send data to phone.
 *   Note: there could be various of reasons failing to deliver data.
 *
 * Input Parameters:
 *   miwear   - the handler to miwear. Each connection uses one handle.
 *   data     - the data to be sent. Memory should be kept until data sent.
 *   len      - data length in bytes.
 *   cb       - the callback function. When data sent or failed, this callback
 *              will be made.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_miwear_send(uv_miwear_t* miwear, const char* to, uv_miwear_message_t* message,
    uv_miwear_sent_cb cb, void* cb_para);

/****************************************************************************
 * Name: uv_miwear_close
 *
 * Description:
 *   Close the miwear handler.
 *   Note: any ongoing transfer will be properly terminated, callback will be
 *         made with error code.
 *
 * Input Parameters:
 *   miwear   - the handler to miwear. Each connection uses one handle.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/
int uv_miwear_close(uv_miwear_t* miwear);

/****************************************************************************
 * Name: uv_miwear_start_client
 *
 * Description:
 *   Start miwear client.
 *
 * Input Parameters:
 *
 *   loop     - the loop used to handle events.
 *   miwear   - the miwear instance, which is initialized when returned.
 *   name     - the client name, used to identify between clients by server.
 *   path     - the server path.
 *   cb       - the callback when client received data or connection status
 *              changed.
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_miwear_start_client(uv_loop_t* loop, uv_miwear_t* miwear,
    const char* name, const char* path,
    uv_miwear_recv_cb cb);

#ifdef CONFIG_NET_RPMSG
/****************************************************************************
 * Name: uv_miwear_start_rpmsg_client
 *
 * Description:
 *   Start miwear client to connect server on another CPU using rpmsg.
 *
 * Input Parameters:
 *
 *   loop     - the loop used to handle events.
 *   miwear   - the miwear instance, which is initialized when returned.
 *   name     - the client name, used to identify between clients by server.
 *   path     - the server path.
 *   cpu_name - the remote CPU name where server runs on.
 *   cb       - the callback when client received data or connection status
 *              changed.
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_miwear_start_rpmsg_client(uv_loop_t* loop, uv_miwear_t* miwear,
    const char* client_name,
    const char* server_path,
    const char* cpu_name,
    uv_miwear_recv_cb cb);
#endif

/****************************************************************************
 * Name: uv_miwear_start_server
 *
 * Description:
 *   Start miwear server.
 *
 * Input Parameters:
 *
 *   loop     - the loop used to handle events.
 *   miwear   - the miwear instance, which is initialized when returned.
 *   path     - the server path.
 *   cb       - the callback when server received data or connection status
 *              changed.
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_miwear_start_server(uv_loop_t* loop, uv_miwear_t* miwear,
    const char* path, uv_miwear_recv_cb cb);

/****************************************************************************
 * Name: uv_miwear_iter_client
 *
 * Description:
 *   Go through every client connected to server.
 *
 * Input Parameters:
 *
 *   miwear   - the miwear instance, which is initialized when returned.
 *   cb       - the callback when every client found.
 *   cb_para  - the callback parameter passed to cb.
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_miwear_iter_client(uv_miwear_t* miwear, void (*cb)(const char*, void*),
    void* cb_para);
#endif

/****************************************************************************
 * audio
 ****************************************************************************/

#ifdef CONFIG_MEDIA

/*********************** Asynchronous interface *****************************/

#define UV_AUDIO_EVENT_ERROR 0x80
#define UV_AUDIO_EVENT_OPEN 0x81
#define UV_AUDIO_EVENT_PREPARE 0x82
#define UV_AUDIO_EVENT_START 0x83
#define UV_AUDIO_EVENT_PAUSE 0x84
#define UV_AUDIO_EVENT_STOP 0x85
#define UV_AUDIO_EVENT_GET_VOLUME 0x86
#define UV_AUDIO_EVENT_GET_POSITION 0x87
#define UV_AUDIO_EVENT_GET_DURATION 0x88
#define UV_AUDIO_EVENT_PLAY_STATE 0x89
#define UV_AUDIO_EVENT_COMPLETE 0x8A
#define UV_AUDIO_EVENT_SEEK 0x8B
#define UV_AUDIO_EVENT_ALLSTATE 0x8C
#define UV_AUDIO_EVENT_VOLUMECHANGE 0x8D
#define UV_AUDIO_EVENT_CLOSE 0xFF

typedef struct uv_audio_mqmessage_s {
    uint16_t cmd;
    uint32_t status;
    void* data;
} uv_audio_mqmessage_t;

typedef struct playstate_s {
    /* The currently playing audio media uri, returns an empty string when stopped. */
    char* src;
    /* Playing status, respectively 'play', 'pause', 'stop'*/
    int state;
    /* The volume of the current audio, the default current system media volume. */
    int volume;
    /* The current progress of the current audio, in seconds. */
    unsigned int currenttime;
    /* The total duration of the currently playing audio. */
    unsigned int duration;
    /* Whether the current audio is playing automatically. */
    bool autoplay;
    /* Whether the current audio is playing in a loop. */
    int loop;
    /* Whether the current audio is playing silently. */
    bool muted;
    /* allstate private data. */
    void* data;
} uv_audio_allstate_t;

typedef void (*uv_audio_callback_t)(void* data, int event, int status, void* result);
typedef void (*uv_audio_music_meta_callback_t)(char* title, char* artist, char* albumt);

typedef struct uv_audio_ops_s {
    void (*uv_audio_play_open)(uv_audio_callback_t cb, void* data, const char* pkgname);
    int (*uv_audio_play_play)(void* handle, const char* url, const char* options);
    int (*uv_audio_play_prepare)(void* handle, const char* url, const char* options);
    int (*uv_audio_play_start)(void* handle);
    int (*uv_audio_play_pause)(void* handle);
    int (*uv_audio_play_stop)(void* handle);
    int (*uv_audio_play_set_loop)(void* handle, int loop);
    int (*uv_audio_play_set_volume)(void* handle, int volume);
    int (*uv_audio_play_get_volume)(void* handle);
    int (*uv_audio_play_muted)(void* handle, bool muted);
    int (*uv_audio_play_set_seek)(void* handle, unsigned int msec);
    int (*uv_audio_play_get_position)(void* handle);
    int (*uv_audio_play_get_duration)(void* handle);
    int (*uv_audio_play_state)(void* handle);
    int (*uv_audio_play_allstate)(void* handle, void* data);
    int (*uv_audio_play_close)(void* handle);
    int (*uv_audio_play_notify)(char* title, char* artist, char* albumt);
} uv_audio_ops_t;

typedef struct uv_audio_ctrl_s {
    int (*uv_audio_ctrl_prevsong)(void);
    int (*uv_audio_ctrl_nextsong)(void);
    int (*uv_audio_ctrl_play)(void);
    int (*uv_audio_ctrl_pause)(void);
    int (*uv_audio_ctrl_stop)(void);
    int (*uv_audio_ctrl_volumeup)(void);
    int (*uv_audio_ctrl_volumedown)(void);
    int (*uv_audio_ctrl_get_music_meta)(void);
} uv_audio_ctrl_t;

void uv_audio_play_register(uv_audio_ops_t* ctrl);
void uv_audio_ctrl_register(uv_audio_ctrl_t* ctrl);
uv_audio_ops_t* uv_audio_play_init(void);
uv_audio_ctrl_t* uv_audio_ctrl_init(void);
int uv_audio_async_messgae_send(const char* mq_name,
    uv_audio_mqmessage_t* data);
int uv_audio_async_messgae_recv(const char* mq_name,
    uv_audio_mqmessage_t* data);
int uv_audio_async_messgae_init(uv_loop_t* loop,
    uv_poll_t* pollhandle,
    const char* mq_name,
    uv_poll_cb cb);

/*********************** Synchronous interface *****************************/

#define UV_EXT_AUDIO_STREAMTYPE_MAX 20

#define UV_EXT_AUDIO_STATE_UKNOW 0
#define UV_EXT_AUDIO_STATE_PLAY 1
#define UV_EXT_AUDIO_STATE_PAUSE 2
#define UV_EXT_AUDIO_STATE_STOP 3
#define UV_EXT_AUDIO_STATE_COMPLETE 4
#define UV_EXT_AUDIO_STATE_STOPING 5

#define UV_EXT_AUDIO_EVENT_ERROR MEDIA_EVENT_NOP
#define UV_EXT_AUDIO_EVENT_STARTED MEDIA_EVENT_STARTED
#define UV_EXT_AUDIO_EVENT_STOPPED MEDIA_EVENT_STOPPED
#define UV_EXT_AUDIO_EVENT_COMPLETE MEDIA_EVENT_COMPLETED
#define UV_EXT_AUDIO_EVENT_EVENT_PREPARED MEDIA_EVENT_PREPARED
#define UV_EXT_AUDIO_EVENT_PAUSED MEDIA_EVENT_PAUSED

typedef struct uv_audio_chain_s uv_audio_t;

struct uv_audio_chain_s {
    void* iofhandle;

    bool loop;
    char* url;
    char* oldurl;
    char streamtype[UV_EXT_AUDIO_STREAMTYPE_MAX];
    bool autoplay;
    bool muted;
    int playstate;
    int init;
    float volume;
};

/****************************************************************************
 * Name: uv_audio_create
 *
 * Description:
 *   audio initialization.
 *
 * Input Parameters:
 *   handles   - audio handle
 *   callback  - Callback function of audio event
 *   parame    - parame of callback
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_create(uv_audio_t* handle, media_event_callback callback,
    void* parame);

/****************************************************************************
 * Name: uv_audio_set_url
 *
 * Description:
 *   Set playback link.
 *
 * Input Parameters:
 *   handles   - audio handle
 *   url       - Play link
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_set_url(uv_audio_t* handles, const char* url, bool force);

/****************************************************************************
 * Name: uv_audio_prepare
 *
 * Description:
 *   Parse the url and get the data.
 *
 * Input Parameters:
 *   handles   - audio handle
 *   url       - play url
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_prepare(uv_audio_t* handle, const char* url);

/****************************************************************************
 * Name: uv_audio_set_autoplay
 *
 * Description:
 *   Auto play, true: open false: close. When set to true, if there is a url
 *   currently, it will be played directly; and when the url is set, it will
 *   also be played directly.
 *
 * Input Parameters:
 *   handles   - audio handle
 *   autoplay  - auto play, true: open false: close.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_set_autoplay(uv_audio_t* handle, bool autoplay);

/****************************************************************************
 * Name: uv_audio_play
 *
 * Description:
 *   Play, need to set url in advance.
 *
 * Input Parameters:
 *   handles   - audio handle
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_play(uv_audio_t* handles);

/****************************************************************************
 * Name: uv_audio_pause
 *
 * Description:
 *   Pause play.
 *
 * Input Parameters:
 *   handles   - audio handle
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_pause(uv_audio_t* handles);

/****************************************************************************
 * Name: uv_audio_stop
 *
 * Description:
 *   Stop play.
 *
 * Input Parameters:
 *   handles   - audio handle
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_stop(uv_audio_t* handles);

/****************************************************************************
 * Name: uv_audio_loop
 *
 * Description:
 *   Set loop playback.
 *
 * Input Parameters:
 *   handles   - audio handle
 *   loop      - Loop count (-1: forever, 0: not loop)
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_loop(uv_audio_t* handles, int loop);

/****************************************************************************
 * Name: uv_audio_set_volume
 *
 * Description:
 *   Set playback volume.
 *
 * Input Parameters:
 *   handles   - audio handle
 *   volume    - volume. 0 ~ 1
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_set_volume(uv_audio_t* handles, float volume);

/****************************************************************************
 * Name: uv_audio_get_volume
 *
 * Description:
 *   Get playback volume.
 *
 * Input Parameters:
 *   handles   - audio handle
 *
 * Output Parameters:
 *   volume    - volume. 0 ~ 1
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_get_volume(uv_audio_t* handles, float* volume);

/****************************************************************************
 * Name: uv_audio_muted
 *
 * Description:
 *   Set mute.
 *
 * Input Parameters:
 *   handles   - audio handle
 *   muted     - true: Turn on mute  false: mute off
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_muted(uv_audio_t* handles, bool muted);

/****************************************************************************
 * Name: uv_audio_streamtype
 *
 * Description:
 *   Set the playback mode. The settable values are
 *   music and voicecall.
 *
 * Input Parameters:
 *   handles   - audio handle
 *   type      - music: uspeaker, voicecall: earpiece. The default is music
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_streamtype(uv_audio_t* handles, const char* type);

/****************************************************************************
 * Name: uv_audio_set_currenttime
 *
 * Description:
 *   Set playback position.
 *
 * Input Parameters:
 *   handles   - audio handle
 *   sec       - Playback position, seconds.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_set_currenttime(uv_audio_t* handles, unsigned int sec);

/****************************************************************************
 * Name: uv_audio_get_currenttime
 *
 * Description:
 *   Get the current playback position.
 *
 * Input Parameters:
 *   handles   - audio handle
 *
 * Output Parameters:
 *   sec       - playback position,(s).
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_get_currenttime(uv_audio_t* handles, unsigned int* sec);

/****************************************************************************
 * Name: uv_audio_get_duration
 *
 * Description:
 *   Get the total time.
 *
 * Input Parameters:
 *   handles   - audio handle
 *
 * Output Parameters:
 *   sec       - total time,(s).
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_get_duration(uv_audio_t* handles, unsigned int* sec);

/****************************************************************************
 * Name: uv_audio_get_isplay
 *
 * Description:
 *   Get whether it is currently playing.
 *
 * Input Parameters:
 *   handles   - audio handle
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_get_isplay(uv_audio_t* handle);

/****************************************************************************
 * Name: uv_audio_close
 *
 * Description:
 *   Close this audio.
 *
 * Input Parameters:
 *   handles   - audio handle
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_audio_close(uv_audio_t* handles);

/****************************************************************************
 * recorder
 ****************************************************************************/

#define UV_RECORDER_EVENT_OPEN 0xA0
#define UV_RECORDER_EVENT_PREPARE 0xA1
#define UV_RECORDER_EVENT_START 0xA2
#define UV_RECORDER_EVENT_STOP 0xA3
#define UV_RECORDER_EVENT_READ 0xA4
#define UV_RECORDER_EVENT_PAUSE 0xA5
#define UV_RECORDER_EVENT_CLOSE 0xFF

#define UV_RECORDER_BUFFER_MODE 1
#define UV_RECORDER_NOBUFFER_MODE 0

#define UV_RECORD_RESULT_SUCCESS 0 // start成功, 但是media start未开始，此时去stop
#define UV_RECORD_RESULT_INVAL 1 // 参数错误
#define UV_RECORD_RESULT_HANDLEING 2 // 正在获取handle
#define UV_RECORD_RESULT_OCCUPY 3 // 资源被占用(录音中)
#define UV_RECORD_RESULT_FAIL 4 // 录音失败
#define UV_RECORD_RESULT_EXCEPTION 5 // 系统异常
#define UV_RECORD_RESULT_TIMEOUT 6 // 超时
#define UV_RECORD_RESULT_READ_SUCCESS 7 // read buffer
#define UV_RECORD_RESULT_STOP_SUCCESS 8 // read buffer

typedef void (*uv_record_callback_t)(void* data, int event, int status, void* result);
typedef void (*uv_record_buffer_cb)(void* data, int size, int status);
typedef void (*uv_record_result_cb)(void* data, int status, const char* result);

typedef struct uv_record_buff_s {
    char* buff;
    int bufflen;
} uv_record_buff_t;

typedef struct uv_record_attr_s {
    char* buff; // buffer or pathname
    int size; // buffer 大小
    int mode; // 0： pathname模式， 1： buffer模式
    int interval; // buffer 模式读取录音的间隔，单位ms/只有在buffer模式下才会用到
    int duration; // 录音时间
    uv_record_result_cb resultcb;
    uv_record_buffer_cb buffercb;
} uv_record_attr_t;

typedef struct uv_record_ops_s {
    void (*uv_record_open)(uv_record_callback_t cb, void* data, const char* pkgname);
    int (*uv_record_prepare)(void* handle, const char* url, const char* options);
    int (*uv_record_close)(void* handle);
    int (*uv_record_start)(void* handle);
    int (*uv_record_pause)(void* handle);
    int (*uv_record_stop)(void* handle);
    int (*uv_record_read_data)(void* handle, char* buff, int bufflen);
} uv_record_ops_t;

void uv_record_register(uv_record_ops_t* ops);
uv_record_ops_t* uv_record_init(void);

#endif

/****************************************************************************
 * volume
 ****************************************************************************/

#ifdef CONFIG_MEDIA

typedef void (*uv_volume_cb)(int status, void* cookie);
typedef struct uv_volume_s {
    uv_loop_t* loop;
} uv_volume_t;

/****************************************************************************
 * Name: uv_volume_init
 *
 * Description:
 *   Init the uv_volume.
 *
 * Input Parameters:
 *   uv_volume - the uv_volume handle
 *   loop      - the uv_loop
 *
 * Returned Value:
 *   Zero (OK) on success;
 *   Negative on fail;
 *
 ****************************************************************************/

int uv_volume_init(uv_volume_t* uv_volume, uv_loop_t* loop);

/****************************************************************************
 * Name: uv_volume_set
 *
 * Description:
 *   Set the specified stream volume.
 *
 * Input Parameters:
 *   uv_volume    - the uv_volume handle
 *   volume       - the set volume
 *   uv_volume_cb - the callback function called after the work finish
 *   stream       - the media stream name
 *   arg          - the jse volume handle
 *
 * Returned Value:
 *   Zero (OK) on success;
 *   Negative on fail;
 *
 ****************************************************************************/

int uv_volume_set(uv_volume_t* uv_volume, int volume, uv_volume_cb cb,
    const char* stream, void* arg);

/****************************************************************************
 * Name: uv_volume_get
 *
 * Description:
 *   Get the specified stream volume.
 *
 * Input Parameters:
 *   uv_volume    - the uv_volume handle
 *   pvolume      - the pointer to get volume
 *   uv_volume_cb - the callback function called after the work finish
 *   stream       - the media stream name
 *   arg          - the jse volume handle
 *
 * Returned Value:
 *   Zero (OK) on success;
 *   Negative on fail;
 *
 ****************************************************************************/

int uv_volume_get(uv_volume_t* uv_volume, int* pvolume, uv_volume_cb cb,
    const char* stream, void* arg);

#endif /* #ifdef CONFIG_MEDIA */

/****************************************************************************
 * uv_mqueue
 ****************************************************************************/

typedef struct uv_message_s {
    int cmd;
    int status;
    void* data;
} uv_message_t;

typedef struct uv_mqueue_s uv_mqueue_t;

typedef void (*uv_mqueue_cb)(uv_mqueue_t* mqueue, int status, void* data, size_t datalen);

struct uv_mqueue_s {
    uv_poll_t poll;
    uv_mqueue_cb cb;
    void* data;

    /** priviate variable */
    int fd;
    void* msg_data;
    uv_close_cb close_cb;
};

/****************************************************************************
 * Name: uv_mqueue_send
 *
 * Description:
 *   Send data to mqueue named by mq_name. This function can be called in any
 *   task and any pthread.
 *
 * Input Parameters:
 *   mq_name   - Message queue name
 *   data      - Data to send
 *   datasize  - The size of the data in bytes
 *
 * Returned Value:
 *   Zero (OK) on success
 *   Negative on fail
 *
 ****************************************************************************/
int uv_mqueue_send(const char* mq_name, void* data, int datasize);

/****************************************************************************
 * Name: uv_mqueue_recv
 *
 * Description:
 *   Receive data from message queue named by mq_name. This function can be
 *   called in any task and any pthread.
 *
 * Input Parameters:
 *   mq_name   - Message queue name
 *   buff      - Buffer to receive the message
 *   buffsize  - Size of the buffer in bytes
 *
 * Returned Value:
 *   On success, the length of the select message in bytes is returned.
 *   Negative on fail
 *
 ****************************************************************************/
int uv_mqueue_recv(const char* mq_name, void* buff, int buffsize);

/****************************************************************************
 * Name: uv_mqueue_init
 *
 * Description:
 *   Initialize uv message queue, will open the message queue or create it if it
 *   not exist.
 *
 * Input Parameters:
 *   loop      - Event loop
 *   mqueue    - Pointer to uv message queue handler, each uv_message has one
 *               handler
 *   name      - Message queue name
 *   attr      - Attribuites of message queue
 *
 * Returned Value:
 *   Zero (OK) on success
 *   Negative on fail
 *
 ****************************************************************************/
int uv_mqueue_init(uv_loop_t* loop, uv_mqueue_t* mqueue, const char* name, struct mq_attr* attr);

/****************************************************************************
 * Name: uv_mqueue_start
 *
 * Description:
 *   Start to listen message queue reading event or disconnecting event.
 *
 * Input Parameters:
 *   mqueue    - Message queue handler
 *   cb        - Callback be called when receieving message from queue or
 *               something is wrong.
 *
 * Returned Value:
 *   Zero (OK) on success
 *   Negative on fail
 *
 ****************************************************************************/
int uv_mqueue_start(uv_mqueue_t* mqueue, uv_mqueue_cb cb);

/****************************************************************************
 * Name: uv_mqueue_stop
 *
 * Description:
 *   Stop listening message queue reading event or disconnecting event.
 *
 * Input Parameters:
 *   mqueue    - Message queue handler
 *
 * Returned Value:
 *   Zero (OK) on success
 *   Negative on fail
 *
 ****************************************************************************/
int uv_mqueue_stop(uv_mqueue_t* mqueue);

/****************************************************************************
 * Name: uv_mqueue_close
 *
 * Description:
 *   Close uv message queue.
 *
 * Input Parameters:
 *   mqueue    - Message queue handler
 *   close_cb  - Closing callback be called asynchronously after this call.
 *               It can be NULL in cases where no cleanup or deallocation is
 *               necessary.
 *
 * Returned Value:
 *   None
 *
 ****************************************************************************/
void uv_mqueue_close(uv_mqueue_t* mqueue, uv_close_cb close_cb);

/****************************************************************************
 * network
 ****************************************************************************/

#if defined(CONFIG_LIB_CURL)
#define UV_NETSTATUS_WIFI 1
#define UV_NETSTATUS_BLUETOOTH 2
#define UV_NETSTATUS_NONE 3
#define UV_NETSTATUS_ETHERNET 4
#define UV_NETSTATUS_CELLULAR 5
#define UV_NETSTATUS_TUN 6

typedef void (*uv_netstatus_ipcb_t)(char* data, int result, void* extra);

typedef struct uv_network_s uv_network_t;

struct uv_network_s {
    uv_request_session_t* handle;
    uv_request_t* fetch;
    uv_netstatus_ipcb_t cb;
    void* data;
};

/****************************************************************************
 * Name: uv_network_init
 *
 * Description:
 *   Get public network ip initialization.
 *
 * Input Parameters:
 *   loop   - event loop
 *   handle - network handle
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_network_init(uv_loop_t* loop, uv_network_t* handle);

/****************************************************************************
 * Name: uv_network_close
 *
 * Description:
 *   Close get public network ip function.
 *
 * Input Parameters:
 *   loop   - event loop
 *   handle - network handle
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_network_close(uv_network_t* handle);

/****************************************************************************
 * Name: uv_netstatus_gettype
 *
 * Description:
 *   get network type.
 *
 * Input Parameters:
 *   type - network type
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_netstatus_gettype(uint8_t* type);

/****************************************************************************
 * Name: uv_netstatus_getip
 *
 * Description:
 *   get public network ip.
 *
 * Input Parameters:
 *   handle - network handle
 *   cb     - callback function
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_netstatus_getip(uv_network_t* handle, uv_netstatus_ipcb_t cb);

#endif

/****************************************************************************
 * topicadv
 ****************************************************************************/

#ifdef CONFIG_UORB

/****************************************************************************
 * Name: uv_topicadv_init
 *
 * Description:
 *   Broadcast initialization, this function will only be called once.
 *
 * Input Parameters:
 *   loop   - event loop
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_topicadv_init(uv_loop_t* loop);

/****************************************************************************
 * Name: uv_topicadv_close
 *
 * Description:
 *   Turn off broadcast.
 *
 * Input Parameters:
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_topicadv_close(void);

#endif

typedef struct app_verify_s app_verify_t;

/****************************************************************************
 * Name: app_verify_init
 *
 * Description:
 *   Resources required for initialization.
 *
 * Input Parameters:
 *   app_path   - rpk file path
 *   pkg_path   - save path of rpk unzip file
 *
 * Returned Value:
 *   app verify info structure, NULL is fail
 ****************************************************************************/

app_verify_t* app_verify_init(const char* app_path, const char* pkg_path);

/****************************************************************************
 * Name: app_verify_unzip
 *
 * Description:
 *   rpk file verify and unzip.
 *
 * Input Parameters:
 *   app_verify_info   - app verify info structure
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int app_verify_unzip(app_verify_t* app_verify_info);

/****************************************************************************
 * Name: app_pre_unzip
 *
 * Description:
 *   Pre decompress a single file in RPK
 *
 * Input Parameters:
 *   app_verify_info   - app verify info structure
 *   filename          - Pre decompress files
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int app_pre_unzip(app_verify_t* app_verify_info, const char* filename);

/****************************************************************************
 * Name: app_get_fingerprint
 *
 * Description:
 *   Get RPK certificate fingerprint
 *
 * Input Parameters:
 *   app_verify_info   - app verify info structure
 *
 * Returned Value:
 *   SHA1 result pointer (32-bit length), NULL is fail
 ****************************************************************************/

uint8_t* app_get_fingerprint(app_verify_t* app_verify_info);

/****************************************************************************
 * Name: app_verify_close
 *
 * Description:
 *   Free up used memory
 *
 * Input Parameters:
 *   app_verify_info   - app verify info structure
 *
 * Returned Value:
 *   None.
 ****************************************************************************/

void app_verify_close(app_verify_t* app_verify_info);

#ifdef CONFIG_UNQLITE

typedef struct uv_db_s uv_db_t;
typedef void (*uv_db_callback)(int status, const char* key, uv_buf_t value, void* cookie);

/****************************************************************************
 * Name: uv_db_init
 *
 * Description:
 *   Initialize database.
 *
 * Input Parameters:
 *   loop     - the loop that data transfer uses.
 *   handle   - the handler to database. Each database uses one handle.
 *   name     - Specified database path.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_db_init(uv_loop_t* loop, uv_db_t** handle, const char* path);

/****************************************************************************
 * Name: uv_db_close
 *
 * Description:
 *   close database. All records will be persisted locally.
 *
 * Input Parameters:
 *   handle   - the handler to database.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_db_close(uv_db_t* handle);

/****************************************************************************
 * Name: uv_db_commit
 *
 * Description:
 *   Commit all changes to the database.
 *
 * Input Parameters:
 *   handle   - the handler to database.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_db_commit(uv_db_t* handle);

/****************************************************************************
 * Name: uv_db_get
 *
 * Description:
 *   Get a record. in synchronous mode, the callback function should be set to null.
 *
 * Input Parameters:
 *   handle   - the handler to database.
 *   key      - key
 *   value    - value buff, valid in sync mode. set to null in asynchronous mode
 *   cb       - completion callback function
 *   arg      - callback function parameters
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_db_get(uv_db_t* handle, const char* key, uv_buf_t* value, uv_db_callback cb, void* arg);

typedef struct uv_db_data_s {
    char* key;
    char* value;
} uv_db_data_t;

/****************************************************************************
 * Name: uv_db_set
 *
 * Description:
 *   set a record. in synchronous mode, the callback function should be set to null.
 *
 * Input Parameters:
 *   handle   - the handler to database.
 *   key      - key
 *   value    - value buff.
 *   cb       - completion callback function
 *   arg      - callback function parameters
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_db_set(uv_db_t* handle, const char* key, uv_buf_t* value, uv_db_callback cb, void* arg);

/****************************************************************************
 * Name: uv_db_delete
 *
 * Description:
 *   delete a record. in synchronous mode, the callback function should be set to null.
 *
 * Input Parameters:
 *   handle   - the handler to database.
 *   key      - key
 *   cb       - completion callback function
 *   arg      - callback function parameters
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_db_delete(uv_db_t* handle, const char* key, uv_db_callback cb, void* arg);

/****************************************************************************
 * Name: uv_db_key
 *
 * Description:
 *   Find a key according to the index. When index is - 1,
 *   the number of keys in the database is returned.
 *
 * Input Parameters:
 *   handle   - the handler to database.
 *   index    - index
 *   cb       - completion callback function
 *   arg      - callback function parameters
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_db_key(uv_db_t* handle, int index, char** key, uv_db_callback cb, void* arg);

/****************************************************************************
 * Name: uv_db_list
 *
 * Description:
 *   Traverse each element in the database.
 *
 * Input Parameters:
 *   handle   - the handler to database.
 *   cb       - callback function
 *   arg      - callback function parameters
 *   is_sync  - is sync mode ,1 is true
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_db_list(uv_db_t* handle, uv_db_callback cb, void* arg, int is_sync);

#endif

#ifdef __cplusplus
}
#endif

#endif /* __SYSTEM_LIBUV_EXT_INCLUDE_UV_EXT_H */
