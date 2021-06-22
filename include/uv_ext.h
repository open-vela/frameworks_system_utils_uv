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

#define UV_EXT_LOCALE_LANG_KEY "persist.language_region"
#define UV_EXT_LOCALE_MAX_SIZE 10

typedef struct uv_locale_s uv_locale_t;

struct uv_locale_s {
  char language[UV_EXT_LOCALE_MAX_SIZE];
  char country_region[UV_EXT_LOCALE_MAX_SIZE];
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

/****************************************************************************
 * brightness
 ****************************************************************************/

#if defined(CONFIG_LCD_DEV) && defined(CONFIG_UORB)

typedef struct uv_brightness_s uv_brightness_t;

struct uv_brightness_s {
  /* Whether the application is on the current screen. 0: no 1: yes*/

  int active;

  /* Each application saves brightness information separately */

  int devid;
  int lightvalue;
  int lightmode;
  bool keepon;
};

/****************************************************************************
 * Name: uv_system_brightness_setval
 *
 * Description:
 *   Set the system brightness value and the screen brightness.
 *
 * Input Parameters:
 *   val     - brightness value. 0 - CONFIG_LCD_MAXPOWER.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_system_brightness_setval(int val);

/****************************************************************************
 * Name: uv_system_brightness_getval
 *
 * Description:
 *   Gets the system brightness value.
 *
 * Input Parameters:
 *   val     - system brightness value.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_system_brightness_getval(int *val);

/****************************************************************************
 * Name: uv_system_brightness_recovery
 *
 * Description:
 *   Recovery the system brightness value.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_system_brightness_recovery(void);

/****************************************************************************
 * Name: uv_brightness_setval
 *
 * Description:
 *   Set screen brightness.The system brightness value does not change.
 *
 * Input Parameters:
 *   handle  - brightness handle. There can only be one per application.
 *   val     - brightness value. 0 - CONFIG_LCD_MAXPOWER.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_setval(uv_brightness_t *handle, int val);

/****************************************************************************
 * Name: uv_brightness_getval
 *
 * Description:
 *   Gets the screen brightness. Does not change the system brightness value
 * Input Parameters:
 *   handle  - brightness handle. There can only be one per application.
 *   val     - brightness value.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_getval(uv_brightness_t *handle, int *val);

/****************************************************************************
 * Name: uv_brightness_setmode
 *
 * Description:
 *   Setting Brightness Mode.
 *
 * Input Parameters:
 *   handle  - brightness handle. There can only be one per application.
 *   mode    - brightness mode. 0: Manual 1: Automatic
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_setmode(uv_brightness_t *handle, int mode);

/****************************************************************************
 * Name: uv_brightness_getmode
 *
 * Description:
 *   Get Brightness Mode.
 *
 * Input Parameters:
 *   handle  - brightness handle. There can only be one per application.
 *   mode    - brightness mode. 0: Manual 1: Automatic
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_getmode(uv_brightness_t *handle, int *mode);

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
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_setkeepon(uv_brightness_t *handle, bool keep);

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
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_init(uv_loop_t *loop, uv_brightness_t *handle);

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

int uv_brightness_close(uv_brightness_t *handle);

/****************************************************************************
 * Name: uv_brightness_free
 *
 * Description:
 *   Brightness free.
 *   Note: Each application is called when it finally closes.
 *
 * Input Parameters:
 *   handle  - brightness handle. There can only be one per application.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_brightness_free(void);
#endif

#if defined(__NuttX__) && defined(CONFIG_LIB_CURL) || defined(MOCK_LIBUV_FEATURE)

struct uv_response_s {
    int httpcode;
    char* headers;
    char* body;
    uint16_t size;
    void* userp;
};

enum {
    UV_REQUEST,
    UV_DOWNLOAD,
    UV_UPLOAD
};

enum {
    UV_REQUEST_DONE,
    UV_REQUEST_ERROR
};

typedef struct uv_request_session_s uv_request_session_t;
typedef struct uv_request_s uv_request_t;
typedef struct uv_response_s uv_response_t;

typedef void (*uv_request_cb)(int state, uv_response_t* response);

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

#endif

#ifdef CONFIG_MIWEAR_APPS

typedef enum {
  MIWEAR_MESSAGE_TYPE_CLIENT_ID = 0,
  MIWEAR_MESSAGE_TYPE_RESPONSE,
  MIWEAR_MESSAGE_TYPE_DATA,
  MIWEAR_MESSAGE_TYPE_STATUS,
} miwear_message_type_t;

typedef enum {
  MIWEAR_CLIENT_ID_SENT = 0,
  MIWEAR_CONNECT_FAILED, /* Failed to connect server */
  MIWEAR_CONNECTION_CLOSED, /* Connection closed */
  MIWEAR_CLIENT_ONLINE, /* A new client connected to server. */

  MIWEAR_PHONE_CONNECTED, /* TBD */
} miwear_status_t;

typedef struct message_status_data_s {
    miwear_status_t status;
    void *parameter;
} message_status_data_t;

typedef struct uv_miwear_s uv_miwear_t;
typedef void (*uv_miwear_cb)(uv_miwear_t* miwear, int status,
                             const void* data, uint32_t len,
                             miwear_message_type_t type);

struct uv_miwear_s {
  union {
    struct server* server;
    struct client* client;
  };
  uv_miwear_cb cb; /* Callback will be made when received data. */
  bool is_server; /* To mark this instance is for a server or client. */
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
                      const char* pkg_name, uv_miwear_cb cb);

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

int uv_miwear_send(uv_miwear_t* miwear, const void* data, uint32_t len,
                   uv_miwear_cb cb);


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
                           const char* name, const char* path, uv_miwear_cb cb);

/****************************************************************************
 * Name: uv_miwear_stop_client
 *
 * Description:
 *   Stop miwear client.
 *
 * Input Parameters:
 *
 *   miwear   - the miwear instance, which is initialized when returned.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/

int uv_miwear_stop_client(uv_miwear_t* miwear);


/****************************************************************************
 * Name: uv_miwear_send_to_client
 *
 * Description:
 *   Send data to connected client.
 *
 * Input Parameters:
 *
 *   miwear   - the miwear instance, which is initialized when returned.
 *   data     - Data going to be sent, memory should be kept until cb called.
 *   len      - Data bytes.
 *   type     - Message type, should always use MIWEAR_MESSAGE_TYPE_DATA.
 *   cb       - the callback will be made when data sent or error occurs.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/
int uv_miwear_send_to_client(uv_miwear_t* miwear, const char* name,
                             const void* data, uint32_t len,
                             miwear_message_type_t type, uv_miwear_cb cb);

/****************************************************************************
 * Name: uv_miwear_send_to_server
 *
 * Description:
 *   send data to connected server.
 *
 * Input Parameters:
 *
 *   miwear   - the miwear instance, which is initialized when returned.
 *   data     - Data going to be sent, memory should be kept until cb called.
 *   len      - Data bytes.
 *   type     - Message type, should always use MIWEAR_MESSAGE_TYPE_DATA.
 *   cb       - the callback will be made when data sent or error occurs.
 *
 * Returned Value:
 *   Zero (OK) on success;
 ****************************************************************************/
int uv_miwear_send_to_server(uv_miwear_t* miwear, const void* data,
                             uint32_t len, miwear_message_type_t type,
                             uv_miwear_cb cb);

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
                           const char* path, uv_miwear_cb cb);


#endif

#ifdef __cplusplus
}
#endif

#endif /* __SYSTEM_LIBUV_EXT_INCLUDE_UV_EXT_H */
