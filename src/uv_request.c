/****************************************************************************
 * system/libuv/ext/src/uv_request.c
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.  The
 * ASF licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the
 * License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *
 ****************************************************************************/

/****************************************************************************
 * Included Files
 ****************************************************************************/
#include <curl/curl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <uv_ext.h>

#include <nuttx/list.h>

#ifndef CONFIG_UV_REQUEST_MAX_LINKS
#define CONFIG_UV_REQUEST_MAX_LINKS 5
#endif

#define request_debug(fmt, ...) uv_log_debug("uv_request", fmt, ##__VA_ARGS__)
#define request_info(fmt, ...) uv_log_info("uv_request", fmt, ##__VA_ARGS__)
#define request_error(fmt, ...) uv_log_error("uv_request", fmt, ##__VA_ARGS__)

struct uv_request_session_s {
    struct list_node list;
    uint32_t connections_cnt;
    uv_loop_t* loop;
    CURLM* multi_handle;
    uv_timer_t timeout;
};

struct uv_request_s {
    int error_code;
    FILE* fd;
    void* data;
    const char* url;
    uv_request_cb cb;
    int (*progress_cb)(uv_request_t*, off_t, off_t, off_t, off_t);
    void* easy_handle;
    void* header_list;
    struct list_node node;
    struct data_block_s body;
    struct data_block_s header;
    uv_request_session_t* handle;
    uv_response_t response;
    struct curl_httppost* formpost;
    struct curl_httppost* lastptr;
};

typedef struct curl_context_s {
    uv_poll_t poll_handle;
    curl_socket_t sockfd;
    uv_request_session_t* handle;
} curl_context_t;

static curl_context_t* create_curl_context(uv_request_session_t* handle, curl_socket_t sockfd)
{
    curl_context_t* context;

    context = (curl_context_t*)malloc(sizeof(*context));

    context->sockfd = sockfd;

    uv_poll_init_socket(handle->loop, &context->poll_handle, sockfd);
    context->poll_handle.loop = handle->loop;
    context->poll_handle.data = context;
    context->handle = handle;

    return context;
}

static int recursion_mkdir(const char* path)
{
    const char s[] = "/";
    char* data;
    char* token;
    int res;

    data = (char*)malloc(PATH_MAX);
    if (data == NULL) {
        return -ENOMEM;
    }

    res = access(path, F_OK);
    if (res == 0) {
        free(data);
        return 0;
    }

    strcpy(data, path);
    token = strtok(data, s);

    while (token != NULL) {
        token = strtok(NULL, s);
        if (token != NULL) {
            *(token - 1) = '/';
        }

        res = access(data, F_OK);
        if (res != 0) {
            res = mkdir(data, 0777);
        }
    }

    free(data);
    return res;
}

static FILE* mkfile(const char* path)
{
    char* ret;
    char* fileName;

    fileName = (char*)malloc(PATH_MAX);
    if (fileName == NULL) {
        return NULL;
    }

    strcpy(fileName, path);
    ret = strrchr(fileName, '/');
    if (ret == 0) {
        free(fileName);
        return fopen(path, "wb+");
    }
    *ret++ = 0;

    recursion_mkdir(fileName);

    free(fileName);
    return fopen(path, "wb+");
}

static void curl_close_cb(uv_handle_t* handle)
{
    curl_context_t* context = (curl_context_t*)handle->data;
    free(context);
}

static void destroy_curl_context(curl_context_t* context)
{
    uv_close((uv_handle_t*)&context->poll_handle, curl_close_cb);
}

static void uv_request_cleanup(uv_request_t* request)
{
    if (request->fd) {
        fclose(request->fd);
    }

    if(request->easy_handle) {
        curl_easy_cleanup(request->easy_handle);
    }

    if (request->header_list) {
        curl_slist_free_all(request->header_list);
    }

    if (request->formpost) {
        curl_formfree(request->formpost);
    }

    if (request->response.body) {
        free(request->response.body);
    }

    if (request->response.headers) {
        free(request->response.headers);
    }

    free(request);
}

static void uv_request_done(CURL* easy_handle, uv_request_t* request)
{
    enum uv_request_state_e state;
    curl_easy_getinfo(easy_handle, CURLINFO_PRIVATE, (char**)&request);
    curl_easy_getinfo(easy_handle, CURLINFO_RESPONSE_CODE, &request->response.httpcode);

    if (request->fd) {
        fclose(request->fd);
        request->fd = 0;
    }

    if (request->error_code != CURLE_OK) {
        request_error("request error: %p, %s", request, curl_easy_strerror(request->error_code));
        request->response.httpcode = request->error_code;
        if (request->response.body) {
            free(request->response.body);
        }
        request->response.body = (char*)strdup(curl_easy_strerror(request->error_code));
        state = UV_REQUEST_ERROR;
    } else {
        request_debug("request done: %p", request);
        state = UV_REQUEST_DONE;
    }
    request->cb(state, &request->response);

    if (easy_handle != NULL) {
        curl_multi_remove_handle(request->handle->multi_handle, easy_handle);
    }
    uv_request_cleanup(request);
}

static void check_multi_info(CURLM* multi_handle)
{
    int pending;
    CURLMsg* message;
    uv_request_t* request = NULL;

    while ((message = curl_multi_info_read(multi_handle, &pending))) {
        if (message->msg == CURLMSG_DONE) {
            curl_easy_getinfo(message->easy_handle, CURLINFO_PRIVATE, (char**)&request);
            request->error_code = message->data.result;

            struct uv_request_session_s* handle = request->handle;
            handle->connections_cnt--;

            if (!list_is_empty(&handle->list)) {
                uv_request_t* new_request;
                request_debug("Leave queue, start downloading: %p", request);
                struct list_node* node = list_remove_head(&handle->list);
                new_request = container_of(node, uv_request_t, node);
                curl_multi_add_handle(multi_handle, new_request->easy_handle);
                handle->connections_cnt++;
            }

            uv_request_done(message->easy_handle, request);
        }
    }
}

static void curl_perform(uv_poll_t* req, int status, int events)
{
    int running_handles;
    int flags = 0;
    curl_context_t* context;
    uv_request_session_t* handle;

    if (events & UV_READABLE)
        flags |= CURL_CSELECT_IN;
    if (events & UV_WRITABLE)
        flags |= CURL_CSELECT_OUT;

    context = (curl_context_t*)req->data;
    handle = context->handle;

    curl_multi_socket_action(handle->multi_handle, context->sockfd, flags,
        &running_handles);

    check_multi_info(handle->multi_handle);
}

static void on_timeout(uv_timer_t* req)
{
    int running_handles;
    uv_request_session_t* handle;

    handle = req->data;
    curl_multi_socket_action(handle->multi_handle, CURL_SOCKET_TIMEOUT, 0,
        &running_handles);
    check_multi_info(handle->multi_handle);
}

static int start_timeout(CURLM* multi, long timeout_ms, void* userp)
{
    uv_request_session_t* handle = (uv_request_session_t*)userp;

    if (timeout_ms < 0) {
        uv_timer_stop(&handle->timeout);
    } else {
        if (timeout_ms == 0)
            timeout_ms = 1;

        uv_timer_start(&handle->timeout, on_timeout, timeout_ms, 0);
    }
    return 0;
}

static int handle_socket(CURL* easy, curl_socket_t s, int action, void* userp, void* socketp)
{
    curl_context_t* curl_context;
    uv_request_session_t* handle = (uv_request_session_t*)userp;
    int events = 0;

    switch (action) {
    case CURL_POLL_IN:
    case CURL_POLL_OUT:
    case CURL_POLL_INOUT:
        curl_context = socketp ? (curl_context_t*)socketp : create_curl_context(handle, s);

        curl_multi_assign(handle->multi_handle, s, (void*)curl_context);

        if (action != CURL_POLL_IN)
            events |= UV_WRITABLE;
        if (action != CURL_POLL_OUT)
            events |= UV_READABLE;

        uv_poll_start(&curl_context->poll_handle, events, curl_perform);
        break;
    case CURL_POLL_REMOVE:
        if (socketp) {
            uv_poll_stop(&((curl_context_t*)socketp)->poll_handle);
            destroy_curl_context((curl_context_t*)socketp);
            curl_multi_assign(handle->multi_handle, s, NULL);
        }
        break;
    default:
        abort();
    }

    return 0;
}

static size_t save_request_body(void* contents, size_t size, size_t nmemb, void* ctx)
{
    size_t realsize = size * nmemb;
    uv_request_t* request = (uv_request_t*)ctx;
    char* ptr = realloc(request->response.body, request->response.size + realsize + 1);
    if (!ptr) {
        return 0;
    }

    request->response.body = ptr;
    memcpy(&(request->response.body[request->response.size]), contents, realsize);
    request->response.size += realsize;
    request->response.body[request->response.size] = '\0';
    return realsize;
}

static void __curl_init_once(void)
{
    curl_global_init(CURL_GLOBAL_ALL);
}

static void __curl_init(void)
{
    static uv_once_t __curl_init_once_s = UV_ONCE_INIT;

    uv_once(&__curl_init_once_s, __curl_init_once);
}

int uv_request_init(uv_loop_t* loop, uv_request_session_t** handle)
{
    if (!loop) {
        return -EINVAL;
    }

    __curl_init();

    *handle = malloc(sizeof(uv_request_session_t));

    uv_timer_init(loop, &(*handle)->timeout);
    (*handle)->timeout.data = *handle;

    (*handle)->connections_cnt = 0;
    list_initialize(&(*handle)->list);
    (*handle)->loop = loop;
    (*handle)->multi_handle = curl_multi_init();
    curl_multi_setopt((*handle)->multi_handle,
        CURLMOPT_MAX_TOTAL_CONNECTIONS,
        CONFIG_UV_REQUEST_MAX_LINKS);
    curl_multi_setopt((*handle)->multi_handle, CURLMOPT_MAXCONNECTS,
        CONFIG_UV_REQUEST_MAX_LINKS);
    return 0;
}

int uv_request_create(uv_request_t** request)
{
    *request = calloc(1, sizeof(uv_request_t));
    if (*request == NULL) {
        return -ENOSPC;
    }

    return 0;
}

int uv_request_set_method(uv_request_t* request, const char* method)
{
    static const char head_method[] = "HEAD";

    if (!request | !method) {
        return -EINVAL;
    }

    if (strncasecmp(head_method, method, sizeof(head_method) - 1) == 0) {
        curl_easy_setopt(request->easy_handle, CURLOPT_NOBODY, 1L);
    } else {
        curl_easy_setopt(request->easy_handle, CURLOPT_CUSTOMREQUEST, method);
    }

    return 0;
}

CURL_EXTERN void Curl_resolver_kill(CURL* data);

int uv_request_delete(uv_request_t* request)
{
    if (!request) {
        return -EINVAL;
    }

    if (request->fd) {
        fclose(request->fd);
        request->fd = 0;
    }

    if (list_in_list(&request->node)) {
        request_debug("cancel pending request: %p", request);
        list_delete(&request->node);
    } else {
        request_debug("Cancel a downloading request: %p", request);
        request->handle->connections_cnt--;
        /* Now, we should kill resolver and clean up any resolver data. */
        if(request->easy_handle){
            Curl_resolver_kill(request->easy_handle);
        }

        curl_multi_remove_handle(request->handle->multi_handle,
                                 request->easy_handle);
    }

    uv_request_cleanup(request);
    return 0;
}

const char* uv_request_get_url(uv_request_t* request)
{
    if (!request || !request->url) {
        return NULL;
    }
    return request->url;
}

uv_request_header_t uv_request_get_header_list(uv_request_t* request)
{
    uv_request_header_t result;
    result.currentIndex = 0;
    result.data = NULL;
    if (!request || !request->header_list) {
        return result;
    }
    struct curl_slist* curr = (struct curl_slist*)request->header_list;
    int count = 0;
    while (curr) {
        count++;
        curr = curr->next;
    }
    result.data = (char**)malloc(count);
    if (!result.data) {
        return result;
    }
    curr = (struct curl_slist*)request->header_list;
    while (curr) {
        result.data[result.currentIndex++] = curr->data;
        curr = curr->next;
    }
    return result;
}

int uv_request_set_url(uv_request_t* request, const char* url)
{
    if (!request || !url) {
        return -EINVAL;
    }

    memset(request, 0, sizeof(uv_request_t));
    request_debug("request url: %p, %s", request, url);
    request->easy_handle = curl_easy_init();
    request->header_list = NULL;
    request->fd = NULL;

    request->url = url;

    return 0;
}

int uv_request_set_verbose(uv_request_t* request)
{
  if (!request) {
    return -EINVAL;
  }

  return curl_easy_setopt(request->easy_handle, CURLOPT_VERBOSE, 1L);
}

int uv_request_set_formdata_file(uv_request_t* request, const char* name,
    const char* filename, const char* filepath)
{
    if (!request || !name || !filename || !filepath) {
        return -EINVAL;
    }

    return curl_formadd(&request->formpost, &request->lastptr,
        CURLFORM_COPYNAME, name, CURLFORM_FILENAME, filename,
        CURLFORM_FILE, filepath, CURLFORM_END);
}

int uv_request_set_formdata_buf(uv_request_t* request, const char* name,
    const char* filename, const char* buffer,
    int len)
{
    if (!request || !name || !filename || !buffer || len == 0) {
        return -EINVAL;
    }

    if (strlen(filename) == 0) {
        return curl_formadd(&request->formpost, &request->lastptr,
            CURLFORM_COPYNAME, name, CURLFORM_BUFFERPTR,
            buffer, CURLFORM_BUFFERLENGTH,
            len, CURLFORM_END);
    } else {
        return curl_formadd(&request->formpost, &request->lastptr,
            CURLFORM_COPYNAME, name, CURLFORM_BUFFER, filename,
            CURLFORM_BUFFERPTR, buffer,
            CURLFORM_BUFFERLENGTH, len, CURLFORM_END);
    }
}

int uv_request_set_timeout(uv_request_t* request, long timeout)
{
    if (!request) {
        return -EINVAL;
    }

    return curl_easy_setopt(request->easy_handle, CURLOPT_TIMEOUT_MS, timeout);
}

static int download_progress_callback(void* clientp,
    curl_off_t dltotal, curl_off_t dlnow,
    curl_off_t ultotal, curl_off_t ulnow)
{
    uv_request_t* request = (uv_request_t*)clientp;
    if (!request) {
        return -1;
    }

    if (request->progress_cb != NULL) {
        return request->progress_cb(request, (off_t)dltotal, (off_t)dlnow, (off_t)ultotal, (off_t)ulnow);
    }
    return 0;
}

int uv_request_set_atrribute(uv_request_t* request, int type, void* data)
{
    struct curl_httppost* formpost = NULL;
    struct curl_httppost* lastptr = NULL;

    if (!request) {
        return -EINVAL;
    }

    switch (type) {
    case UV_REQUEST:
        curl_easy_setopt(request->easy_handle, CURLOPT_WRITEFUNCTION, save_request_body);
        curl_easy_setopt(request->easy_handle, CURLOPT_WRITEDATA, request);
        break;
    case UV_DOWNLOAD:
        if (data == NULL) {
            return -EINVAL;
        }
        request->response.body = (char*)strdup(data);
        request->fd = mkfile(data);
        if (request->fd == NULL) {
            return -EMFILE;
        }
        curl_easy_setopt(request->easy_handle, CURLOPT_WRITEDATA, request->fd);
        break;
    case UV_DOWNLOAD_PROGRESS:
        request->progress_cb = data;
        curl_easy_setopt(request->easy_handle, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(request->easy_handle, CURLOPT_XFERINFOFUNCTION, download_progress_callback);
        curl_easy_setopt(request->easy_handle, CURLOPT_XFERINFODATA, request);
        break;
    case UV_UPLOAD:
        if (data == NULL) {
            return -EINVAL;
        }
        request->response.body = (char*)strdup(data);
        curl_formadd(&formpost, &lastptr,
            CURLFORM_COPYNAME, "filename",
            CURLFORM_FILE, data,
            CURLFORM_END);
        curl_easy_setopt(request->easy_handle, CURLOPT_HTTPPOST, formpost);
        break;
    case UV_UPLOAD_TASK:
        if (data == NULL) {
            return -EINVAL;
        }
        curl_easy_setopt(request->easy_handle, CURLOPT_WRITEFUNCTION, save_request_body);
        curl_easy_setopt(request->easy_handle, CURLOPT_WRITEDATA, request);
        curl_easy_setopt(request->easy_handle, CURLOPT_HTTPPOST, request->formpost);
        break;
    default:
        return -EINVAL;
    }

    return 0;
}

static size_t __curl_header_cb(char* contents, size_t size, size_t nmemb, void* userdata)
{
    uv_request_t* request = (uv_request_t*)userdata;
    size_t realsize = size * nmemb;

    request->header.data = realloc(request->header.data, request->header.size + realsize + 1);
    if (!request->header.data) {
        return 0;
    }

    memcpy(&(request->header.data[request->header.size]), contents, realsize);
    request->response.headers = (char*)request->header.data;
    request->header.size += realsize;
    request->header.data[request->header.size] = '\0';
    return realsize;
}

int uv_request_commit(uv_request_session_t* handle, uv_request_t* request, uv_request_cb cb)
{
    if (!handle || !request || !cb) {
        return -EINVAL;
    }

    request->header_list = curl_slist_append(request->header_list, "Expect:");
    curl_easy_setopt(request->easy_handle, CURLOPT_HTTPHEADER, request->header_list);
    request->cb = cb;
    if (cb) {
        curl_multi_setopt(handle->multi_handle, CURLMOPT_SOCKETDATA, handle);
        curl_multi_setopt(handle->multi_handle, CURLMOPT_SOCKETFUNCTION, handle_socket);
        curl_multi_setopt(handle->multi_handle, CURLMOPT_TIMERDATA, handle);
        curl_multi_setopt(handle->multi_handle, CURLMOPT_TIMERFUNCTION, start_timeout);
    } else {
        curl_multi_setopt(handle->multi_handle, CURLMOPT_SOCKETFUNCTION, NULL);
        curl_multi_setopt(handle->multi_handle, CURLMOPT_TIMERFUNCTION, NULL);
    }

    curl_easy_setopt(request->easy_handle, CURLOPT_TCP_KEEPALIVE, 0L);
    curl_easy_setopt(request->easy_handle, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(request->easy_handle, CURLOPT_HEADERFUNCTION, __curl_header_cb);
    curl_easy_setopt(request->easy_handle, CURLOPT_HEADERDATA, request);
    curl_easy_setopt(request->easy_handle, CURLOPT_URL, request->url);
    curl_easy_setopt(request->easy_handle, CURLOPT_PRIVATE, (void*)request);
    curl_easy_setopt(request->easy_handle, CURLOPT_ACCEPT_ENCODING, "gzip");

    request->handle = handle;

    if (handle->connections_cnt < CONFIG_UV_REQUEST_MAX_LINKS) {
        request_debug("start download: %p", request);
        curl_multi_add_handle(handle->multi_handle, request->easy_handle);
        handle->connections_cnt++;
    } else {
        request_debug("join the waiting queue: %p", request);
        list_initialize(&request->node);
        list_add_tail(&handle->list, &request->node);
    }

    if (!cb) {
        check_multi_info(&handle->multi_handle);
    }

    return 0;
}

int uv_request_get_header(uv_request_t* request)
{
    if (!request) {
        return -EINVAL;
    };

    curl_easy_setopt(request->easy_handle, CURLOPT_HEADER, 1L);

    return 0;
}

char* uv_request_escape(uv_request_t* request, const void* data, ssize_t size)
{
    return curl_easy_escape(request->easy_handle, (const char*)data, size);
}

int uv_request_set_data(uv_request_t* request, const void* data, ssize_t size)
{
    if (!request || !data) {
        return -EINVAL;
    };

    curl_easy_setopt(request->easy_handle, CURLOPT_POSTFIELDSIZE, size);
    curl_easy_setopt(request->easy_handle, CURLOPT_POSTFIELDS, data);

    return 0;
}

int uv_request_append_header(uv_request_t* request, const char* header)
{
    if (!request || !header) {
        return -EINVAL;
    }

    request->header_list = curl_slist_append(request->header_list, header);

    return 0;
}

int uv_request_set_userp(uv_request_t* request, void* userp)
{
    if (!request) {
        return -EINVAL;
    }

    request->response.userp = userp;

    return 0;
}

void* uv_request_get_userp(uv_request_t* request)
{
    return request->response.userp;
}

static void __uv_time_close(uv_handle_t* handle)
{
    uv_request_session_t* session = (uv_request_session_t*)handle->data;
    curl_multi_cleanup(session->multi_handle);
    free(session);
}

int uv_request_close(uv_request_session_t* handle)
{
    if (!handle) {
        return -EINVAL;
    }

    uv_close((uv_handle_t*)&handle->timeout, __uv_time_close);

    return 0;
}
