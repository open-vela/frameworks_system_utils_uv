#include "assert.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "uv/tree.h"
#include "uv_ext.h"
#include <unistd.h>

typedef void (*uv_ncm_cb_t)(int, const char*, void*);

RB_HEAD(file_cache_tree_s, file_cache_s);

typedef struct cache_manager uv_ncm_t;
typedef struct download_s download_t;

typedef struct file_cache_s {
    char* url;
    char* path;
    bool ready;
    int download_nums;
    download_t** download_list;
    RB_ENTRY(file_cache_s)
    tree_entry;
} file_cache_t;

typedef struct download_s {
    uv_ncm_cb_t cb;
    uv_ncm_t* ncm;
    void* userp;
    uv_request_t* request;
    char* fallback;
    file_cache_t* cache;
} download_t;

typedef struct cache_manager {
    uv_loop_t* loop;
    char* cache_path;
    uv_request_session_t* handle;
    struct file_cache_tree_s file_cache_tree;
} uv_ncm_t;

static int file_cache_cmp(file_cache_t* a, file_cache_t* b)
{
    return strcasecmp(a->url, b->url);
}

RB_GENERATE_STATIC(file_cache_tree_s, file_cache_s, tree_entry, file_cache_cmp);

uv_ncm_t* uv_ncm_init(uv_loop_t* loop, const char* cache_path)
{
    struct cache_manager* ncm;
    assert(cache_path);
    assert(loop);

    if (access(cache_path, F_OK) != 0) {
        return NULL;
    }
    ncm = calloc(1, sizeof(struct cache_manager));
    assert(ncm);
    ncm->cache_path = strdup(cache_path);
    assert(ncm->cache_path);
    ncm->loop = loop;

    uv_request_init(loop, &ncm->handle);

    return ncm;
}

static int is_path(const char* path)
{
    int res = strncmp("http", path, 4);

    return res;
}

const char* uv_ncm_get_cache(uv_ncm_t* ncm, const char* path)
{
    file_cache_t cache = { 0 }, *ret;
    cache.url = (char*)path;
    if (ncm == NULL) {
        return NULL;
    }

    ret = RB_FIND(file_cache_tree_s, &ncm->file_cache_tree, &cache);
    if (ret == NULL) {
        return NULL;
    }
    if (ret->ready == false) {
        return NULL;
    }

    return (char*)ret->path;
}

char* download_file_cb(int state, uv_response_t* response)
{
    download_t* download = response->userp;
    download_t** download_list = download->cache->download_list;
    int download_nums = download->cache->download_nums;

    if (state != UV_REQUEST_DONE) {
        download->cb(response->httpcode, NULL, (void*)download->userp);
        free(download);
        return NULL;
    }

    download->cache->download_nums = 0;
    download->cache->download_list = NULL;
    download->cache->ready = true;
    if (download->cb == NULL) {
        free(download_list);
        free(download);
        return response->body;
    }

    download->cb(UV_REQUEST_DONE, response->body, (void*)download->userp);
    for (size_t i = 0; i < download_nums; i++) {
        if (download_list == NULL) {
            break;
        }
        download_t* ret = download_list[i];
        ret->cb(UV_REQUEST_DONE, response->body, (void*)ret->userp);
        free(ret);
    }
    free(download_list);
    free(download);
    return NULL;
}

static char* download_file(uv_ncm_t* ncm, const char* url, char* fallback,
    uv_ncm_cb_t cb, void* userp)
{
    char *temp_path;
    download_t* download = calloc(1, sizeof(download_t));
    download->cb = cb;
    download->userp = userp;
    download->ncm = ncm;
    download->fallback = fallback;
    download->cache = calloc(1, sizeof(file_cache_t));
    download->cache->url = strdup(url);

    file_cache_t* cache;
    cache = RB_INSERT(file_cache_tree_s, &download->ncm->file_cache_tree,
        download->cache);
    if (cache != NULL) {
        cache->download_nums++;
        cache->download_list = realloc(cache->download_list,
            cache->download_nums * sizeof(download_t*));
        cache->download_list[cache->download_nums - 1] = download;
        return (char*)download->fallback;
    }

    uv_request_create(&download->request);
    uv_request_set_url(download->request, url);
    uv_request_set_userp(download->request, download);

    temp_path = (char *)malloc(PATH_MAX);
    if (temp_path == NULL) {
        return NULL;
    }

    strcpy(temp_path, ncm->cache_path);
    strcat(temp_path, "/ncm_XXXXXX");
    int fd = mkstemp(temp_path);
    close(fd);
    if (fd < 0) {
        free(temp_path);
        return NULL;
    }
    download->cache->path = strdup(temp_path);
    free(temp_path);
    int res = uv_request_set_atrribute(download->request, UV_DOWNLOAD,
        (void*)download->cache->path);
    if (res != 0) {
        return NULL;
    }

    uv_request_commit(ncm->handle, download->request, (uv_request_cb)download_file_cb);

    return fallback;
}

uv_ncm_res_t uv_ncm_get_resource(uv_ncm_t* ncm, const char** res_path, const char* path,
    uv_ncm_cb_t cb, void* userp)
{
    if (ncm == NULL) {
        return UV_NCM_RES_ERROR;
    }

    if (is_path(path)) {
        *res_path = path;
        return UV_NCM_RES_LOCAL_PATH;
    }

    const char* ret = uv_ncm_get_cache(ncm, path);
    if (ret) {
        *res_path = ret;
        return UV_NCM_RES_CACHE_HIT;
    }

    *res_path = download_file(ncm, path, NULL, cb, userp);
    if (*res_path == NULL) {
        return UV_NCM_RES_ERROR;
    }

    return UV_NCM_RES_DOWNLOAD_START;
}

int uv_ncm_close(uv_ncm_t* ncm)
{
    if (ncm == NULL) {
        return -1;
    }

    file_cache_t *cache, *temp;

    RB_FOREACH_SAFE(cache, file_cache_tree_s, &ncm->file_cache_tree, temp)
    {
        unlink(cache->path);
        free(cache->path);
        free(cache->url);
        for (size_t i = 0; i < cache->download_nums; i++) {
            download_t* ret = cache->download_list[i];
            free(ret->cache->url);
            free(ret->cache);
            free(ret);
        }
        free(cache->download_list);
        RB_REMOVE(file_cache_tree_s, &ncm->file_cache_tree, cache);
        free(cache);
    }

    uv_request_close(ncm->handle);
    free((void*)ncm->cache_path);
    free(ncm);
    return 0;
}
