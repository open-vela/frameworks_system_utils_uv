#include "assert.h"
#include "stdio.h"
#include "stdlib.h"
#include "string.h"
#include "uv/tree.h"
#include "uv_ext.h"
#include <unistd.h>

typedef void (*uv_ncm_cb_t)(int, const char*, void*);

RB_HEAD(file_cache_tree_s, file_cache_s);

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
    file_cache_t* cache;
} download_t;

typedef struct uv_ncm_s {
    uv_loop_t* loop;
    char* cache_path;
    uv_request_session_t* handle;
    struct file_cache_tree_s file_cache_tree;
} uv_ncm_t;

static int file_cache_cmp(file_cache_t* a, file_cache_t* b)
{
    return strcasecmp(a->url, b->url);
}

static int unlink_recursive(FAR char *path)
{
  struct dirent *d;
  struct stat stat;
  size_t len;
  int ret;
  DIR *dp;

  ret = lstat(path, &stat);
  if (ret < 0)
    {
      return ret;
    }

  if (!S_ISDIR(stat.st_mode))
    {
      return unlink(path);
    }

  dp = opendir(path);
  if (dp == NULL)
    {
      return -1;
    }

  len = strlen(path);
  if (len > 0 && path[len - 1] == '/')
    {
      path[--len] = '\0';
    }

  while ((d = readdir(dp)) != NULL)
    {
      if (strcmp(d->d_name, ".") == 0 || strcmp(d->d_name, "..") == 0)
        {
          continue;
        }

      snprintf(&path[len], PATH_MAX - len, "/%s", d->d_name);
      ret = unlink_recursive(path);
      if (ret < 0)
        {
          closedir(dp);
          return ret;
        }
    }

  ret = closedir(dp);
  if (ret >= 0)
    {
      path[len] = '\0';
      ret = rmdir(path);
    }

  return ret;
}

RB_GENERATE_STATIC(file_cache_tree_s, file_cache_s, tree_entry, file_cache_cmp);

uv_ncm_t* uv_ncm_init(uv_loop_t* loop, const char* cache_path)
{
    struct uv_ncm_s* ncm;
    assert(cache_path);
    assert(loop);

    ncm = calloc(1, sizeof(struct uv_ncm_s));
    assert(ncm);
    ncm->cache_path = strdup(cache_path);
    assert(ncm->cache_path);
    ncm->loop = loop;
    unlink_recursive(ncm->cache_path);
    uv_request_init(loop, &ncm->handle);
    return ncm;
}

static int is_path(const char* path)
{
    return strncmp("http", path, 4);
}

const char* uv_ncm_get_cache(uv_ncm_t* ncm, const char* path)
{
    file_cache_t cache = { 0 };
    file_cache_t* ret;

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

    return (const char*)ret->path;
}

static char* download_file_cb(int state, uv_response_t* response)
{
    download_t* download = (download_t*)response->userp;
    download_t** download_list = download->cache->download_list;
    int download_nums = download->cache->download_nums;

    download->cache->download_nums = 0;
    download->cache->download_list = NULL;
    download->cache->ready = true;

    if (state != UV_REQUEST_DONE) {
        if (download->cb != NULL) {
            download->cb(response->httpcode, NULL, (void*)download->userp);
        }
        free(download);
        return NULL;
    }

    for (int i = 0; i < download_nums; i++) {
        if (download_list == NULL) {
            break;
        }
        download = download_list[i];
        if (download->cb != NULL) {
            download->cb(UV_REQUEST_DONE, response->body, (void*)download->userp);
        }
        free(download);
    }
    free(download_list);
    return NULL;
}

static int checkpath(const char* path)
{
    const char s[] = "/";
    char* data;
    char* token;
    int res;

    res = access(path, F_OK);
    if (res == 0) {
        return 0;
    }

    data = strdup(path);
    if (data == NULL) {
        return -ENOMEM;
    }

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

static int download_file(uv_ncm_t* ncm, const char* url, uv_ncm_cb_t cb,
     void* userp, file_cache_t** handle)
{
    char* temp_path;
    download_t* download = calloc(1, sizeof(download_t));
    download->cb = cb;
    download->userp = userp;
    download->ncm = ncm;
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
        *handle = download->cache;
        return 0;
    } else {
        download->cache->download_nums++;
        download->cache->download_list = realloc(download->cache->download_list,
            download->cache->download_nums * sizeof(download_t*));
        download->cache->download_list[download->cache->download_nums - 1] = download;
    }

    uv_request_create(&download->request);
    uv_request_set_url(download->request, url);
    uv_request_set_userp(download->request, download);

    temp_path = (char*)malloc(PATH_MAX);
    if (temp_path == NULL) {
        return -1;
    }

    strcpy(temp_path, ncm->cache_path);
    checkpath(temp_path);
    strcat(temp_path, "/ncm_XXXXXX");
    int fd = mkstemp(temp_path);
    close(fd);
    if (fd < 0) {
        free(temp_path);
        return -1;
    }
    download->cache->path = strdup(temp_path);
    free(temp_path);
    int res = uv_request_set_atrribute(download->request, UV_DOWNLOAD,
        (void*)download->cache->path);
    if (res != 0) {
        return -1;
    }

    uv_request_commit(ncm->handle, download->request, (uv_request_cb)download_file_cb);
    *handle = download->cache;
    return 0;
}

uv_ncm_res_t uv_ncm_get_resource(uv_ncm_t* ncm, const uv_ncm_cfg_t* cfg, uv_ncm_handle_t* handle)
{
    file_cache_t* cache = NULL;
    int res;
    if (ncm == NULL) {
        return UV_NCM_RES_ERROR;
    }

    if (is_path(cfg->path)) {
        *cfg->res_path = cfg->path;
        return UV_NCM_RES_LOCAL_PATH;
    }

    const char* ret = uv_ncm_get_cache(ncm, cfg->path);
    if (ret) {
        *cfg->res_path = ret;
        return UV_NCM_RES_CACHE_HIT;
    }

    res = download_file(ncm, cfg->path, cfg->cb, cfg->userp, &cache);
    *handle = (void*)cache;
    if (res != 0) {
        return UV_NCM_RES_ERROR;
    }

    return UV_NCM_RES_DOWNLOAD_START;
}

void uv_ncm_cancel(uv_ncm_handle_t handle)
{
    if (handle == NULL) {
        return;
    }

    download_t* download;
    file_cache_t* cache = (file_cache_t*)handle;
    download_t** download_list = cache->download_list;
    int download_nums = cache->download_nums;

    if (cache->ready == true){
        return;
    }

    for (int i = 0; i < download_nums; i++) {
        if (download_list == NULL) {
            break;
        }
        download = download_list[i];
        download->cb = NULL;
    }
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
        for (int i = 0; i < cache->download_nums; i++) {
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

void uv_ncm_cfg_init(uv_ncm_cfg_t* cfg)
{
    memset(cfg, 0, sizeof(uv_ncm_cfg_t));
}
