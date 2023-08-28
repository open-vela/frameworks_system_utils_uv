#include <uv_ext.h>

const char* url[] = { "http://www.baidu.com",
    "http://icanhazip.com",
    "http://httpbin.org/get",
    "http://httpbin.org/post"
    "http://httpbin.org/image/webp" };

void test1_cb(int status, const char* path, void* userp)
{

    if (status != 0) {
        printf("download error\n");
    } else {
        printf("path:%s\n", path);
    }
}

void test_case1(void)
{
    uv_loop_t* loop = malloc(sizeof(uv_loop_t));
    uv_loop_init(loop);
    uv_ncm_t* ncm = uv_ncm_init(loop, "/data/quickapp/cache");

    const char* ret;
    uv_ncm_handle_t handle;
    uv_ncm_cfg_t cfg = { &ret, url[0], test1_cb, ncm };

    uv_ncm_get_resource(ncm, &cfg, &handle);
    printf("path:%s\n", ret);

    uv_ncm_get_resource(ncm, &cfg, &handle);
    printf("path:%s\n", ret);

    uv_ncm_get_resource(ncm, &cfg, &handle);
    printf("path:%s\n", ret);

    uv_ncm_get_resource(ncm, &cfg, &handle);
    printf("path:%s\n", ret);

    uv_ncm_get_resource(ncm, &cfg, &handle);
    printf("path:%s\n", ret);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
    free(loop);
}

void test2_cb(int status, const char* path, void* userp)
{
    printf("path:%s\n", path);
}

void test_case2(void)
{
    const char* ret;
    uv_ncm_handle_t handle;
    uv_loop_t* loop;
    uv_ncm_t* ncm;

    loop = malloc(sizeof(uv_loop_t));
    uv_loop_init(loop);
    ncm = uv_ncm_init(loop, "quickapp/cache");

    uv_ncm_cfg_t cfg = { &ret, url[0], test2_cb, ncm };

    uv_ncm_get_resource(ncm, &cfg, &handle);
    printf("path:%s\n", ret);
    uv_ncm_get_resource(ncm, &cfg, &handle);
    printf("path:%s\n", ret);

    cfg.path = url[1];
    uv_ncm_get_resource(ncm, &cfg, &handle);
    printf("path:%s\n", ret);

    cfg.path = url[2];
    uv_ncm_get_resource(ncm, &cfg, &handle);
    printf("path:%s\n", ret);

    cfg.path = url[3];
    uv_ncm_get_resource(ncm, &cfg, &handle);
    printf("path:%s\n", ret);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_ncm_close(ncm);
    uv_loop_close(loop);
    free(loop);
}

void test3_cb(int status, const char* path, void* userp)
{
    printf("path:%s\n", path);
}

void timer_cb(uv_timer_t* handle)
{
    static int cnt = 0;
    uv_ncm_handle_t handle1;
    uv_ncm_t* ncm = (uv_ncm_t*)handle->data;
    const char* ret = NULL;
    uv_ncm_cfg_t cfg = { &ret, url[0], test3_cb, ncm };

    if (++cnt == 6) {
        uv_timer_stop(handle);
        return;
    }

    if (cnt >= 3) {
        uv_ncm_close(ncm);
        uv_timer_stop(handle);
        return;
    }

    cfg.path = url[cnt % 3];
    uv_ncm_get_resource(ncm, &cfg, &handle1);
    printf("path:%s\n", ret);
}

void test_case3(void)
{
    uv_timer_t timer;
    uv_ncm_t* ncm;
    uv_loop_t* loop;

    loop = malloc(sizeof(uv_loop_t));
    uv_loop_init(loop);
    ncm = uv_ncm_init(loop, "quickapp/cache");

    timer.data = ncm;
    uv_timer_init(loop, &timer);
    uv_timer_start(&timer, timer_cb, 0, 1000);

    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
    free(loop);
}

void test4_cb(int status, const char* path, void* userp)
{
    printf("path:%s\n", path);
}

void timer_cb2(uv_timer_t* handle)
{
    uv_ncm_cancel(handle->data);
}

void test_case4(void)
{
    uv_timer_t timer;
    uv_loop_t* loop = malloc(sizeof(uv_loop_t));
    uv_loop_init(loop);
    uv_ncm_t* ncm = uv_ncm_init(loop, "/data/quickapp/cache");

    const char* ret;
    uv_ncm_handle_t handle1, handle2;
    uv_ncm_cfg_t cfg = { &ret, url[0], test4_cb, ncm };

    uv_ncm_get_resource(ncm, &cfg, &handle1);
    printf("path:%s\n", ret);

    cfg.path = url[1];
    uv_ncm_get_resource(ncm, &cfg, &handle2);
    printf("path:%s\n", ret);

    uv_timer_init(loop, &timer);
    timer.data = handle2;
    uv_timer_start(&timer, timer_cb2, 0, 0);
    uv_run(loop, UV_RUN_DEFAULT);
    uv_loop_close(loop);
    free(loop);
}

int main(void)
{

    printf("====== case1 =====\n");
    test_case1();

    printf("====== case2 =====\n");
    test_case2();

    printf("====== case3 =====\n");
    test_case3();

    printf("====== case4 =====\n");
    test_case4();

    return 0;
}
