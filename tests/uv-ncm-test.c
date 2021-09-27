#include <uv_ext.h>

const char *url[] = {"http://www.baidu.com", "https://www.baidu.com",
                     "http://httpbin.org/get",
                     "http://httpbin.org/post"
                     "http://httpbin.org/image/webp"};

void test1_cb(int status, const char *path, void *userp) {

  if (status != 0) {
    printf("download error\n");
  } else {
    printf("path:%s\n", path);
  }
}

void test_case1(void) {
  uv_loop_t *loop = malloc(sizeof(uv_loop_t));
  uv_loop_init(loop);
  uv_ncm_t *ncm = uv_ncm_init(loop, "/data/quickapp/cache");

  const char *ret ;
  uv_ncm_get_resource(ncm, &ret, url[0], test1_cb, ncm);
  printf("path:%s\n", ret);

  uv_ncm_get_resource(ncm, &ret, url[0], test1_cb, ncm);
  printf("path:%s\n", ret);

  uv_ncm_get_resource(ncm, &ret, url[1], test1_cb, ncm);
  printf("path:%s\n", ret);

  uv_ncm_get_resource(ncm, &ret, url[1], test1_cb, ncm);
  printf("path:%s\n", ret);

  uv_ncm_get_resource(ncm, &ret, url[2], test1_cb, ncm);
  printf("path:%s\n", ret);

  uv_run(loop, UV_RUN_DEFAULT);
  uv_loop_close(loop);
  free(loop);
}

void test2_cb(int status, const char *path, void *userp) {
  printf("path:%s\n", path);
}

void test_case2(void) {
  const char *ret;
  uv_loop_t *loop = malloc(sizeof(uv_loop_t));
  uv_loop_init(loop);
  uv_ncm_t *ncm = uv_ncm_init(loop, "quickapp/cache");

  uv_ncm_get_resource(ncm, &ret, url[0], NULL, ncm);
  printf("path:%s\n", ret);
  uv_ncm_get_resource(ncm, &ret, url[0], NULL, ncm);
  printf("path:%s\n", ret);
  uv_ncm_get_resource(ncm, &ret, url[1], NULL, ncm);
  printf("path:%s\n", ret);
  uv_ncm_get_resource(ncm, &ret, url[2], NULL, ncm);
  printf("path:%s\n", ret);
  uv_ncm_get_resource(ncm, &ret, url[3], NULL, ncm);
  printf("path:%s\n", ret);

  uv_run(loop, UV_RUN_DEFAULT);
  uv_ncm_close(ncm);
  uv_loop_close(loop);
  free(loop);
}

void test3_cb(int status, const char *path, void *userp) {
  printf("path:%s\n", path);
}

void timer_cb(uv_timer_t *handle) {
  static int cnt = 0;
  uv_ncm_t *ncm = (uv_ncm_t *)handle->data;
  const char * ret = NULL;

  if (++cnt == 6) {
    uv_timer_stop(handle);
    return ;
  }

  if (cnt >= 3) {
      uv_ncm_close(ncm);
      uv_timer_stop(handle);
      return ;
  }

  uv_ncm_get_resource(ncm, &ret, url[cnt % 3], test3_cb, ncm);
  printf("path:%s\n", ret);
}

void test_case3(void) {
  uv_timer_t timer;
  uv_ncm_t *ncm;
  uv_loop_t *loop;

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

int main(void) {

  printf("====== case1 =====\n");
  test_case1();

  printf("====== case2 =====\n");
  test_case2();

  printf("====== case3 =====\n");
  test_case3();

  return 0;
}
