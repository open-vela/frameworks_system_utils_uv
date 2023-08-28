
#include "uv_ext.h"

void print_fingerprint(uint8_t* data)
{
    if (data == NULL) {
        return;
    }

    printf("\nfingerprint(SHA1) is : \n");

    for (size_t i = 0; i < 20; i++) {
        printf("%02x:", (uint8_t)data[i]);
    }

    printf("\b \n\n");
}

int main(int argc, char* argv[])
{
    app_verify_t* app_verify_info;
    int res;

    app_verify_info = app_verify_init("/data/app/demo.rpk", "/data/app/com.xiaomi.verify.demo");
    res = app_pre_unzip(app_verify_info, "Common/logo.png");
    if (res != 0) {
        printf("app_pre_unzip failed: %d\n", res);
        return -1;
    }

    res = app_verify_unzip(app_verify_info);
    if (res != 0) {
        printf("rpk verify fail\n");
        return -1;
    }
    printf("rpk verify success\n");

    uint8_t* fingerprint = app_get_fingerprint(app_verify_info);
    print_fingerprint(fingerprint);

    app_verify_close(app_verify_info);

    return 0;
}
