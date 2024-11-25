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

/****************************************************************************
 * Included Files
 ****************************************************************************/

#include <sensor/accel.h>
#include <stdlib.h>
#include <uORB/uORB.h>
#include <uv_ext.h>

static int senddatacount = 0;
static int recvcount = 0;
static uv_topic_t topic_t;
static int pfd0;

static void topic_cb(uv_topic_t* topic, int status, void* data, size_t datalen)
{
    struct sensor_accel* t_r = data;

    if (status == 0) {
        printf("timestamp=%lld temperature=%f\n", t_r->timestamp, t_r->temperature);
        printf("x=%f y=%f z=%f\n", t_r->x, t_r->y, t_r->z);
        recvcount++;
    } else {
        printf("topic_cb status = %d\n", status);
    }
}

static void timer_run_cb(uv_timer_t* handle)
{
    struct sensor_accel t;

    t.timestamp = orb_absolute_time();
    t.temperature = 10;
    t.x = 111;
    t.y = 222;
    t.z = 235;

    /* publish test data */

    if (orb_publish(ORB_ID(sensor_accel), pfd0, &t) < 0) {
        printf("orb_publish fail. ");
    }

    if (++senddatacount == 10) {
        uv_close((uv_handle_t*)handle, NULL);
        uv_topic_unsubscribe(&topic_t);
        uv_stop(uv_default_loop());
    }

    printf("time_cb senddatacount = %d\n", senddatacount);
}

int main(int argc, char* argv[])
{
    uv_loop_t* loop = uv_default_loop();
    uv_timer_t timer_handle;

    /* advertise */

    pfd0 = orb_advertise(ORB_ID(sensor_accel), NULL);

    /* topic subscribe */

    if (uv_topic_subscribe(loop, &topic_t, ORB_ID(sensor_accel), topic_cb) < 0) {
        printf("uv_topic_subscribe fail.\n");
        goto testfail;
    }

    if (uv_topic_set_frequency(&topic_t, 1) != 0) {
        printf("uv_topic_set_frequency fail.\n");
        goto testfail;
    }

    /* Sends sensor data using the Timer loop */

    if (uv_timer_init(loop, &timer_handle) != 0) {
        goto testfail;
    }

    if (uv_timer_start(&timer_handle, timer_run_cb, 1, 1) != 0) {
        goto testfail;
    }

    uv_run(loop, UV_RUN_DEFAULT);

    printf("TEST PASSED !\n");
    exit(0);

testfail:
    printf("TEST FAILED !\n");
    exit(1);
}