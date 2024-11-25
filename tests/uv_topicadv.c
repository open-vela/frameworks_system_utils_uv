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

#include <alloca.h>
#include <sensor/prox.h>
#include <stdlib.h>
#include <system/message.h>
#include <system/state.h>
#include <uORB/uORB.h>
#include <uv_ext.h>

/****************************************************************************
 *  Explanation: Because there is no actual driver, there is no way to use
 *  topic to get the corresponding data. This file simulates the push data of
 *  the underlying driver, realizes the simulated topic data, and is used for
 *  debugging of related topic interfaces. In the case of actual driver
 *  implementation, these functions, including the entire file, should not be
 *  deleted. (Note that the declaration in uv_ext.h should also be deleted.)
 ****************************************************************************/

#define TOPIC_ADVFD_MAX 7

MESSAGE_TYPE_DECLARE(system_update, 200);
MESSAGE_TYPE_DECLARE(system_screen, 20);

ORB_DEFINE(system_update, struct system_update, NULL);
ORB_DEFINE(system_screen, struct system_screen, NULL);

const char* system_update1 = "{\"curVer\": \"1.0.0\", \"newVer\": \"1.0.1\", \"desc\": \"update 1111\"}";
const char* system_update2 = "{\"curVer\": \"1.0.0\", \"newVer\": \"1.0.1\", \"desc\": \"update 2222\"}";
const char* system_screen1 = "{\"isOn\": \"true\"}";
const char* system_screen2 = "{\"isOn\": \"false\"}";

typedef struct topicadv {
    uv_timer_t timer_handle;
    int fd[TOPIC_ADVFD_MAX];
    int cref;
} topicadv_t;

static topicadv_t topicadv = { 0 };

static bool change = false;
struct network_state adv1 = { .type = 1 };
static struct battery_state adv2 = { .state = 1 };
static struct wear_state adv3 = { .wear = 1 };
static struct sleep_state adv4 = { .sleep = 1 };
static struct sensor_prox adv5 = { .proximity = 1.0f };
static struct system_update adv6 = { .name = "system_update", .json = "\0" };
static struct system_screen adv7 = { .name = "system_screen", .json = "\0" };

static void timer_advertise_cb(uv_timer_t* handle)
{
    if (change) {
        adv1.type = 2;
        adv2.state = 2;
        adv3.wear = 2;
        adv4.sleep = 2;
        adv5.proximity = 2.0f;
        strlcpy(adv6.json, system_update1, 200);
        strlcpy(adv7.json, system_screen1, 20);
    } else {
        adv1.type = 1;
        adv2.state = 1;
        adv3.wear = 1;
        adv4.sleep = 1;
        adv5.proximity = 1.0f;
        strlcpy(adv6.json, system_update2, 200);
        strlcpy(adv7.json, system_screen2, 20);
    }

    orb_publish(ORB_ID(network_state), topicadv.fd[0], &adv1);
    orb_publish(ORB_ID(battery_state), topicadv.fd[1], &adv2);
    orb_publish(ORB_ID(wear_state), topicadv.fd[2], &adv3);
    orb_publish(ORB_ID(sleep_state), topicadv.fd[3], &adv4);
    orb_publish(ORB_ID(sensor_prox), topicadv.fd[4], &adv5);
    orb_publish(ORB_ID(system_update), topicadv.fd[5], &adv6);
    orb_publish(ORB_ID(system_screen), topicadv.fd[6], &adv7);
    change = !change;
}

int uv_topicadv_init(uv_loop_t* loop)
{
    int ret, i;

    if (!loop) {
        return UV_EINVAL;
    }

    if (topicadv.cref > 0) {
        return 0;
    }

    do {
        /* network_state advertise. */
        topicadv.fd[topicadv.cref] = orb_advertise(ORB_ID(network_state), NULL);
        if (topicadv.fd[topicadv.cref] < 0) {
            ret = -errno;
            break;
        }

        /* battery_state advertise. */
        topicadv.fd[++topicadv.cref] = orb_advertise(ORB_ID(battery_state), NULL);
        if (topicadv.fd[topicadv.cref] < 0) {
            ret = -errno;
            break;
        }

        /* wear_state advertise. */
        topicadv.fd[++topicadv.cref] = orb_advertise(ORB_ID(wear_state), NULL);
        if (topicadv.fd[topicadv.cref] < 0) {
            ret = -errno;
            break;
        }

        /* sleep_state advertise. */
        topicadv.fd[++topicadv.cref] = orb_advertise(ORB_ID(sleep_state), NULL);
        if (topicadv.fd[topicadv.cref] < 0) {
            ret = -errno;
            break;
        }

        /* sensor_prox advertise. */
        topicadv.fd[++topicadv.cref] = orb_advertise(ORB_ID(sensor_prox), NULL);
        if (topicadv.fd[topicadv.cref] < 0) {
            ret = -errno;
            break;
        }

        /* system_update topic */
        topicadv.fd[++topicadv.cref] = orb_advertise(ORB_ID(system_update), NULL);
        if (topicadv.fd[topicadv.cref] < 0) {
            ret = -errno;
            break;
        }

        /* system_screen topic */
        topicadv.fd[++topicadv.cref] = orb_advertise(ORB_ID(system_screen), NULL);
        if (topicadv.fd[topicadv.cref] < 0) {
            ret = -errno;
            break;
        }

        ret = uv_timer_init(loop, &topicadv.timer_handle);
        if (ret != 0) {
            break;
        }

        ret = uv_timer_start(&topicadv.timer_handle, timer_advertise_cb, 0, 2000);
        if (ret != 0) {
            uv_timer_stop(&topicadv.timer_handle);
            return ret;
        }

        return 0;
    } while (0);

    for (i = 0; i <= topicadv.cref; i++) {
        orb_unadvertise(topicadv.fd[i]);
    }

    memset(&topicadv, 0, sizeof(topicadv));
    return ret;
}

int uv_topicadv_close(void)
{
    int ret, i;

    if (topicadv.cref == 0) {
        return 0;
    }

    topicadv.cref = 0;

    ret = uv_timer_stop(&topicadv.timer_handle);
    if (ret != 0) {
        return ret;
    }

    for (i = 0; i < TOPIC_ADVFD_MAX; i++) {
        orb_unadvertise(topicadv.fd[i]);
    }

    memset(&topicadv, 0, sizeof(topicadv));
    return 0;
}
