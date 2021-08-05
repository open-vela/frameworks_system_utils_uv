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
#include <stdlib.h>
#include <uv_ext.h>
#include <uORB/uORB.h>
#include <uORB/uORBTopics.h>
#include <system/state.h>

/****************************************************************************
 *  Explanation: Because there is no actual driver, there is no way to use
 *  topic to get the corresponding data. This file simulates the push data of
 *  the underlying driver, realizes the simulated topic data, and is used for
 *  debugging of related topic interfaces. In the case of actual driver
 *  implementation, these functions, including the entire file, should not be
 *  deleted. (Note that the declaration in uv_ext.h should also be deleted.)
 ****************************************************************************/

#define TOPIC_ADVFD_MAX 4

typedef struct topicadv {
  uv_timer_t timer_handle;
  int fd[TOPIC_ADVFD_MAX];
  int cref;
} topicadv_t;

static topicadv_t topicadv = {0};

static bool change = false;
static struct network_state adv1 = {.type = 1};
static struct battery_state adv2 = {.state = 1};
static struct wear_state    adv3 = {.wear = 1};
static struct sleep_state   adv4 = {.sleep = 1};

static void timer_advertise_cb(uv_timer_t* handle) {
  if (change) {
    adv1.type  = 2;
    adv2.state = 2;
    adv3.wear  = 2;
    adv4.sleep = 2;
  } else {
    adv1.type  = 1;
    adv2.state = 1;
    adv3.wear  = 1;
    adv4.sleep = 1;
  }

  orb_publish(ORB_ID(network_state), topicadv.fd[0], &adv1);
  orb_publish(ORB_ID(battery_state), topicadv.fd[1], &adv2);
  orb_publish(ORB_ID(wear_state),    topicadv.fd[2], &adv3);
  orb_publish(ORB_ID(sleep_state),   topicadv.fd[3], &adv4);
  change =!change;
}

int uv_topicadv_init(uv_loop_t *loop) {
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

    ret = uv_timer_init(loop, &topicadv.timer_handle);
    if (ret != 0) {
      break;
    }

    ret = uv_timer_start(&topicadv.timer_handle, timer_advertise_cb, 0, 5000);
    if (ret != 0) {
      uv_timer_stop(&topicadv.timer_handle);
      return ret;
    }

    return 0;
  } while(0);

  for (i = 0; i <= topicadv.cref; i++) {
    orb_unadvertise(topicadv.fd[i]);
  }

  memset(&topicadv, 0, sizeof(topicadv));
  return ret;
}

int uv_topicadv_close(void) {
  int ret, i;

  if (--topicadv.cref > 0) {
    return 0;
  }

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
