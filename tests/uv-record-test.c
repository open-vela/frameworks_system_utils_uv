
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

#include <semaphore.h>
#include <stdlib.h>
#include <syslog.h>
#include <time.h>
#include <uv_ext.h>

#define UV_RECORD_TEST_PACKNAME "uv_record_test"
#define UV_RECORD_TEST_FILEPATH "/data/recordtest.wav"
#define UV_RECORD_TEST_OPTIONS "format=wav:sample_rate=44100:channel_layout=stereo"
#define UV_RECORD_TEST_HANDLE_START 1
#define UV_RECORD_TEST_HANDLE_END 2

typedef struct {
    sem_t resultwait;
    uv_record_ops_t* ops;
    void* handle;
    int handlestate; // record handle
    int recordstate; // open (prepare, start)
} uv_record_test_t;

void* tets;

void uv_record_callback(void* data, int event, int status, void* result)
{
    uv_record_test_t* th = (uv_record_test_t*)data;

    switch (event) {
    case UV_RECORDER_EVENT_OPEN: {
        int val = 0;

        if (status == 0) {
            th->handle = result;
        }
        th->handlestate = UV_RECORD_TEST_HANDLE_END;
        sem_getvalue(&th->resultwait, &val);
        if (val < 0) {
            sem_post(&th->resultwait);
        }
        syslog(LOG_DEBUG, "[%s %d] record open event, status = %d\n", __func__, __LINE__, status);
    } break;

    case UV_RECORDER_EVENT_PREPARE:
        syslog(LOG_DEBUG, "[%s %d] record prepare event, status = %d\n", __func__, __LINE__, status);
        break;

    case UV_RECORDER_EVENT_START:
        syslog(LOG_DEBUG, "[%s %d] record start event, status = %d\n", __func__, __LINE__, status);
        break;

    case UV_RECORDER_EVENT_STOP:
        syslog(LOG_DEBUG, "[%s %d] record stop event, status = %d\n", __func__, __LINE__, status);
        break;

    case UV_RECORDER_EVENT_READ:
        syslog(LOG_DEBUG, "[%s %d] record read event, status = %d\n", __func__, __LINE__, status);
        break;

    case UV_RECORDER_EVENT_PAUSE:
        syslog(LOG_DEBUG, "[%s %d] record pause event, status = %d\n", __func__, __LINE__, status);
        break;

    default:
        syslog(LOG_DEBUG, "[%s %d] record default event, status = %d\n", __func__, __LINE__, status);
        return;
    }
}

int main(int argc, char** argv)
{
    int ret;
    struct timespec ts = { 0 };

    uv_record_test_t* recordhd = (uv_record_test_t*)malloc(sizeof(uv_record_test_t));
    if (!recordhd) {
        syslog(LOG_DEBUG, "[%s %d] reocrd struct malloc fail.\n", __func__, __LINE__);
        return UV_ENOMEM;
    }

    memset(recordhd, 0, sizeof(uv_record_test_t));

    do {
        recordhd->ops = uv_record_init();
        if (!recordhd->ops) {
            syslog(LOG_DEBUG, "[%s %d] uv_record_play_init fail.\n", __func__, __LINE__);
            break;
        }

        if (!(recordhd->ops->uv_record_open && recordhd->ops->uv_record_prepare
                && recordhd->ops->uv_record_start && recordhd->ops->uv_record_stop
                && recordhd->ops->uv_record_pause && recordhd->ops->uv_record_close
                && recordhd->ops->uv_record_read_data)) {
            syslog(LOG_DEBUG, "[%s %d] record ops function error.\n", __func__, __LINE__);
            break;
        }

        ret = sem_init(&recordhd->resultwait, 0, 0);
        if (ret < 0) {
            break;
        }

        clock_gettime(CLOCK_REALTIME, &ts);
        ts.tv_sec += 5;
        ts.tv_nsec = 0;

        recordhd->handlestate = UV_RECORD_TEST_HANDLE_START;
        recordhd->ops->uv_record_open(uv_record_callback, recordhd, UV_RECORD_TEST_PACKNAME);
        if (recordhd->handlestate != UV_RECORD_TEST_HANDLE_END) {
            sem_timedwait(&recordhd->resultwait, &ts);
        }

        if (recordhd->handle == NULL) {
            syslog(LOG_DEBUG, "[%s %d] get reocrd handle fail.\n", __func__, __LINE__);
            break;
        }

        recordhd->ops->uv_record_prepare(recordhd->handle, UV_RECORD_TEST_FILEPATH, UV_RECORD_TEST_OPTIONS);
        recordhd->ops->uv_record_start(recordhd->handle);

        syslog(LOG_DEBUG, "[%s %d] start recording(10s)...\n", __func__, __LINE__);
        sleep(10);

        recordhd->ops->uv_record_close(recordhd->handle);
        free(recordhd);
        syslog(LOG_DEBUG, "[%s %d] PASS.\n", __func__, __LINE__);
        return 0;
    } while (0);

    free(recordhd);
    syslog(LOG_DEBUG, "[%s %d] FAIL.\n", __func__, __LINE__);
    return 0;
}
