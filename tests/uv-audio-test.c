
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

#include <fcntl.h>
#include <nuttx/mqueue.h>
#include <system/readline.h>
#include <uv_ext.h>

#ifdef CONFIG_MIWEAR_APPS_FRAMEWORKS

// #define UV_AUDIO_TEST_CTRL

#define UV_AUDIO_TEST_STEP0 0
#define UV_AUDIO_TEST_STEP1 (UV_AUDIO_TEST_STEP0 + 1)
#define UV_AUDIO_TEST_STEP2 (UV_AUDIO_TEST_STEP1 + 1)
#define UV_AUDIO_TEST_STEP3 (UV_AUDIO_TEST_STEP2 + 1)
#define UV_AUDIO_TEST_STEP4 (UV_AUDIO_TEST_STEP3 + 1)
#define UV_AUDIO_TEST_STEP5 (UV_AUDIO_TEST_STEP4 + 1)
#define UV_AUDIO_TEST_STEP6 (UV_AUDIO_TEST_STEP5 + 1)
#define UV_AUDIO_TEST_STEP7 (UV_AUDIO_TEST_STEP6 + 1)
#define UV_AUDIO_TEST_STEP8 (UV_AUDIO_TEST_STEP7 + 1)
#define UV_AUDIO_TEST_STEP9 (UV_AUDIO_TEST_STEP8 + 1)
#define UV_AUDIO_TEST_STEP10 (UV_AUDIO_TEST_STEP9 + 1)
#define UV_AUDIO_TEST_STEP11 (UV_AUDIO_TEST_STEP10 + 1)
#define UV_AUDIO_TEST_STEP12 (UV_AUDIO_TEST_STEP11 + 1)
#define UV_AUDIO_TEST_STEP13 (UV_AUDIO_TEST_STEP12 + 1)
#define UV_AUDIO_TEST_STEP14 (UV_AUDIO_TEST_STEP13 + 1)
#define UV_AUDIO_TEST_STEP15 (UV_AUDIO_TEST_STEP14 + 1)

#define UV_AUDIO_TEST_CTRL_PREV 1
#define UV_AUDIO_TEST_CTRL_NEXT 2
#define UV_AUDIO_TEST_CTRL_PLAY 3
#define UV_AUDIO_TEST_CTRL_PAUSE 4
#define UV_AUDIO_TEST_CTRL_STOP 5
#define UV_AUDIO_TEST_CTRL_VLMUP 6
#define UV_AUDIO_TEST_CTRL_VLMDOWM 7
#define UV_AUDIO_TEST_CTRL_MUSIC 8

#define UV_AUDIO_TEST_QUEUE "uv_audio_test_queue"
#define UV_AUDIO_TEST_PACKNAME "uv_audio_test"
#ifdef UV_AUDIO_TEST_CTRL

static uv_audio_ctrl_t* ctrl_ops = NULL;
struct crtlcmd_s {
    char str[25];
    int cmd;
} crtlcmd[] = {
    { "prev", UV_AUDIO_TEST_CTRL_PREV },
    { "next", UV_AUDIO_TEST_CTRL_NEXT },
    { "play", UV_AUDIO_TEST_CTRL_PLAY },
    { "pause", UV_AUDIO_TEST_CTRL_PAUSE },
    { "stop", UV_AUDIO_TEST_CTRL_STOP },
    { "vlmup", UV_AUDIO_TEST_CTRL_VLMUP },
    { "vlmdown", UV_AUDIO_TEST_CTRL_VLMDOWM },
    { "music", UV_AUDIO_TEST_CTRL_MUSIC },
};

#else

static uv_poll_t uv_audio_test_poll;
static uv_audio_ops_t* ops = NULL;
static void* handle = NULL;
static uv_loop_t audiploop;

#endif

#ifdef UV_AUDIO_TEST_CTRL

void uv_audio_test_music_meta_cb(char* title,
    char* artist,
    char* album)
{
    if (title) {
        printf("title:%s\n", title);
    }

    if (artist) {
        printf("artist:%s\n", artist);
    }

    if (album) {
        printf("album:%s\n", album);
    }
}

static void audio_test_execute_cmd(char* cmd)
{
    int op = 0;
    int i;

    if (ctrl_ops == NULL) {
        return;
    }

    for (i = 0; i < sizeof(crtlcmd) / sizeof(crtlcmd[0]); i++) {
        if (strstr(cmd, crtlcmd[i].str)) {
            op = crtlcmd[i].cmd;
        }
    }

    if (op == 0) {
        return;
    }

    switch (op) {
    case UV_AUDIO_TEST_CTRL_PREV:
        ctrl_ops->uv_audio_ctrl_prevsong();
        break;

    case UV_AUDIO_TEST_CTRL_NEXT:
        ctrl_ops->uv_audio_ctrl_nextsong();
        break;

    case UV_AUDIO_TEST_CTRL_PLAY:
        ctrl_ops->uv_audio_ctrl_play();
        break;

    case UV_AUDIO_TEST_CTRL_PAUSE:
        ctrl_ops->uv_audio_ctrl_pause();
        break;

    case UV_AUDIO_TEST_CTRL_STOP:
        ctrl_ops->uv_audio_ctrl_stop();
        break;

    case UV_AUDIO_TEST_CTRL_VLMUP:
        ctrl_ops->uv_audio_ctrl_volumeup();
        break;

    case UV_AUDIO_TEST_CTRL_VLMDOWM:
        ctrl_ops->uv_audio_ctrl_volumedown();
        break;

    case UV_AUDIO_TEST_CTRL_MUSIC:
        ctrl_ops->uv_audio_ctrl_get_music_meta(uv_audio_test_music_meta_cb);
        break;
    }

    printf("ctrl op ======= %d\n", op);
}

static int audio_test_ctrl_tool(int argc, char* argv[])
{
    int len;
    char* buffer = malloc(CONFIG_NSH_LINELEN);

    if (!buffer) {
        return -ENOMEM;
    }

    ctrl_ops = uv_audio_ctrl_init();
    if (ctrl_ops == NULL) {
        free(buffer);
        return -1;
    }

    while (1) {
        printf("audio_test> ");
        fflush(stdout);

        len = readline_stream(buffer, CONFIG_NSH_LINELEN, stdin, stdout);
        buffer[len] = '\0';
        if (len < 0)
            continue;

        if (buffer[0] == '!') {
#ifdef CONFIG_SYSTEM_SYSTEM
            system(buffer + 1);
#endif
            continue;
        }

        if (buffer[len - 1] == '\n')
            buffer[len - 1] = '\0';

        audio_test_execute_cmd(buffer);
    }

    free(buffer);
}

#else

static void __audio_state_work_cb(uv_work_t* work)
{

    if (work && work->data) {
        printf("(%s %d) thread id is: %d, (data=%p)\n", __func__, __LINE__, uv_thread_self(), work->data);
    } else {
        printf("(%s %d) thread id is: %d\n", __func__, __LINE__, uv_thread_self());
    }
}

static void __audio_state_after_work_cb(uv_work_t* req, int status)
{
    if (req) {
        free(req);
    }

    printf("(%s %d) thread id is: %d\n", __func__, __LINE__, uv_thread_self());
}

static void uv_audio_callback_cb(void* data, int event, int status, void* result)
{
    uv_audio_mqmessage_t message = { 0 };

    if (status != 0) {
        printf("audio event fail. event=%x status=%d\n", event, status);
        return;
    }

    printf("audio event cb. event=%x status=%d\n", event, status);

    switch (event) {
    case UV_AUDIO_EVENT_ERROR:
        printf("uv_audio_callback_cb:UV_AUDIO_EVENT_ERROR\n");
        break;

    case UV_AUDIO_EVENT_OPEN:
        if (!handle) {
            handle = result;
            return;
        }
        break;

    case UV_AUDIO_EVENT_PREPARE:
        printf("uv_audio_callback_cb:UV_AUDIO_EVENT_PREPARE\n");
        break;

    case UV_AUDIO_EVENT_START:
        printf("uv_audio_callback_cb:UV_AUDIO_EVENT_START\n");
        break;

    case UV_AUDIO_EVENT_PAUSE:
        printf("uv_audio_callback_cb:UV_AUDIO_EVENT_PAUSE\n");
        break;

    case UV_AUDIO_EVENT_STOP:
        printf("uv_audio_callback_cb:UV_AUDIO_EVENT_STOP\n");
        break;

    case UV_AUDIO_EVENT_GET_VOLUME:
        printf("uv_audio_callback_cb:UV_AUDIO_EVENT_GET_VOLUME(%d)\n", *(int*)result);
        break;

    case UV_AUDIO_EVENT_GET_POSITION:
        printf("uv_audio_callback_cb:UV_AUDIO_EVENT_GET_POSITION(%u)\n", *(unsigned int*)result);
        break;

    case UV_AUDIO_EVENT_GET_DURATION:
        printf("uv_audio_callback_cb:UV_AUDIO_EVENT_GET_DURATION(%u)\n", *(unsigned int*)result);
        break;

    case UV_AUDIO_EVENT_PLAY_STATE:
        printf("uv_audio_callback_cb:UV_AUDIO_EVENT_PLAY_STATE(%d)\n", *(int*)result);
        break;

    case UV_AUDIO_EVENT_COMPLETE:
        printf("uv_audio_callback_cb:UV_AUDIO_EVENT_COMPLETE\n");
        break;

    case UV_AUDIO_EVENT_SEEK:
        printf("uv_audio_callback_cb:UV_AUDIO_EVENT_SEEK\n");
        break;

    case UV_AUDIO_EVENT_VOLUMECHANGE:
        printf("uv_audio_callback_cb:UV_AUDIO_EVENT_VOLUMECHANGE\n");
        break;

    case UV_AUDIO_EVENT_ALLSTATE: {
        uv_audio_allstate_t* info = (uv_audio_allstate_t*)result;

        printf("src:%s\n", info->src);
        printf("autoplay:%d\n", info->autoplay);
        printf("loop:%d\n", info->loop);
        printf("muted:%d\n", info->muted);
        printf("volume:%d\n", info->volume);
        printf("state:%d\n", info->state);
        printf("currenttime:%d\n", info->currenttime);
        printf("duration:%d\n", info->duration);
        printf("data:(p=%p)\n", info->data);

        message.data = info->data;
        break;
    }
    }

    message.status = event;
    uv_audio_async_messgae_send(UV_AUDIO_TEST_QUEUE, &message);
}

static void audio_timer_run_cb(uv_timer_t* tim_handle)
{
    char* p = (char*)malloc(50);
    static int step = 0;

    if (p == NULL) {
        return;
    }

    printf("state malloc info:(p=%p)\n", p);

    switch (step) {
    case UV_AUDIO_TEST_STEP0:
        ops->uv_audio_play_set_volume(handle, 0.5);
        ops->uv_audio_play_pause(handle);
        ops->uv_audio_play_state(handle);
        break;

    case UV_AUDIO_TEST_STEP1:
        ops->uv_audio_play_start(handle);
        ops->uv_audio_play_allstate(handle, p);
        break;

    case UV_AUDIO_TEST_STEP2:
        ops->uv_audio_play_set_loop(handle, 1);
        ops->uv_audio_play_allstate(handle, p);
        break;

    case UV_AUDIO_TEST_STEP3:
        ops->uv_audio_play_get_volume(handle);
        ops->uv_audio_play_allstate(handle, p);
        break;

    case UV_AUDIO_TEST_STEP4:
        ops->uv_audio_play_set_volume(handle, 0.8);
        ops->uv_audio_play_allstate(handle, p);
        break;

    case UV_AUDIO_TEST_STEP5:
        ops->uv_audio_play_allstate(handle, p);
        break;

    case UV_AUDIO_TEST_STEP6:
        ops->uv_audio_play_allstate(handle, p);
        break;

    case UV_AUDIO_TEST_STEP7:
        ops->uv_audio_play_get_position(handle);
        ops->uv_audio_play_allstate(handle, p);
        break;

    case UV_AUDIO_TEST_STEP8:
        ops->uv_audio_play_set_seek(handle, 5000);
        ops->uv_audio_play_allstate(handle, p);
        break;

    case UV_AUDIO_TEST_STEP9:
        ops->uv_audio_play_get_duration(handle);
        ops->uv_audio_play_allstate(handle, p);
        break;

    case UV_AUDIO_TEST_STEP10:
        ops->uv_audio_play_stop(handle);
        break;

    case UV_AUDIO_TEST_STEP11:
        ops->uv_audio_play_prepare(handle, "http://m701.music.126.net/20220321202554/756cd38f0991898a219d0b2244dd1b02/jdymusic/obj/w5zDlMODwrDDiGjCn8Ky/1511339371/3baa/2841/ee34/024f4dbd2f96a2b3d7f6fdae3e85243a.mp3", NULL);
        break;

    case UV_AUDIO_TEST_STEP12:
        ops->uv_audio_play_start(handle);
        ops->uv_audio_play_allstate(handle, p);
        break;

    case UV_AUDIO_TEST_STEP13:
        ops->uv_audio_play_allstate(handle, p);
        break;

    case UV_AUDIO_TEST_STEP14:
        ops->uv_audio_play_play(handle, "http://m10.music.126.net/20220321202822/1361a0f2d100fec585918fda79ff1670/ymusic/0758/550f/545f/028d3b9421be8425d60dc57735cf6ebc.mp3", NULL);
        ops->uv_audio_play_allstate(handle, p);
        break;

    case UV_AUDIO_TEST_STEP15:
        ops->uv_audio_play_allstate(handle, p);
        break;

    default:
        ops->uv_audio_play_close(handle);
        uv_close((uv_handle_t*)tim_handle, NULL);
        uv_poll_stop((uv_poll_t*)&uv_audio_test_poll);
        uv_stop(&audiploop);
        break;
    }

    step++;
    printf("step=%d\n", step);
}

static void uv_audio_test_poll_cb(uv_poll_t* handle, int status, int events)
{

    int ret;
    uv_audio_mqmessage_t message = { 0 };
    uv_work_t* work;

    ret = uv_audio_async_messgae_recv(UV_AUDIO_TEST_QUEUE, &message);
    if (ret < 0) {
        return;
    }

    work = (uv_work_t*)malloc(sizeof(uv_work_t));
    work->data = message.data;
    uv_queue_work(handle->loop, work, __audio_state_work_cb, __audio_state_after_work_cb);
}

#endif

int main(int argc, char* argv[])
{
#ifdef UV_AUDIO_TEST_CTRL
    return audio_test_ctrl_tool(argc, argv);
#else
    int data = 100;
    int timeout = 10;
    int ret;
    uv_timer_t audio_timer_handle;

    uv_loop_init(&audiploop);

    ret = uv_audio_async_messgae_init(&audiploop, &uv_audio_test_poll,
        UV_AUDIO_TEST_QUEUE, uv_audio_test_poll_cb);
    if (ret < 0) {
        printf("audio async fail.\n");
        return -1;
    }

    ops = uv_audio_play_init();
    if (!ops) {
        printf("Get audio ops fail.\n");
        goto testfail;
    }

    ops->uv_audio_play_open(uv_audio_callback_cb, &data, UV_AUDIO_TEST_PACKNAME);

    while (timeout--) {
        usleep(200000);
        if (handle != NULL) {
            break;
        }
    }

    if (handle == NULL) {
        printf("audio handle is NULL.\n");
        goto testfail;
    }

    ops->uv_audio_play_prepare(handle,
        "https://96.f.1ting.com/local_to_cube_202004121813/96kmp3/zzzzzmp3/2014dApr/15W/15zhangkeer/01.mp3", NULL);
    ops->uv_audio_play_start(handle);

    printf("audio handle timeout = %d\n", timeout);

    if (uv_timer_init(&audiploop, &audio_timer_handle) != 0) {
        ops->uv_audio_play_close(handle);
        goto testfail;
    }

    if (uv_timer_start(&audio_timer_handle, audio_timer_run_cb, 5000, 1000) != 0) {
        ops->uv_audio_play_close(handle);
        uv_close((uv_handle_t*)&audio_timer_handle, NULL);
        goto testfail;
    }

    printf("start loop !\n");
    uv_run(&audiploop, UV_RUN_DEFAULT);
    printf("TEST PASSED !\n");
    exit(0);

testfail:
    uv_poll_stop(&uv_audio_test_poll);
    printf("TEST FAILED !\n");
    exit(1);
#endif
}

#else

static uv_audio_t audio;
static int step = 0;

static void audio_notify_callback(void* cookie, int event,
    int ret, const char* extra)
{
    uv_audio_t* paudio = (uv_audio_t*)cookie;

    if (event == UV_EXT_AUDIO_EVENT_ERROR) {

    } else if (event == UV_EXT_AUDIO_EVENT_STARTED) {
        paudio->playstate = UV_EXT_AUDIO_STATE_PLAY;
    } else if (event == UV_EXT_AUDIO_EVENT_STOPPED) {
        paudio->playstate = UV_EXT_AUDIO_STATE_STOP;
    } else if (event == UV_EXT_AUDIO_EVENT_COMPLETE) {
        paudio->playstate = UV_EXT_AUDIO_STATE_COMPLETE;
    } else if (event == UV_EXT_AUDIO_EVENT_EVENT_PREPARED) {
    } else if (event == UV_EXT_AUDIO_EVENT_PAUSED) {
        paudio->playstate = UV_EXT_AUDIO_STATE_PAUSE;
    }

    printf("%s %s %d eventid=%d\n", __FILE__, __func__, __LINE__, event);
}

static void audio_timer_run_cb(uv_timer_t* handle)
{
    float volume = 0;
    unsigned int ret, sec = 0;

    switch (step) {
    case 0:
        ret = uv_audio_pause(&audio);
        printf("\nstep[%02d, pause] playstate:%d\n", step, audio.playstate);
        break;
    case 1:
        break;
    case 2:
        ret = uv_audio_play(&audio);
        printf("step[%02d, play] playstate:%d\n", step, audio.playstate);
        break;
    case 3:
        ret = uv_audio_get_volume(&audio, &volume);
        printf("step[%02d, get_volume] playstate:%d, %f %f\n", step,
            audio.playstate, audio.volume, volume);
        break;
    case 4:
        ret = uv_audio_set_volume(&audio, 0.1);
        printf("step[%02d, set_volume] playstate:%d, %f %f\n", step,
            audio.playstate, audio.volume, audio.volume);
        break;
    case 5:
        ret = uv_audio_muted(&audio, true);
        printf("step[%02d, muted true] playstate:%d, %f %d\n", step,
            audio.playstate, audio.volume, audio.muted);
        break;
    case 6:
        ret = uv_audio_muted(&audio, false);
        printf("step[%02d, muted false] playstate:%d, %f %d\n", step,
            audio.playstate, audio.volume, audio.muted);
        break;
    case 7:
        ret = uv_audio_get_currenttime(&audio, &sec);
        printf("step[%02d, get_currenttime] playstate:%d, %d\n", step,
            audio.playstate, sec);
        break;
    case 8:
        ret = uv_audio_set_currenttime(&audio, 5);
        printf("step[%02d, set_currenttime] playstate:%d, %d\n", step,
            audio.playstate, 5);
        break;
    case 9:
        ret = uv_audio_get_duration(&audio, &sec);
        printf("step[%02d, get_duration] playstate:%d, %d\n", step,
            audio.playstate, sec);
        break;
    case 10:
        ret = uv_audio_get_isplay(&audio);
        printf("step[%02d, get_isplay] playstate:%d\n", step, audio.playstate);
        break;
    case 11:
        ret = uv_audio_set_url(&audio, "/music/2.mp3");
        printf("step[%02d, get_isplay] url:%s\n", step, audio.url);
        break;
    case 12:
        ret = uv_audio_play(&audio);
        printf("step[%02d, get_isplay] playstate:%d\n", step, audio.playstate);
        break;
    case 13:
        ret = uv_audio_stop(&audio);
        printf("step[%02d, stop] playstate:%d", step, audio.playstate);
        break;
    default:
        uv_audio_close(&audio);
        uv_close((uv_handle_t*)handle, NULL);
        uv_stop(uv_default_loop());
        break;
    }

    step++;
    printf("ret=%d\n", ret);
}

int main(int argc, char* argv[])
{
    uv_timer_t audio_timer_handle;

    if (uv_audio_create(&audio, audio_notify_callback, &audio) != 0) {
        goto testfail;
    }

    if (uv_audio_set_url(&audio, "/music/1.mp3") != 0) {
        goto testfail;
    }

    if (uv_audio_prepare(&audio, "/music/1.mp3") != 0) {
        goto testfail;
    }

    if (uv_audio_play(&audio) != 0) {
        goto testfail;
    }

    printf("url:%s playstate:%d", audio.url, audio.playstate);

    if (uv_timer_init(uv_default_loop(), &audio_timer_handle) != 0) {
        goto testfail;
    }

    if (uv_timer_start(&audio_timer_handle, audio_timer_run_cb, 5000, 5000) != 0) {
        goto testfail;
    }

    uv_run(uv_default_loop(), UV_RUN_DEFAULT);

    printf("TEST PASSED !\n");
    exit(0);

testfail:
    printf("TEST FAILED !\n");
    exit(1);
}
#endif
