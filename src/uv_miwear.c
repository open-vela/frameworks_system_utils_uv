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
#include <uv_ext.h>

#include <assert.h>
#include <debug.h>
#include <netpacket/rpmsg.h>
#include <nuttx/list.h>
#include <nuttx/nuttx.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <uv.h>

#ifndef CONFIG_MIWEAR_QAPP_PROXY_SERVER
#define CONFIG_MIWEAR_QAPP_PROXY_SERVER "miwear-server"
#endif

#ifndef CONFIG_MIWEAR_MESSAGE_MAX_LEN
/* Nearly not limit the message length. */
#define CONFIG_MIWEAR_MESSAGE_MAX_LEN (1024 * 1024 * 2)
#endif

#ifndef CONFIG_UV_MIWEAR_CLIENT_ID_LEN
#define CONFIG_UV_MIWEAR_CLIENT_ID_LEN 64
#endif

#define uv_miwear_debug(fmt, ...) uv_log_debug("uv_miwear", fmt, ##__VA_ARGS__)
#define uv_miwear_info(fmt, ...) uv_log_info("uv_miwear", fmt, ##__VA_ARGS__)
#define uv_miwear_error(fmt, ...) uv_log_error("uv_miwear", fmt, ##__VA_ARGS__)
/**
 * The actual message send over socket, added id field for auto response
 * process.
 */

typedef struct message_response_s {
    uint32_t id;
} message_response_t;

typedef struct miwear_wreq_s {
    uv_write_t req; /* Must be the first element. */

    struct list_node node; /* The data sending out that needs response will
                              be inserted to a list. */
    uv_miwear_sent_cb cb;
    void* cb_para;
    uv_miwear_message_t message;
    uv_miwear_t* miwear;
    struct client* client;
} miwear_wreq_t;

typedef void (*msg_reader_cb)(uv_stream_t* stream, uv_miwear_message_t* msg,
    struct client* client);

enum client_state {
    CLIENT_STATE_CONNECTING = 0,
    CLIENT_STATE_HANDSHAKING, /* Sending CLIENT_ID message. */
    CLIENT_STATE_CONNECTED,
    CLIENT_STATE_DISCONNECTED,
};

struct client {
    struct list_node node;
    uv_pipe_t pipe;

    char name[CONFIG_UV_MIWEAR_CLIENT_ID_LEN];
    enum client_state state;

    /* List of all write request sending out waiting for response. */
    struct list_node sending_list;

    uint32_t message_id; /* A self growing number used as message ID. */

    uv_miwear_t* miwear;
};

struct server {
    uv_pipe_t pipe;

#ifdef CONFIG_NET_RPMSG
    uv_pipe_t pipe_rpmsg;
#endif

    struct list_node client_list;
    int client_count;

    uv_miwear_t* miwear;
};

/**
 * Message reader, used to read message froms stream.
 */
typedef enum {
    /* Currently is reading msg header from stream. */
    MESSAGE_READER_STATE_HEADER = 0,

    /* Reading msg body from stream. */
    MESSAGE_READER_STATE_BODY,

    /* Message read completed. */
    MESSAGE_READER_STATE_FINISHED,
} message_reader_state_t;

struct reader {
    uv_stream_t* stream;

    message_reader_state_t state;
    uv_miwear_header_t header;

    /* The message received. */
    uv_miwear_message_t message;

    /* Message body(message.data) bytes received. */
    uint32_t recv_len;

    msg_reader_cb cb;
    struct client* client; /* the client connected to this stream */
};

static int uv__miwear_send_to_client(struct client* client,
    uv_miwear_message_t* message,
    uv_miwear_sent_cb cb, void* cb_para);

static int uv_miwear_send_to_server(uv_miwear_t* miwear,
    uv_miwear_message_t* message,
    uv_miwear_sent_cb cb, void* cb_para);

static int uv_miwear_send_to_client(uv_miwear_t* miwear, const char* name,
    uv_miwear_message_t* message,
    uv_miwear_sent_cb cb, void* cb_para);

static void reader_state_reset(struct reader* reader)
{
    reader->state = MESSAGE_READER_STATE_HEADER;
    reader->message.data = NULL;
    reader->recv_len = 0;
}

static void message_reader_alloc_cb(uv_handle_t* handle, size_t suggested_size,
    uv_buf_t* buf)
{
    struct reader* reader = (struct reader*)handle->data;

    if (reader->state == MESSAGE_READER_STATE_HEADER) {
        buf->base = ((char*)&reader->header) + reader->recv_len;
        buf->len = sizeof(reader->header) - reader->recv_len;
        return;
    }

    if (reader->state == MESSAGE_READER_STATE_BODY) {
        /* Check if memory already allocated. */
        if (reader->message.data) {
            /* Body read ongoing. */
            buf->base = (char*)reader->message.data + reader->recv_len;
            buf->len = reader->header.len - reader->recv_len;

            if (buf->len == 0) {
                /* This should not happen. */
            }
            return;
        }

        /* Alloc memory for message body. */
        uint32_t len = reader->header.len;

        /* For debug purpose, limit the max message length. */
        if (len > CONFIG_MIWEAR_MESSAGE_MAX_LEN) {
            nerr("Fatal error, message length check failed: %" PRIu32 ", suggested: %zu\n", len,
                suggested_size);
            DEBUGASSERT(0);
        }

        void* body = malloc(len);
        if (body == NULL) {
            nerr("Fatal error: no memory, request len: %" PRIu32 ".\n", len);
            return;
        }

        /* Copy the header to packet */
        memcpy(&reader->message, &reader->header, sizeof(uv_miwear_header_t));
        reader->message.data = body;

        buf->base = (char*)reader->message.data;
        buf->len = len;
        ninfo("msg body alloc: %" PRIu32 ".\n", len);
        return;
    }

    buf->base = 0;
    buf->len = 0;
}

/**
 * Callback when received data from stream.
 */
static void message_reader_read_cb(uv_stream_t* stream, ssize_t nread,
    const uv_buf_t* buf)
{
    struct reader* reader = stream->data;

    if (nread == 0) {
        /* EAGAIN */
        return;
    }

    if (nread < 0) {
        /* Check errno, need to continue to read. */
        nwarn("IPC client read met EOF\n");
        if (reader->cb) {
            reader->cb(reader->stream, NULL, reader->client);
            return;
        } else {
            /** @todo connection closed, process it properly. */
            DEBUGASSERT(0);
        }
    }

    if (reader->state == MESSAGE_READER_STATE_HEADER) {
        if (nread > sizeof(uv_miwear_header_t)) {
            _err("fatal, wrong header len %zu\n", nread);
            /* @todo what now... */
            return;
        }

        reader->recv_len += nread;
        if (reader->recv_len < sizeof(uv_miwear_header_t)) {
            nwarn("header read ongoing: %" PRIu32 "\n", reader->recv_len);
            return;
        }

        reader->state = MESSAGE_READER_STATE_BODY;
        reader->recv_len = 0;
        uv_read_start(reader->stream, message_reader_alloc_cb,
            message_reader_read_cb);
        return;
    }

    if (reader->state == MESSAGE_READER_STATE_BODY) {
        reader->recv_len += nread;
        if (reader->recv_len >= reader->header.len) {
            reader->state = MESSAGE_READER_STATE_FINISHED;
            if (reader->cb) {
                reader->cb(reader->stream, &reader->message, reader->client);
            }

            free((void*)reader->message.data);
            reader_state_reset(reader);
        }

        uv_read_start(reader->stream, message_reader_alloc_cb,
            message_reader_read_cb);
        return;
    }

    nerr("Unexpected reader state: %d\n", reader->state);

    uv_read_start(reader->stream, message_reader_alloc_cb,
        message_reader_read_cb);
}

static struct reader* message_reader_start(uv_stream_t* stream,
    msg_reader_cb cb,
    void* client)
{
    DEBUGASSERT(stream);
    DEBUGASSERT(cb);
    struct reader* reader = zalloc(sizeof(struct reader));
    if (reader == NULL) {
        nerr("no memory.\n");
        return NULL;
    }
    reader->stream = stream;
    reader->cb = cb;
    reader->client = client;

    stream->data = reader;
    uv_read_start(stream, message_reader_alloc_cb, message_reader_read_cb);
    return reader;
}

static void uv__miwear_client_close(struct client* client)
{
    miwear_wreq_t* wreq;
    miwear_wreq_t* wreq_next;
    uv_miwear_info("uv__miwear_client_close, client: %p\n", client);
    list_for_every_entry_safe(&client->sending_list, wreq, wreq_next,
        miwear_wreq_t, node)
    {
        /* Remove from sending list. */
        list_delete(&wreq->node);
        if (wreq->cb) {
            /** Let application known write request failed. */
            wreq->cb(wreq->miwear, UV_ECANCELED, &wreq->message, wreq->cb_para);
        }
        free(wreq);
    }

    if (client->miwear->is_server) {
        /* For server also need to remove client from list */
        if (list_in_list(&client->node)) {
            list_delete(&client->node);
        }
    }

    /* Make callback to let application know connection lost. */
    if (client->miwear->cb) {
        uv_miwear_status_t data;
        data.status = MIWEAR_STATUS_CONNECTION_CLOSED;
        data.parameter = client->name;

        uv_miwear_message_t msg;
        msg.header.type = MIWEAR_MESSAGE_TYPE_STATUS;
        msg.header.len = sizeof(data);
        msg.header.id = 0;
        msg.data = &data;
        client->miwear->cb(client->miwear, 0, &msg, client->name);
    }

    free(client);
}

static void pipe_close_callback(uv_handle_t* handle)
{
    uv_miwear_info("pipe_close_callback\n");
    struct reader* reader = handle->data;
    uv__miwear_client_close(reader->client);
    free(reader);
}

static void pipe_close_callback2(uv_handle_t* handle)
{
    uv_miwear_info("pipe_close_callback2\n");

    /* Get client from pipe address using container_of pattern.
     * handle points to client->pipe, so we can calculate client address.
     */
    struct client* client = container_of(handle, struct client, pipe);
    uv_miwear_t* miwear = client->miwear;

    if (miwear->is_server)
        return;

    struct reader* reader = miwear->reader;
    if (reader)
        free(reader);

    uv__miwear_client_close(client);
}

static void message_reader_stop(uv_stream_t* stream)
{
    uv_miwear_info("message_reader_stop\n");
    uv_close((uv_handle_t*)stream, pipe_close_callback);
}

static void response_sent_callback(uv_miwear_t* miwear, int status,
    uv_miwear_message_t* message,
    void* cb_para)
{
    free((void*)message->data);
}

/* Callback when server/client received data from socket. */
static void stream_read_callback(uv_stream_t* stream, uv_miwear_message_t* msg,
    struct client* client)
{
    uv_miwear_info("stream_read_callback\n");
    if (msg == NULL) {
        /**
         * A null pointer means stream disconnected. Terminate the client.
         * Stop the message reader where client is properly closed.
         */
        message_reader_stop(stream);
        return;
    }

    if (msg->header.type == MIWEAR_MESSAGE_TYPE_CLIENT_ID) {
        /* The first message from client. Only server could receive this message. */
        struct server* server = client->miwear->server;
        ninfo("Got connection from client: %s\n", (char*)msg->data);
        strlcpy(client->name, msg->data, CONFIG_UV_MIWEAR_CLIENT_ID_LEN);
        client->state = CLIENT_STATE_CONNECTED;

        /* Add client to list. */
        list_add_tail(&server->client_list, &client->node);
        server->client_count++;

        /* Let server know that a new client connected. */
        if (server->miwear->cb) {
            uv_miwear_status_t data;
            data.status = MIWEAR_STATUS_CLIENT_ONLINE;
            data.parameter = client->name;

            uv_miwear_message_t msg;
            msg.header.type = MIWEAR_MESSAGE_TYPE_STATUS;
            msg.header.len = sizeof(data);
            msg.header.id = 0;
            msg.data = &data;
            client->miwear->cb(client->miwear, 0, &msg, client->name);
        }

        ninfo("client count: %d\n", server->client_count);
        return;
    }

    if (msg->header.type == MIWEAR_MESSAGE_TYPE_RESPONSE) {
        if (msg->header.len != sizeof(message_response_t)) {
            nerr("Unrecognized response packet, client: %s\n", client->name);
            return;
        }

        const message_response_t* response = msg->data;
        ninfo("Got response, client %s, to message id: 0x%08" PRIx32 "\n", client->name,
            response->id);

        /* Loop through the write-requests waiting for response. */
        miwear_wreq_t* wreq;

        bool found = false;
        list_for_every_entry(&client->sending_list, wreq, miwear_wreq_t, node)
        {
            if (wreq->message.header.id == response->id) {
                found = true;
                break;
            }
        }

        if (!found) {
            nerr("Unrecognized response id: 0x%08" PRIx32 "\n", response->id);
            return;
        }

        list_delete(&wreq->node);

        if (wreq->cb) {
            wreq->cb(wreq->miwear, 0, &wreq->message, wreq->cb_para);
        }
        free(wreq);

        return;
    }

    /**
     * All other types are data, if MIWEAR_MESSAGE_NEED_REPLY_MASK is set, then
     * this data message needs reply, otherwise, simply receive it.
     */

    ninfo("got message to/from client:%s, msg:%d, len:%" PRIu32 "\n", client->name,
        msg->header.type, msg->header.len);

    if (client->state != CLIENT_STATE_CONNECTED) {
        nerr("Data received when client not connected.");
    }

    if (msg->header.type & MIWEAR_MESSAGE_NEED_REPLY_MASK) {
        message_response_t* response = malloc(sizeof(message_response_t));
        if (response == NULL) {
            nerr("No memory for response.");
            return;
        }
        response->id = msg->header.id;

        uv_miwear_message_t reply = { 0 };
        reply.data = response;
        reply.header.len = sizeof(message_response_t);
        reply.header.type = MIWEAR_MESSAGE_TYPE_RESPONSE;
        int ret = uv__miwear_send_to_client(client, &reply,
            response_sent_callback, NULL);
        if (ret != 0) {
            /* Sender should send the message again because of missing response. */
            nerr("Cannot send response to client.\n");
            return;
        }
    }

    if (client->miwear->cb) {
        client->miwear->cb(client->miwear, 0, msg, client->name);
    }
}

static void server_listen_callback(uv_stream_t* stream, int status)
{
    struct server* server = stream->data;

    if (status < 0) {
        nerr("uv listen error: %s", uv_strerror(status));
        return;
    }

    struct client* client = zalloc(sizeof(struct client));
    if (client == NULL) {
        nerr("No memory for client structure.\n");
        return;
    }

    int error = uv_pipe_init(stream->loop, &client->pipe, 0);
    if (error != 0) {
        nerr("pipe init failed: %s\n", uv_strerror(error));
        return;
    }

    error = uv_accept(stream, (uv_stream_t*)&client->pipe);
    if (error != 0) {
        nerr("uv_accept failed: %s\n", uv_strerror(error));
        return;
    }

    client->state = CLIENT_STATE_CONNECTING;
    client->miwear = server->miwear;
    list_initialize(&client->sending_list);
    server->miwear->reader = message_reader_start((uv_stream_t*)&client->pipe,
        stream_read_callback,
        client);
}

int uv_miwear_start_server(uv_loop_t* loop, uv_miwear_t* miwear,
    const char* path, uv_miwear_recv_cb cb)
{
    if (!loop || !miwear || !path || !cb)
        return UV_EINVAL;

    struct server* server;
    server = zalloc(sizeof(struct server));
    if (server == NULL) {
        nerr("no memory.");
        return UV_ENOMEM;
    }

    list_initialize(&server->client_list);

    server->miwear = miwear;

    miwear->server = server;
    miwear->cb = cb;
    miwear->is_server = true;
    uv_fs_t fs;

    int err = uv_pipe_init(loop, &server->pipe, 0);
    if (err != 0) {
        nerr("pipe init failed: %s\n", uv_strerror(err));
        goto server_start_err;
    }

    err = uv_fs_unlink(loop, &fs, path, NULL);
    if (err != 0 && err != UV_ENOENT) {
        nerr("uv_fs_unlink() fail  uv error: %s", uv_strerror(err));
        goto server_start_err;
    }

    err = uv_pipe_bind(&server->pipe, path);
    if (err != 0) {
        nerr("pipe bind failed: %s\n", uv_strerror(err));
        goto server_start_err;
    }

    server->pipe.data = server;

    err = uv_listen((uv_stream_t*)&server->pipe, SOMAXCONN,
        server_listen_callback);
    if (err != 0) {
        nerr("uv_listen failed: %s\n", uv_strerror(err));
        goto server_start_err;
    }

#ifdef CONFIG_NET_RPMSG
    /* Start RPMSG server */
    err = uv_pipe_init(loop, &server->pipe_rpmsg, 0);
    if (err != 0) {
        nerr("pipe_rpmsg init failed: %s\n", uv_strerror(err));
        goto server_start_err;
    }

    err = uv_pipe_rpmsg_bind(&server->pipe_rpmsg, path, "");
    if (err != 0) {
        nerr("pipe_rpmsg bind failed: %s\n", uv_strerror(err));
        goto server_start_err;
    }

    server->pipe_rpmsg.data = server; /* save handler to server. */
    err = uv_listen((uv_stream_t*)&server->pipe_rpmsg, 16,
        server_listen_callback);
    if (err != 0) {
        nerr("pipe_rpmsg listen failed: %s\n", uv_strerror(err));
        goto server_start_err;
    }
#endif

    return 0;

server_start_err:
    miwear->server = NULL;
    /* Need to unregister all handlers.... */
    free(server);
    return err;
}

static void uv_write_done_callback(uv_write_t* req, int status)
{
    miwear_wreq_t* wreq = (miwear_wreq_t*)req;

    if (status != 0) {
        nerr("Failed sending data, client: %s, id: %" PRIu32 ", status: %d\n",
            wreq->client->name, wreq->message.header.id, status);
        /* For all other messages, no responses needed, make the callback now.*/
        if (wreq->cb) {
            wreq->cb(wreq->miwear, status, &wreq->message, wreq->cb_para);
        }
        free(wreq);
        return;
    }

    ninfo("sent to %s, type:%d, id: %" PRIu32 "\n", wreq->client->name,
        wreq->message.header.type, wreq->message.header.id);

    if (wreq->message.header.type & MIWEAR_MESSAGE_NEED_REPLY_MASK) {
        /* Add this request to sending list that waiting for response. */
        struct client* client = wreq->client;
        list_add_tail(&client->sending_list, &wreq->node);
        return;
    }

    if (wreq->cb) {
        wreq->cb(wreq->miwear, status, &wreq->message, wreq->cb_para);
    }

    free(wreq);
}

static int uv__miwear_send_to_client(struct client* client,
    uv_miwear_message_t* message,
    uv_miwear_sent_cb cb, void* cb_para)
{
    if (!client || !message || !cb)
        return UV_EINVAL;

    miwear_wreq_t* wreq = malloc(sizeof(miwear_wreq_t));
    if (wreq == NULL)
        return UV_ENOMEM;

    wreq->cb = cb;
    wreq->cb_para = cb_para;
    wreq->message = *message;
    wreq->miwear = client->miwear;
    wreq->client = client;

    wreq->message.header.id = client->message_id++;

    uv_buf_t b[2];
    b[0] = uv_buf_init((char*)&wreq->message, sizeof(uv_miwear_header_t));
    b[1] = uv_buf_init((char*)message->data, message->header.len);

    int error = uv_write(&wreq->req, (uv_stream_t*)&client->pipe, b, 2,
        uv_write_done_callback);

    if (error) {
        nerr("stream write failed.\n");
        return error;
    }

    return 0;
}

static int uv_miwear_send_to_client(uv_miwear_t* miwear, const char* name,
    uv_miwear_message_t* message,
    uv_miwear_sent_cb cb, void* cb_para)
{
    if (!miwear || !message || !cb)
        return UV_EINVAL;

    struct server* server = miwear->server;
    struct client* client;

    if (!server)
        return UV_EINVAL;

    /* broadcast */
    if (name == NULL) {
        int ret = 0;
        list_for_every_entry(&server->client_list, client, struct client, node)
        {
            ninfo("send message to client [%s]\n", client->name);
            ret |= uv__miwear_send_to_client(client, message, cb, cb_para);
        }
        return !!ret;
    }

    /* Find client via name. */
    bool found = false;
    list_for_every_entry(&server->client_list, client, struct client, node)
    {
        if (!strcmp(name, client->name)) {
            found = true;
            break;
        }
    }
    if (!found) {
        nerr("Client %s not found\n", name);
        return UV_ENXIO;
    }
    ninfo("send message to client [%s]\n", client->name);
    return uv__miwear_send_to_client(client, message, cb, cb_para);
}

static void client_id_sent_callback(uv_miwear_t* miwear, int status,
    uv_miwear_message_t* msg,
    void* cb_para)
{
    struct client* client = miwear->client;
    if (status != 0) {
        client->state = CLIENT_STATE_DISCONNECTED;
        return;
    }
    uv_miwear_info("CLIENT_ID message sent, server connected\n");
    ninfo("CLIENT_ID message sent, server connected\n");
    client->state = CLIENT_STATE_CONNECTED;

    miwear->reader = message_reader_start((uv_stream_t*)&client->pipe,
        stream_read_callback,
        client);

    /* Notify app of this status. */
    if (client->miwear->cb) {
        uv_miwear_status_t data;
        data.status = MIWEAR_STATUS_CLIENT_ID_SENT;

        uv_miwear_message_t msg = { 0 };
        msg.header.type = MIWEAR_MESSAGE_TYPE_STATUS;
        msg.header.len = sizeof(data);
        msg.header.id = 0;
        msg.data = &data;

        client->miwear->cb(client->miwear, 0, &msg, client->name);
    }
}

static void client_on_connect_callback(uv_connect_t* req, int status)
{
    struct client* client = req->data;
    uv_miwear_info("client on connect callback.\n");
    /* Check connection status. */
    if (status != 0) {
        client->state = CLIENT_STATE_DISCONNECTED;
        nerr("Fatal error: failed to connect server: %d\n", status);

        if (client->miwear->cb) {
            uv_miwear_status_t data;
            data.status = MIWEAR_STATUS_CONNECT_FAILED;
            data.parameter = (void*)(uintptr_t)status;

            uv_miwear_message_t msg = { 0 };
            msg.header.type = MIWEAR_MESSAGE_TYPE_STATUS;
            msg.header.len = sizeof(data);
            msg.header.id = 0;
            msg.data = &data;
            client->miwear->cb(client->miwear, status, &msg, client->name);
        }
        free(req);
        return;
    }

    ninfo("server connected, send CLIENT_ID message now.\n");

    client->state = CLIENT_STATE_HANDSHAKING;

    /* Write first message to server, which is the CLIENT_ID message. */
    uv_miwear_message_t msg = { 0 };
    msg.data = client->name;
    msg.header.len = strlen(client->name) + 1;
    msg.header.type = MIWEAR_MESSAGE_TYPE_CLIENT_ID;

    uv_miwear_send_to_server(client->miwear, &msg,
        client_id_sent_callback, NULL);

    free(req);
}

int uv_miwear_start_client(uv_loop_t* loop, uv_miwear_t* miwear,
    const char* name, const char* path,
    uv_miwear_recv_cb cb)
{
    if (!loop || !miwear || !name || !path || !cb)
        return UV_EINVAL;

    struct client* client;
    client = malloc(sizeof(struct client));
    if (client == NULL) {
        nerr("no memory.");
        return UV_ENOMEM;
    }
    memset(client, 0, sizeof(struct client));

    strlcpy(client->name, name, CONFIG_UV_MIWEAR_CLIENT_ID_LEN);
    list_initialize(&client->sending_list);
    client->state = CLIENT_STATE_CONNECTING;
    client->miwear = miwear;
    miwear->cb = cb;
    miwear->client = client;
    miwear->is_server = false;

    uv_connect_t* connect = malloc(sizeof(uv_connect_t));
    if (connect == NULL) {
        nerr("No memory.\n");
        return UV_ENOMEM;
    }

    connect->data = client;

    uv_pipe_init(loop, &client->pipe, 0);

    uv_pipe_connect(connect, &client->pipe, path, client_on_connect_callback);

    ninfo("start client: %p\n", miwear);
    return 0;
}

#ifdef CONFIG_NET_RPMSG
int uv_miwear_start_rpmsg_client(uv_loop_t* loop, uv_miwear_t* miwear,
    const char* client_name,
    const char* server_path,
    const char* cpu_name,
    uv_miwear_recv_cb cb)
{
    if (!loop || !miwear || !client_name || !cpu_name || !server_path || !cb)
        return UV_EINVAL;

    struct client* client;
    client = malloc(sizeof(struct client));
    if (client == NULL) {
        nerr("no memory.");
        return UV_ENOMEM;
    }
    memset(client, 0, sizeof(struct client));

    strlcpy(client->name, client_name, CONFIG_UV_MIWEAR_CLIENT_ID_LEN);
    list_initialize(&client->sending_list);
    client->state = CLIENT_STATE_CONNECTING;
    client->miwear = miwear;
    miwear->cb = cb;
    miwear->client = client;
    miwear->is_server = false;

    uv_connect_t* connect = malloc(sizeof(uv_connect_t));
    if (connect == NULL) {
        nerr("No memory.\n");
        return UV_ENOMEM;
    }

    connect->data = client;

    uv_pipe_init(loop, &client->pipe, 0);

    uv_pipe_rpmsg_connect(connect, &client->pipe, server_path, cpu_name,
        client_on_connect_callback);
    return 0;
}
#endif

static int uv_miwear_stop_client(uv_miwear_t* miwear)
{
    uv_miwear_info("uv_miwear_stop_client: %p\n", miwear);
    ninfo("stop client: %p\n", miwear);

    uv_close((uv_handle_t*)&miwear->client->pipe, pipe_close_callback2);
    return 0;
}

static int uv_miwear_send_to_server(uv_miwear_t* miwear,
    uv_miwear_message_t* message,
    uv_miwear_sent_cb cb, void* cb_para)
{
    if (!miwear || !message || !cb)
        return UV_EINVAL;

    struct client* client = miwear->client;

    if (client->state == CLIENT_STATE_HANDSHAKING) {
        /* only CLIENT_ID message could be sent at this stage. */
        if (message->header.type == MIWEAR_MESSAGE_TYPE_CLIENT_ID) {
            goto send_msg_continue;
        }
    }

    if (client->state != CLIENT_STATE_CONNECTED) {
        nerr("client not connected.\n");
        return -1;
    }

send_msg_continue:
    ninfo("Send to server MSG: %d, len: %" PRIu32 "\n", message->header.type,
        message->header.len);

    miwear_wreq_t* wreq = malloc(sizeof(miwear_wreq_t));
    if (wreq == NULL)
        return UV_ENOMEM;

    wreq->cb = cb;
    wreq->cb_para = cb_para;
    wreq->message = *message;

    wreq->message.header.id = client->message_id++;
    wreq->miwear = miwear;
    wreq->client = client;

    uv_buf_t b[2];

    b[0] = uv_buf_init((char*)&wreq->message, sizeof(uv_miwear_header_t));
    b[1] = uv_buf_init((char*)message->data, message->header.len);

    int error = uv_write(&wreq->req, (uv_stream_t*)&client->pipe, b, 2,
        uv_write_done_callback);

    if (error) {
        nerr("stream write failed.\n");
        return ERROR;
    }

    return OK;
}

int uv_miwear_connect(uv_loop_t* loop, uv_miwear_t* miwear,
    const char* pkg_name, uv_miwear_recv_cb cb)
{
    uv_miwear_info("uv_miwear_connect: %p %s\n", miwear, pkg_name);
    return uv_miwear_start_client(loop, miwear, pkg_name,
        CONFIG_MIWEAR_QAPP_PROXY_SERVER, cb);
}

int uv_miwear_send(uv_miwear_t* miwear, const char* to,
    uv_miwear_message_t* message,
    uv_miwear_sent_cb cb, void* cb_para)
{
    if (miwear->is_server)
        return uv_miwear_send_to_client(miwear, to, message, cb, cb_para);

    return uv_miwear_send_to_server(miwear, message, cb, cb_para);
}

int uv_miwear_iter_client(uv_miwear_t* miwear, void (*cb)(const char*, void*),
    void* cb_para)
{
    if (!miwear || !cb)
        return UV_EINVAL;

    struct server* server = miwear->server;
    struct client* client;

    if (!miwear->is_server || !server)
        return UV_EINVAL;

    list_for_every_entry(&server->client_list, client, struct client, node)
    {
        cb(client->name, cb_para);
    }
    return 0;
}

int uv_miwear_close(uv_miwear_t* miwear)
{
    if (miwear->is_server)
        return 0;

    return uv_miwear_stop_client(miwear);
}
