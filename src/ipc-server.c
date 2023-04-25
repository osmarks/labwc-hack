/*
From swaywm
Copyright (c) 2016-2017 Drew DeVault

Permission is hereby granted, free of charge, to any person obtaining a copy of
this software and associated documentation files (the "Software"), to deal in
the Software without restriction, including without limitation the rights to
use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
of the Software, and to permit persons to whom the Software is furnished to do
so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

// See https://i3wm.org/docs/ipc.html for protocol information
#define _POSIX_C_SOURCE 200112L
#include <linux/input-event-codes.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <json.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <unistd.h>
#include <wayland-server-core.h>
#include <wlr/util/box.h>
#include "view.h"
#include "labwc.h"
#include "common/list.h"
#include "ipc.h"
#include "ipc-server.h"

#define wlr_abort(s) wlr_log(WLR_ERROR, s); exit(EXIT_FAILURE);
#define wlr_assert(c, s) (c)

static int ipc_socket = -1;
static struct wl_event_source *ipc_event_source =  NULL;
static struct sockaddr_un *ipc_sockaddr = NULL;
static struct wl_list ipc_client_list = {0};
static struct wl_listener ipc_display_destroy;

static const char ipc_magic[] = {'i', '3', '-', 'i', 'p', 'c'};

#define IPC_HEADER_SIZE (sizeof(ipc_magic) + 8)

struct ipc_client {
	struct wl_event_source *event_source;
	struct wl_event_source *writable_event_source;
	struct server *server;
	int fd;
	enum ipc_command_type subscribed_events;
	size_t write_buffer_len;
	size_t write_buffer_size;
	char *write_buffer;
	// The following are for storing data between event_loop calls
	uint32_t pending_length;
	enum ipc_command_type pending_type;
    struct wl_list link;
};

int ipc_handle_connection(int fd, uint32_t mask, void *data);
int ipc_client_handle_readable(int client_fd, uint32_t mask, void *data);
int ipc_client_handle_writable(int client_fd, uint32_t mask, void *data);
void ipc_client_disconnect(struct ipc_client *client);
void ipc_client_handle_command(struct ipc_client *client, uint32_t payload_length,
	enum ipc_command_type payload_type);
bool ipc_send_reply(struct ipc_client *client, enum ipc_command_type payload_type,
	const char *payload, uint32_t payload_length);

static void handle_display_destroy(struct wl_listener *listener, void *data) {
	if (ipc_event_source) {
		wl_event_source_remove(ipc_event_source);
	}
	close(ipc_socket);
	unlink(ipc_sockaddr->sun_path);

    struct ipc_client *e;
    struct ipc_client *f;
    wl_list_for_each_safe(e, f, &ipc_client_list, link) {
        ipc_client_disconnect(e);
    }

	free(ipc_sockaddr);

	wl_list_remove(&ipc_display_destroy.link);
}

void ipc_init(struct server *server) {
	ipc_socket = socket(AF_UNIX, SOCK_STREAM, 0);
	if (ipc_socket == -1) {
		wlr_abort("Unable to create IPC socket");
	}
	if (fcntl(ipc_socket, F_SETFD, FD_CLOEXEC) == -1) {
		wlr_abort("Unable to set CLOEXEC on IPC socket");
	}
	if (fcntl(ipc_socket, F_SETFL, O_NONBLOCK) == -1) {
		wlr_abort("Unable to set NONBLOCK on IPC socket");
	}

	ipc_sockaddr = ipc_user_sockaddr();

	// We want to use socket name set by user, not existing socket from another sway instance.
	if (getenv("SWAYSOCK") != NULL && access(getenv("SWAYSOCK"), F_OK) == -1) {
		strncpy(ipc_sockaddr->sun_path, getenv("SWAYSOCK"), sizeof(ipc_sockaddr->sun_path) - 1);
		ipc_sockaddr->sun_path[sizeof(ipc_sockaddr->sun_path) - 1] = 0;
	}

	unlink(ipc_sockaddr->sun_path);
	if (bind(ipc_socket, (struct sockaddr *)ipc_sockaddr, sizeof(*ipc_sockaddr)) == -1) {
		wlr_abort("Unable to bind IPC socket");
	}

	if (listen(ipc_socket, 3) == -1) {
		wlr_abort("Unable to listen on IPC socket");
	}

	// Set i3 IPC socket path so that i3-msg works out of the box
	setenv("I3SOCK", ipc_sockaddr->sun_path, 1);
	setenv("SWAYSOCK", ipc_sockaddr->sun_path, 1);

    wl_list_init(&ipc_client_list);

	ipc_display_destroy.notify = handle_display_destroy;
	wl_display_add_destroy_listener(server->wl_display, &ipc_display_destroy);

	ipc_event_source = wl_event_loop_add_fd(server->wl_event_loop, ipc_socket, WL_EVENT_READABLE, ipc_handle_connection, server);
}

struct sockaddr_un *ipc_user_sockaddr(void) {
	struct sockaddr_un *ipc_sockaddr = malloc(sizeof(struct sockaddr_un));
	if (ipc_sockaddr == NULL) {
		wlr_abort("Can't allocate ipc_sockaddr");
	}

	ipc_sockaddr->sun_family = AF_UNIX;
	int path_size = sizeof(ipc_sockaddr->sun_path);

	// Env var typically set by logind, e.g. "/run/user/<user-id>"
	const char *dir = getenv("XDG_RUNTIME_DIR");
	if (!dir) {
		dir = "/tmp";
	}
	if (path_size <= snprintf(ipc_sockaddr->sun_path, path_size,
			"%s/sway-ipc.%u.%i.sock", dir, getuid(), getpid())) {
		wlr_abort("Socket path won't fit into ipc_sockaddr->sun_path");
	}

	return ipc_sockaddr;
}

int ipc_handle_connection(int fd, uint32_t mask, void *data) {
	(void) fd;
	struct server *server = data;
	assert(mask == WL_EVENT_READABLE);

	int client_fd = accept(ipc_socket, NULL, NULL);
	if (client_fd == -1) {
		wlr_log_errno(WLR_ERROR, "Unable to accept IPC client connection");
		return 0;
	}

	int flags;
	if ((flags = fcntl(client_fd, F_GETFD)) == -1
			|| fcntl(client_fd, F_SETFD, flags|FD_CLOEXEC) == -1) {
		wlr_log_errno(WLR_ERROR, "Unable to set CLOEXEC on IPC client socket");
		close(client_fd);
		return 0;
	}
	if ((flags = fcntl(client_fd, F_GETFL)) == -1
			|| fcntl(client_fd, F_SETFL, flags|O_NONBLOCK) == -1) {
		wlr_log_errno(WLR_ERROR, "Unable to set NONBLOCK on IPC client socket");
		close(client_fd);
		return 0;
	}

	struct ipc_client *client = malloc(sizeof(struct ipc_client));
	if (!client) {
		wlr_log(WLR_ERROR, "Unable to allocate ipc client");
		close(client_fd);
		return 0;
	}
	client->server = server;
	client->pending_length = 0;
	client->fd = client_fd;
	client->subscribed_events = 0;
	client->event_source = wl_event_loop_add_fd(server->wl_event_loop,
			client_fd, WL_EVENT_READABLE, ipc_client_handle_readable, client);
	client->writable_event_source = NULL;

	client->write_buffer_size = 128;
	client->write_buffer_len = 0;
	client->write_buffer = malloc(client->write_buffer_size);
	if (!client->write_buffer) {
		wlr_log(WLR_ERROR, "Unable to allocate ipc client write buffer");
		close(client_fd);
		return 0;
	}

	wlr_log(WLR_DEBUG, "New client: fd %d", client_fd);
    wl_list_insert(&ipc_client_list, &client->link);
	return 0;
}

int ipc_client_handle_readable(int client_fd, uint32_t mask, void *data) {
	struct ipc_client *client = data;

	if (mask & WL_EVENT_ERROR) {
		wlr_log(WLR_ERROR, "IPC Client socket error, removing client");
		ipc_client_disconnect(client);
		return 0;
	}

	if (mask & WL_EVENT_HANGUP) {
		ipc_client_disconnect(client);
		return 0;
	}

	int read_available;
	if (ioctl(client_fd, FIONREAD, &read_available) == -1) {
		wlr_log_errno(WLR_INFO, "Unable to read IPC socket buffer size");
		ipc_client_disconnect(client);
		return 0;
	}

	// Wait for the rest of the command payload in case the header has already been read
	if (client->pending_length > 0) {
		if ((uint32_t)read_available >= client->pending_length) {
			// Reset pending values.
			uint32_t pending_length = client->pending_length;
			enum ipc_command_type pending_type = client->pending_type;
			client->pending_length = 0;
			ipc_client_handle_command(client, pending_length, pending_type);
		}
		return 0;
	}

	if (read_available < (int) IPC_HEADER_SIZE) {
		return 0;
	}

	uint8_t buf[IPC_HEADER_SIZE];
	// Should be fully available, because read_available >= IPC_HEADER_SIZE
	ssize_t received = recv(client_fd, buf, IPC_HEADER_SIZE, 0);
	if (received == -1) {
		wlr_log_errno(WLR_INFO, "Unable to receive header from IPC client");
		ipc_client_disconnect(client);
		return 0;
	}

	if (memcmp(buf, ipc_magic, sizeof(ipc_magic)) != 0) {
		wlr_log(WLR_DEBUG, "IPC header check failed");
		ipc_client_disconnect(client);
		return 0;
	}

	memcpy(&client->pending_length, buf + sizeof(ipc_magic), sizeof(uint32_t));
	memcpy(&client->pending_type, buf + sizeof(ipc_magic) + sizeof(uint32_t), sizeof(uint32_t));

	if (read_available - received >= (long)client->pending_length) {
		// Reset pending values.
		uint32_t pending_length = client->pending_length;
		enum ipc_command_type pending_type = client->pending_type;
		client->pending_length = 0;
		ipc_client_handle_command(client, pending_length, pending_type);
	}

	return 0;
}

int ipc_client_handle_writable(int client_fd, uint32_t mask, void *data) {
	struct ipc_client *client = data;

	if (mask & WL_EVENT_ERROR) {
		wlr_log(WLR_ERROR, "IPC Client socket error, removing client");
		ipc_client_disconnect(client);
		return 0;
	}

	if (mask & WL_EVENT_HANGUP) {
		ipc_client_disconnect(client);
		return 0;
	}

	if (client->write_buffer_len <= 0) {
		return 0;
	}

	ssize_t written = write(client->fd, client->write_buffer, client->write_buffer_len);

	if (written == -1 && errno == EAGAIN) {
		return 0;
	} else if (written == -1) {
		wlr_log_errno(WLR_INFO, "Unable to send data from queue to IPC client");
		ipc_client_disconnect(client);
		return 0;
	}

	memmove(client->write_buffer, client->write_buffer + written, client->write_buffer_len - written);
	client->write_buffer_len -= written;

	if (client->write_buffer_len == 0 && client->writable_event_source) {
		wl_event_source_remove(client->writable_event_source);
		client->writable_event_source = NULL;
	}

	return 0;
}

void ipc_client_disconnect(struct ipc_client *client) {
	if (!wlr_assert(client != NULL, "client != NULL")) {
		return;
	}

	shutdown(client->fd, SHUT_RDWR);

	wlr_log(WLR_INFO, "IPC Client %d disconnected", client->fd);
	wl_event_source_remove(client->event_source);
	if (client->writable_event_source) {
		wl_event_source_remove(client->writable_event_source);
	}
	wl_list_remove(&client->link);
	free(client->write_buffer);
	close(client->fd);
	free(client);
}

void ipc_client_handle_command(struct ipc_client *client, uint32_t payload_length,
		enum ipc_command_type payload_type) {
	if (!wlr_assert(client != NULL, "client != NULL")) {
		return;
	}

    struct server *server = client->server;

	char *buf = malloc(payload_length + 1);
	if (!buf) {
		wlr_log_errno(WLR_INFO, "Unable to allocate IPC payload");
		ipc_client_disconnect(client);
		return;
	}
	if (payload_length > 0) {
		// Payload should be fully available
		ssize_t received = recv(client->fd, buf, payload_length, 0);
		if (received == -1)
		{
			wlr_log_errno(WLR_INFO, "Unable to receive payload from IPC client");
			ipc_client_disconnect(client);
			free(buf);
			return;
		}
	}
	buf[payload_length] = '\0';

	switch (payload_type) {
	case IPC_GET_FOCUSED_WINDOW:
	{
        struct view *focused = server->focused_view;
        struct wlr_box box = focused->current;
        char buf[128];
        snprintf(buf, 128, "[%d,%d,%d,%d]", box.x, box.y, box.width, box.height);
		ipc_send_reply(client, payload_type, buf,
			(uint32_t)strlen(buf));
		goto exit_cleanup;
	}

	case IPC_TEST:
	{
		// It was decided sway will not support this, just return success:false
		const char msg[] = "{\"success\": true}";
		ipc_send_reply(client, payload_type, msg, strlen(msg));
		goto exit_cleanup;
	}

	default:
		wlr_log(WLR_INFO, "Unknown IPC command type %x", payload_type);
		goto exit_cleanup;
	}

exit_cleanup:
	free(buf);
}

bool ipc_send_reply(struct ipc_client *client, enum ipc_command_type payload_type,
		const char *payload, uint32_t payload_length) {
	assert(payload);

	char data[IPC_HEADER_SIZE];

	memcpy(data, ipc_magic, sizeof(ipc_magic));
	memcpy(data + sizeof(ipc_magic), &payload_length, sizeof(payload_length));
	memcpy(data + sizeof(ipc_magic) + sizeof(payload_length), &payload_type, sizeof(payload_type));

	while (client->write_buffer_len + IPC_HEADER_SIZE + payload_length >=
				 client->write_buffer_size) {
		client->write_buffer_size *= 2;
	}

	if (client->write_buffer_size > 4e6) { // 4 MB
		wlr_log(WLR_ERROR, "Client write buffer too big (%zu), disconnecting client",
				client->write_buffer_size);
		ipc_client_disconnect(client);
		return false;
	}

	char *new_buffer = realloc(client->write_buffer, client->write_buffer_size);
	if (!new_buffer) {
		wlr_log(WLR_ERROR, "Unable to reallocate ipc client write buffer");
		ipc_client_disconnect(client);
		return false;
	}
	client->write_buffer = new_buffer;

	memcpy(client->write_buffer + client->write_buffer_len, data, IPC_HEADER_SIZE);
	client->write_buffer_len += IPC_HEADER_SIZE;
	memcpy(client->write_buffer + client->write_buffer_len, payload, payload_length);
	client->write_buffer_len += payload_length;

	if (!client->writable_event_source) {
		client->writable_event_source = wl_event_loop_add_fd(
				client->server->wl_event_loop, client->fd, WL_EVENT_WRITABLE,
				ipc_client_handle_writable, client);
	}

	return true;
}
