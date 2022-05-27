#include "common/log.h"
#include "common/socket.h"

#include <sys/epoll.h>
#include <string.h>
#include <assert.h>

#define ARRLEN(arr) \
    (sizeof(arr)/sizeof(arr[0]))

#define MAX_CONNS 64

static int disconnect_client(int set, int sock, int *conn_socks, int *num_conns) {
    // Remove from epoll
    if (epoll_ctl(set, EPOLL_CTL_DEL, sock, NULL) == -1) {
        log_error("Failed to remove disconnected fd from epoll: %s!\n", strerror(errno));
        return 1;
    }

    // Remove from client array
    int index = 0;
    for (; index < *num_conns; ++index)
        if (conn_socks[index] == sock)
            break;
    assert(index < *num_conns);
    for (int i = index+1; i < *num_conns; ++i)
        conn_socks[i-1] = conn_socks[i];
    --(*num_conns);
    close(sock);

    log_info("Client disconnected!");

    return 0;
}

int main(int argc, char **argv) {
    if (argc != 2) {
        log_error("Usage: gn-server [port]");
        return 1;
    }

    const char *port = argv[1];

    int accept_sock = socket_bind(port);
    if (accept_sock == -1)
        return 1;

    log_info("Bound socket to port %s!", port);
    log_info("Listening...");

    // Use `listen` to mark `accept_socket` as
    // accepting connections.
    const unsigned backlog = 512;
    if (listen(accept_sock, backlog) == -1) {
        log_error("Failed to listen: %s", strerror(errno));
        return 1;
    }

    // Setup epoll
    int set = epoll_create1(0);
    if (set == -1) {
        log_error("Failed to create pollset: %s", strerror(errno));
        return 1;
    }

    // Add accept socket to epoll, note: not edge triggered (EPOLLET)
    set_blocking(accept_sock, false);
    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = accept_sock,
    };
    if (epoll_ctl(set, EPOLL_CTL_ADD, accept_sock, &ev) == -1) {
        log_error("Failed to add new connected fd to epoll: %s!\n", strerror(errno));
        return 1;
    }

    unsigned char buf[2048] = {0};
    unsigned char *input = buf;

    int num_conns = 0;
    int conn_socks[MAX_CONNS] = {0};

    // Wait on events from epoll
    struct epoll_event events[64] = {0};
    while (true) {
        const int num_events = epoll_wait(set, events, ARRLEN(events), -1);
        if (num_events == -1) {
            log_error("epoll_wait() failed: %s", strerror(errno));
            return 1;
        }

        for (int i = 0; i < num_events; ++i) {
            if (events[i].data.fd == accept_sock) {
                // Accept new connection
                if (num_conns >= MAX_CONNS) {
                    // TODO(anjo): A better way to handle this would be to accept
                    // the connection, and quickly answer, letting the client know
                    // the room is full.
                    log_warning("Pending connection, but we're out of room!");
                    continue;
                }

                int sock = socket_accept(accept_sock);
                if (sock == -1) {
                    log_error("Failed to accept incoming connection!\n");
                    return 1;
                }
                conn_socks[num_conns++] = sock;
                set_blocking(sock, false);
                struct epoll_event ev = {
                    .events = EPOLLIN | EPOLLET | EPOLLRDHUP,
                    .data.fd = sock,
                };
                if (epoll_ctl(set, EPOLL_CTL_ADD, sock, &ev) == -1) {
                    log_error("Failed to add new connected fd to epoll: %s!\n", strerror(errno));
                    return 1;
                }
            } else if (events[i].events & EPOLLRDHUP) {
                // Client disconnected
                disconnect_client(set, events[i].data.fd, conn_socks, &num_conns);
            } else if (events[i].events & EPOLLIN) {
                // Data on the socket
                int sock = events[i].data.fd;
                memset(buf, 0, sizeof(buf));
                size_t bytes_read = socket_recv_all(sock, buf, sizeof(buf));
                if (bytes_read == -1) {
                    disconnect_client(set, events[i].data.fd, conn_socks, &num_conns);
                    continue;
                }

                log_info("Received %u bytes\n", bytes_read);

                // Send back the same data they sent us.
                for (int i = 0; i < num_conns; ++i) {
                    int sock = conn_socks[i];
                    if (socket_send_all(sock, buf, bytes_read) == -1) {
                        disconnect_client(set, sock, conn_socks, &num_conns);
                        close(sock);
                    }
                }
            } else {
                log_error("Unhandled epoll event!");
            }
        }
    }

    close(accept_sock);

    return 1;
}
