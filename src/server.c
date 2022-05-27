#include "common/log.h"
#include "common/socket.h"

#include <sys/epoll.h>
#include <string.h>
#include <assert.h>

#define ARRLEN(arr) \
    (sizeof(arr)/sizeof(arr[0]))

#define MAX_CONNS 64

int main(int argc, char **argv) {
    if (argc != 2) {
        log_error("Usage: gn-server [port]");
        return 1;
    }

    const char *port = argv[1];

    int accept_sock = socket_bind(port);
    if (accept_sock == -1) {
        return 1;
    }

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
                if (epoll_ctl(set, EPOLL_CTL_DEL, events[i].data.fd, NULL) == -1) {
                    log_error("Failed to remove disconnected fd from epoll: %s!\n", strerror(errno));
                    return 1;
                }
                int index = 0;
                for (; index < num_conns; ++index)
                    if (conn_socks[index] == events[i].data.fd)
                        break;
                assert(index < num_conns);
                for (int i = index+1; i < num_conns; ++i)
                    conn_socks[i-1] = conn_socks[i];
                --num_conns;
                close(events[i].data.fd);
            } else if (events[i].events & EPOLLIN) {
                // Data on the socket
                int sock = events[i].data.fd;
                log_info("Waiting on data...");
                memset(buf, 0, sizeof(buf));
                if (socket_recv_all(sock, buf, sizeof(buf)-1) == -1) {
                    log_info("Client disconnected");
                    if (epoll_ctl(set, EPOLL_CTL_DEL, events[i].data.fd, NULL) == -1) {
                        log_error("Failed to remove disconnected fd from epoll: %s!\n", strerror(errno));
                        return 1;
                    }
                    int index = 0;
                    for (; index < num_conns; ++index)
                        if (conn_socks[index] == events[i].data.fd)
                            break;
                    assert(index < num_conns);
                    for (int i = index+1; i < num_conns; ++i)
                        conn_socks[i-1] = conn_socks[i];
                    --num_conns;
                    close(events[i].data.fd);
                    continue;
                }
                log_info("    Got: %s", buf);

                // Send back the same data they sent us.
                log_info("    Sending response");
                for (int i = 0; i < num_conns; ++i) {
                    int sock = conn_socks[i];
                    if (socket_send_all(sock, buf, strlen((char *) buf)) == -1) {
                        log_info("Client disconnected");
                        if (epoll_ctl(set, EPOLL_CTL_DEL, sock, NULL) == -1) {
                            log_error("Failed to remove disconnected fd from epoll: %s!\n", strerror(errno));
                            return 1;
                        }
                        int index = 0;
                        for (; index < num_conns; ++index)
                            if (conn_socks[index] == sock)
                                break;
                        assert(index < num_conns);
                        for (int i = index+1; i < num_conns; ++i)
                            conn_socks[i-1] = conn_socks[i];
                        --num_conns;
                        close(sock);
                    }
                }
            } else {
                log_error("Unhandled epoll event!");
            }
        }
    }

    // Here's a simple loop that serves one client at a time,
    // we do the following:
    //   1. Call `socket_accept` in a loop (blocks), will return when
    //      we have a new connection.
    //
    //   2. In a new loop, keep reading and writing data to the
    //      client, until the connection is closed.
    //
    //   3. Close client socket and goto 1 to wait for new connection.
    //while (true) {
    //    log_info("Accepting connection...");
    //    int sock = socket_accept(accept_sock);
    //    if (sock == -1) {
    //        return 1;
    //    }

    //    // The new connection can now be reached on
    //    // `sock`. Make sure we set it to blocking,
    //    // (might not be needed but you never know.)
    //    socket_set_blocking(sock, true);

    //    // Respond to connection until it's closed.
    //    unsigned char buf[256] = {0};
    //    while (true) {
    //        // Assume the client attemps to send us data, so
    //        // get it here (blocking).
    //        log_info("Waiting on data...");
    //        memset(buf, 0, sizeof(buf));
    //        if (socket_recv_all(sock, buf, sizeof(buf)-1) == -1) {
    //            log_info("Client disconnected");
    //            break;
    //        }
    //        log_info("    Got: %s", buf);

    //        // Send back the same data they sent us.
    //        log_info("    Sending response");
    //        if (socket_send_all(sock, buf, strlen((char *) buf)) == -1) {
    //            log_info("Client disconnected");
    //            break;
    //        }
    //    }

    //    close(sock);
    //}

    close(accept_sock);

    return 1;
}
