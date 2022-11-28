#include "common/common.h"
#include "common/log.h"
#include "common/socket.h"

#include <sys/epoll.h>
#include <string.h>
#include <assert.h>
#include <threads.h>
#include <stdlib.h>
#include <signal.h>

#define MAX_CONNS 1024

bool running = true;

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

    conn_socks[index] = conn_socks[--(*num_conns)];

    // Get address
    struct address addr = {0};
    get_address(sock, &addr);
    close(sock);

    log_info("(%s:%d) disconnected!", addr.host, addr.port);
    log_info("[%u/%u] connections", *num_conns, MAX_CONNS);

    return 0;
}

void interrupt_handler(int i) {
    (void) i;
    running = false;
}

void *handle_voice(void *args) {
    const char *port = args;

    int accept_sock = socket_bind(SOCK_DGRAM, "9054");
    if (accept_sock == -1)
        thrd_exit(EXIT_FAILURE);

    unsigned char buf[2 << 16] = {0};

    struct sockaddr_storage their_addr;
    socklen_t addrlen = sizeof(their_addr);

    while (running) {
        ssize_t numbytes = recvfrom(accept_sock, buf, ARRLEN(buf), 0, (struct sockaddr *) &their_addr, &addrlen);
        if (numbytes == -1) {
            log_error("recvfrom failed: %s", strerror(errno));
            continue;
        }
        log_info("Read %d bytes", numbytes);

        if (socket_sendto_all(accept_sock, &their_addr, buf, numbytes) == -1) {
            log_error("sendto failed: %s", strerror(errno));
        }
    }

    log_info("Closing voice thread");
    close(accept_sock);
    thrd_exit(EXIT_SUCCESS);
}

int main(int argc, char **argv) {
    if (argc != 2) {
        log_error("Usage: gn-server [port]");
        return 1;
    }

    signal(SIGINT, interrupt_handler);

    const char *port = argv[1];

    thrd_t voice_thread;
    if (thrd_create(&voice_thread, (thrd_start_t) handle_voice, (void *) port) == thrd_error) {
        log_info("Failed to create voice thread");
        return 1;
    }

    // Create TCP socket for normal chatting
    int chat_accept_sock = socket_bind(SOCK_STREAM, port);
    if (chat_accept_sock == -1)
        return 1;

    log_info("Bound socket to port %s!", port);
    log_info("Listening...");

    // Use `listen` to mark `chat_accept_socket`
    // and `voice_accept_sock` as accepting connections.
    const unsigned backlog = 512;
    if (listen(chat_accept_sock, backlog) == -1) {
        log_error("Failed to listen: %s", strerror(errno));
        return 1;
    }

    // Setup epoll
    int set = epoll_create1(0);
    if (set == -1) {
        log_error("Failed to create epoll fd: %s", strerror(errno));
        return 1;
    }

    // Add `chat_accept_socket` to epoll, note: not edge triggered (EPOLLET)
    set_blocking(chat_accept_sock, false);
    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = chat_accept_sock,
    };
    if (epoll_ctl(set, EPOLL_CTL_ADD, chat_accept_sock, &ev) == -1) {
        log_error("Failed to add new connected fd to epoll: %s!", strerror(errno));
        return 1;
    }

    unsigned char buf[2048] = {0};

    int chat_num_conns = 0;
    int chat_conn_socks[MAX_CONNS] = {0};

    // Wait on events from epoll
    struct epoll_event events[64] = {0};
    while (running) {
        const int num_events = epoll_wait(set, events, ARRLEN(events), -1);
        if (num_events == -1) {
            log_error("epoll_wait() failed: %s", strerror(errno));
            return 1;
        }

        for (int i = 0; i < num_events; ++i) {
            if (events[i].data.fd == chat_accept_sock) {
                // Accept new connection
                struct address addr = {0};

                int sock = socket_accept(chat_accept_sock, &addr);
                if (sock == -1) {
                    log_error("Failed to accept incoming connection!");
                    return 1;
                }

                if (chat_num_conns >= MAX_CONNS) {
                    // Immediately close connection.
                    //
                    // TODO(anjo): Some improvements, either
                    //     1. Send rejection packet, so client knows what's up
                    //     2. Close accept socket once full so no connection attempts can
                    //        be made.
                    close(sock);
                    log_warning("Dropping pending connection (out of room)!");
                    continue;
                }
                chat_conn_socks[chat_num_conns++] = sock;

                log_info("(%s:%d) connected!", addr.host, addr.port);
                log_info("[%u/%u] connections", chat_num_conns, MAX_CONNS);

                set_blocking(sock, false);
                struct epoll_event ev = {
                    .events = EPOLLIN | EPOLLET | EPOLLRDHUP,
                    .data.fd = sock,
                };
                if (epoll_ctl(set, EPOLL_CTL_ADD, sock, &ev) == -1) {
                    log_error("Failed to add new connected fd to epoll: %s!", strerror(errno));
                    return 1;
                }
            } else if (events[i].events & EPOLLRDHUP) {
                // Client disconnected
                disconnect_client(set, events[i].data.fd, chat_conn_socks, &chat_num_conns);
            } else if (events[i].events & EPOLLIN) {
                // Data on the socket
                int sock = events[i].data.fd;
                memset(buf, 0, sizeof(buf));
                ssize_t bytes_read = socket_recv_all(sock, buf, sizeof(buf));
                if (bytes_read == -1) {
                    disconnect_client(set, events[i].data.fd, chat_conn_socks, &chat_num_conns);
                    continue;
                }

                // TODO(anjo): Save this info alongside the socket in chat_conn_socks?
                // Might be nice to not have to fetch it from the kernel every time.
                struct address addr = {0};
                get_address(sock, &addr);
                log_info("(%s:%d) sent %uB", addr.host, addr.port, bytes_read);

                // Forward data to all connected clients
                for (int i = 0; i < chat_num_conns; ++i) {
                    int sock = chat_conn_socks[i];
                    if (socket_send_all(sock, buf, bytes_read) == -1) {
                        disconnect_client(set, sock, chat_conn_socks, &chat_num_conns);
                        close(sock);
                    }
                }
            } else {
                log_error("Unhandled epoll event!");
            }
        }
    }

    thrd_join(voice_thread, NULL);

    close(chat_accept_sock);

    return 1;
}
