#include "common/common.h"
#include "common/log.h"
#include "common/socket.h"
#include "common/stack.h"
#include "common/packet.h"
#include "common/net-protocol.h"
#include "crypto.h"

#include <netinet/in.h>
#include <stdio.h>

#include <sys/epoll.h>
#include <string.h>
#include <assert.h>

#define MAX_CONNS 64

struct client {
    int sock;
    enum connection_state state; // Default state is DISCONNECTED
    struct address addr;
};

static ssize_t find_client_by_socket(struct client *clients, size_t num_clients, int sock) {
    for (ssize_t i = 0; i < (ssize_t) num_clients; ++i)
        if (clients[i].sock == sock)
            return i;
    return -1;
}

static int disconnect_client(int set, ssize_t index, struct client *clients, int *num_conns) {
    struct client client = clients[index];

    // Remove from epoll
    if (epoll_ctl(set, EPOLL_CTL_DEL, client.sock, NULL) == -1) {
        log_error("Failed to remove disconnected fd from epoll: %s!\n", strerror(errno));
        return 1;
    }

    // Remove from client array
    clients[index] = clients[--(*num_conns)];

    close(client.sock);

    log_info("(%s:%d) disconnected!", client.addr.host, client.addr.port);
    log_info("[%u/%u] connections", *num_conns, MAX_CONNS);

    return 0;
}

int main(int argc, char **argv) {

    //daemon(1, 1);

    if (argc != 2) {
        log_error("Usage: gn-server [port]");
        return 1;
    }

    const size_t pagesize = 4096;
    struct stack stack = {
        .size = pagesize,
    };

    FILE *fd_log = fopen("io-server/log", "wr");
    assert(fd_log);

    log_init(fd_log, true);

    crypto_init("keys-server", "password");
    crypto_generate_or_load_keypair(&stack, "server", KEYPAIR_SERVER);
    crypto_generate_or_load_keypair(&stack, "session", KEYPAIR_SESSION);

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
        log_error("Failed to create epoll fd: %s", strerror(errno));
        return 1;
    }

    // Add accept socket to epoll, note: not edge triggered (EPOLLET)
    set_blocking(accept_sock, false);
    struct epoll_event ev = {
        .events = EPOLLIN,
        .data.fd = accept_sock,
    };
    if (epoll_ctl(set, EPOLL_CTL_ADD, accept_sock, &ev) == -1) {
        log_error("Failed to add new connected fd to epoll: %s!", strerror(errno));
        return 1;
    }

    int num_conns = 0;
    struct client clients[MAX_CONNS] = {0};

    // Wait on events from epoll
    struct epoll_event events[64] = {0};
    while (true) {
        stack_clear(&stack);

        const int num_events = epoll_wait(set, events, ARRLEN(events), -1);
        if (num_events == -1) {
            log_error("epoll_wait() failed: %s", strerror(errno));
            return 1;
        }

        for (int i = 0; i < num_events; ++i) {
            if (events[i].data.fd == accept_sock) {
                // Accept new connection
                struct address addr = {0};

                int sock = socket_accept(accept_sock, &addr);
                if (sock == -1) {
                    log_error("Failed to accept incoming connection!");
                    return 1;
                }

                if (num_conns >= MAX_CONNS) {
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

                log_info("(%s:%d) connected!", addr.host, addr.port);
                log_info("[%u/%u] connections", num_conns, MAX_CONNS);

                set_blocking(sock, false);
                struct epoll_event ev = {
                    .events = EPOLLIN | EPOLLET | EPOLLRDHUP,
                    .data.fd = sock,
                };
                if (epoll_ctl(set, EPOLL_CTL_ADD, sock, &ev) == -1) {
                    log_error("Failed to add new connected fd to epoll: %s!", strerror(errno));
                    return 1;
                }

                // Send server public key to initiate handshake
                size_t keylen;
                const uint8_t *key = crypto_get_key(&stack, "server", KEYPAIR_SERVER, KEY_PUBLIC, &keylen);
                if (key == NULL) {
                    log_error("Failed to get key");
                    return 1;
                }
                log_info("sending key w len %ld", keylen);
                struct packet p = {
                    .name = "server",
                    .data = key,
                    .data_size = keylen
                };
                const uint8_t *output = packet_encode(&stack, &p);
                if (socket_send_all(sock, output, packet_size(&p)) == -1) {
                    log_error("Server failed to initiate handshake (send failed)!");
                    break;
                }

                clients[num_conns++] = (struct client) {
                    .sock = sock,
                    .state = HANDSHAKE_WAIT_SERVER_PUB,
                    .addr = addr,
                };
            } else if (events[i].events & EPOLLRDHUP) {
                ssize_t index = find_client_by_socket(clients, num_conns, events[i].data.fd);
                disconnect_client(set, index, clients, &num_conns);
            } else if (events[i].events & EPOLLIN) {
                // Data on the socket
                int sock = events[i].data.fd;
                ssize_t index = find_client_by_socket(clients, num_conns, sock);
                struct client *client = &clients[index];
                uint8_t *buf;
                ssize_t bytes_read = socket_recv_all(&stack, sock, &buf);
                if (bytes_read == -1) {
                    disconnect_client(set, index, clients, &num_conns);
                    continue;
                }

                if (client->state == CONNECTED) {
                    // Forward data to all connected clients
                    for (int i = 0; i < num_conns; ++i) {
                        int sock = clients[i].sock;
                        if (socket_send_all(sock, buf, bytes_read) == -1) {
                            disconnect_client(set, index, clients, &num_conns);
                            close(sock);
                        }
                    }
                } else {
                    struct packet packet_in = {0};
                    ssize_t read_size = 0;
                    while (read_size < bytes_read &&
                           packet_decode(buf + read_size, bytes_read, &packet_in) == 0) {
                        read_size += packet_size(&packet_in);
                        switch (client->state) {
                        case CONNECTED: {
                            break;
                        }
                        case DISCONNECTED:
                            log_error("Data received from disconnected client, drop");
                            continue;
                        case HANDSHAKE_WAIT_SERVER_PUB: {
                            log_info("  [handshake] received encrypted public key len: %d", packet_in.data_size);

                            uint8_t *decrypted_key;
                            size_t decrypted_key_len;
                            crypto_decrypt(&stack, packet_in.data, packet_in.data_size, &decrypted_key, &decrypted_key_len);

                            crypto_add_key(&stack, decrypted_key, decrypted_key_len, KEY_PUBLIC);

                            uint8_t *challenge = "hello";
                            size_t challenge_len = 5;

                            uint8_t *out;
                            size_t out_len;
                            crypto_encrypt(&stack, packet_in.name, KEYPAIR_USER, challenge, challenge_len, &out, &out_len);

                            struct packet p = {
                                .name = "server",
                                .data = out,
                                .data_size = out_len
                            };
                            const uint8_t *output = packet_encode(&stack, &p);
                            if (socket_send_all(sock, output, packet_size(&p)) == -1) {
                                log_error("Failed to send public key (send failed)!");
                                break;
                            }

                            client->state = HANDSHAKE_CHALLENGE;
                            break;
                        }
                        case HANDSHAKE_CHALLENGE: {
                            log_info("  [handshake] received challenge response:");

                            uint8_t *decrypted_challenge;
                            size_t decrypted_challenge_len;
                            crypto_decrypt(&stack, packet_in.data, packet_in.data_size, &decrypted_challenge, &decrypted_challenge_len);

                            log_info("    %.*s", (int) decrypted_challenge_len, decrypted_challenge);

                            size_t session_pub_key_len;
                            size_t session_prv_key_len;
                            const uint8_t *session_pub_key = crypto_get_key(&stack, "session", KEYPAIR_SESSION, KEY_PUBLIC, &session_pub_key_len);
                            const uint8_t *session_prv_key = crypto_get_key(&stack, "session", KEYPAIR_SESSION, KEY_PRIVATE, &session_prv_key_len);

                            const uint8_t *data = stack_top(&stack);
                            stack_push_value(&stack, uint32_t, htonl(session_pub_key_len));
                            stack_push_value(&stack, uint32_t, htonl(session_prv_key_len));
                            stack_push_bytes(&stack, session_pub_key, session_pub_key_len);
                            stack_push_bytes(&stack, session_prv_key, session_prv_key_len);
                            const uint32_t data_len = stack_top(&stack) - data;

                            uint8_t *out;
                            size_t out_len;
                            crypto_encrypt(&stack, packet_in.name, KEYPAIR_USER, data, data_len, &out, &out_len);

                            struct packet p = {
                                .name = "server",
                                .data = out,
                                .data_size = out_len
                            };
                            const uint8_t *output = packet_encode(&stack, &p);
                            if (socket_send_all(sock, output, packet_size(&p)) == -1) {
                                log_error("Failed to send public key (send failed)!");
                                break;
                            }

                            client->state = CONNECTED;
                            break;
                        }
                        case HANDSHAKE_WAIT_SESSION_KEYS: {
                            break;
                        }
                        default:
                            assert(false);
                        }
                    }
                }

            } else {
                log_error("Unhandled epoll event!");
            }
        }
    }

    crypto_deinit();
    stack_deinit(&stack);

    close(accept_sock);

    return 1;
}
