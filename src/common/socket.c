#include "log.h"
#include "socket.h"

#include <string.h>

#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <fcntl.h>

//
// Common socket operations
//

void set_blocking(int fd, bool state) {
    if (state) {
        // Unset O_NONBLOCK flag
        int opts = fcntl(fd, F_GETFL);
        opts &= ~O_NONBLOCK;
        fcntl(fd, F_SETFL, opts);
    } else {
        // Set O_NONBLOCK flag
        fcntl(fd, F_SETFL, O_NONBLOCK);
    }
}

// The `send(...)` function is not guaranteed to actually send all the
// data you tell it to send. So just call send until everything is sent.
int socket_send_all(int sock, const unsigned char *data, const size_t size) {
    size_t total_bytes_sent = 0;
    while (total_bytes_sent < size) {
        ssize_t bytes_sent = send(sock, data + total_bytes_sent, size - total_bytes_sent, 0);
        if (bytes_sent == -1) {
            return -1;
        }
        total_bytes_sent += bytes_sent;
    }

    return 0;
}

// Same here, the `recv(...)` function is not guaranteed to read all the data
// available in the socket, so call it repeatedaly until it returns that
// the socket is emtpy.
size_t socket_recv_all(int sock, unsigned char *buf, const size_t buf_size) {
    size_t total_bytes_received = 0;
    ssize_t bytes_received = 0;

    do {
        bytes_received = recv(sock,
                              buf + total_bytes_received,
                              buf_size - total_bytes_received, 0);

        // TODO(anjo): Is this even used??
        if (total_bytes_received == 0 && bytes_received == 0)
            return -1;

        if (bytes_received == -1) {
            if (errno == EWOULDBLOCK || errno == EAGAIN)
                break;
            else
                return -1;
        }

        total_bytes_received += bytes_received;
    } while (bytes_received > 0);

    return total_bytes_received;
}

int socket_connect(const char *host, const char *port) {
    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,   // IPv4 or IPv6, choose whichever
        .ai_socktype = SOCK_STREAM, // TCP
    };

    // Get possible addresses for the
    // given hostname.
    struct addrinfo *info = NULL;
    int err = getaddrinfo(host, port, &hints, &info);
    if (err != 0) {
        log_error(gai_strerror(err));
        return -1;
    }

    // Loop over possible addresses and connect to
    // the first one which works.
    int sock = -1;
    struct addrinfo *p = NULL;
    for (p = info; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == -1) {
            continue;
        }

        if (connect(sock, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock);
            continue;
        }

        // If we get to there the socket is up and bound.
        break;
    }

    freeaddrinfo(info);

    if (sock == -1) {
        log_info("Failed to create socket");
        return -1;
    } else if (p == NULL) {
        log_info("Failed to connect to %s:%s, no valid addresses", host, port);
        return -1;
    }

    return sock;
}

int socket_bind(const char *port) {
    struct addrinfo hints = {
        .ai_family   = AF_UNSPEC,   // IPv4 or IPv6, choose whichever
        .ai_socktype = SOCK_STREAM, // TCP
        .ai_flags    = AI_PASSIVE,  // We want to accept connections
    };

    struct addrinfo *info = NULL;
    // Pass `NULL` as ip argument as we want to accept connections,
    // specifying ip makes no sense, only port needed.
    int err = getaddrinfo(NULL, port, &hints, &info);
    if (err != 0) {
        log_error(gai_strerror(err));
        return -1;
    }

    // Loop over possible addresses and bind to
    // the first one which works.
    int sock = -1;
    const int yes = 1;
    struct addrinfo *p = NULL;
    for (p = info; p != NULL; p = p->ai_next) {
        sock = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock == -1) {
            continue;
        }

        // Allow address reuse. Nice if server is killed or rebooted,
        // and wants to accept connections to the same address again.
        // Otherwise, the TCP stack will hold the address hostage for
        // a while.
        //
        // See:
        //     https://stackoverflow.com/questions/3229860/what-is-the-meaning-of-so-reuseaddr-setsockopt-option-linux
        if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            continue;
        }

        if (bind(sock, p->ai_addr, p->ai_addrlen) == -1) {
            close(sock);
            continue;
        }

        // If we get to there the socket is up and bound.
        break;
    }

    freeaddrinfo(info);

    if (sock == -1) {
        log_info("Failed to create socket");
        return -1;
    } else if (p == NULL) {
        log_info("Failed to bind to %s, no valid addresses", port);
        return -1;
    }

    return sock;
}

int socket_accept(int sock) {
    struct sockaddr_storage their_addr;
    socklen_t sin_size = sizeof(their_addr);

    int connected_sock = accept(sock, (struct sockaddr *) &their_addr, &sin_size);
    if (connected_sock == -1) {
        log_error("Failed to accept connection: %s", strerror(errno));
        return -1;
    }

    // Might be nice to move this to a separate function,
    // I think it's best to keep track of the ip ourselves,
    // but we could rely on the OS and use `getpeername(...)`.
    int port = 0;
    char ipstr[INET6_ADDRSTRLEN] = {0};
    switch (their_addr.ss_family) {
    case AF_INET: {
        struct sockaddr_in *s = (struct sockaddr_in *) &their_addr;
        port = ntohs(s->sin_port);
        inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof(ipstr));
    } break;
    case AF_INET6: {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *) &their_addr;
        port = ntohs(s->sin6_port);
        inet_ntop(AF_INET6, &s->sin6_addr, ipstr, sizeof(ipstr));
    } break;
    default:
        log_error("Something went horribly wrong, WHO ARE YOU? ._.");
        return -1;
    };

    log_info("%s:%d connected!", ipstr, port);

    return connected_sock;
}
