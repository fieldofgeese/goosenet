#include "log.h"
#include "socket.h"

// stdlib
#include <string.h>

enum return_values {
    GN_SUCCESS = 0,
    GN_INVALID_USAGE,
    GN_INVALID_SOCKET,
    GN_BIND_FAILURE,
    GN_LISTEN_FAILURE,
    GN_ACCEPT_FAILURE,
};

int main(int argc, char **argv) {
    if (argc < 2) {
        log_error("Usage: gn-server [port]");
        return GN_INVALID_USAGE;
    } else if (argc > 2) {
        log_warning("Ignoring extra arguments!");
    }

    const char *port = argv[1];

    int accept_sock = socket_bind(port);
    if (accept_sock == -1) {
        return GN_BIND_FAILURE;
    }

    log_info("Bound socket to port %s!", port);
    log_info("Listening...");

    // Use `listen` to mark `accept_socket` as
    // accepting connections.
    const unsigned backlog = 512;
    if (listen(accept_sock, backlog) == -1) {
        log_error("Failed to listen: %s", strerror(errno));
        return GN_LISTEN_FAILURE;
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
    while (true) {
        log_info("Accepting connection...");
        int sock = socket_accept(accept_sock);
        if (sock == -1) {
            return GN_ACCEPT_FAILURE;
        }

        // The new connection can now be reached on
        // `sock`. Make sure we set it to blocking,
        // (might not be needed but you never know.)
        socket_set_blocking(sock, true);

        // Respond to connection until it's closed.
        unsigned char buf[256] = {0};
        while (true) {
            // Assume the client attemps to send us data, so
            // get it here (blocking).
            log_info("Waiting on data...");
            memset(buf, 0, sizeof(buf));
            if (socket_recv_all(sock, buf, sizeof(buf)-1) == -1) {
                log_info("Client disconnected");
                break;
            }
            log_info("    Got: %s", buf);

            // Send back the same data they sent us.
            log_info("    Sending response");
            if (socket_send_all(sock, buf, strlen((char *) buf)) == -1) {
                log_info("Client disconnected");
                break;
            }
        }

        close(sock);
    }

    close(accept_sock);

    return GN_SUCCESS;
}
