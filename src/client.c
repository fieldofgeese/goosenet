#include "log.h"
#include "socket.h"

// stdlib
#include <stdio.h>
#include <string.h>

enum return_values {
    GN_SUCCESS = 0,
    GN_INVALID_USAGE,
    GN_INVALID_SOCKET,
    GN_CONNECTION_FAILURE,
};

int main(int argc, char **argv) {
    if (argc < 3) {
        log_error("Usage: gn-client [hostname] [port]");
        return GN_INVALID_USAGE;
    } else if (argc > 3) {
        log_warning("Ignoring extra arguments!");
    }

    const char *host = argv[1];
    const char *port = argv[2];

    int sock = socket_connect(host, port);
    if (sock == -1) {
        return GN_INVALID_SOCKET;
    }

    log_info("Connected!");

    unsigned char buf[256] = {0};

    while (true) {
        printf("| ");
        memset(buf, 0, sizeof(buf));
        if (fgets((char *) buf, sizeof(buf)-1, stdin) == NULL) {
            break;
        }

        // Send strlen(buf)-1 to remove trailing newline
        if (socket_send_all(sock, buf, strlen((char *) buf)-1) == -1) {
            log_error("Server disconnected!");
            break;
        }

        memset(buf, 0, sizeof(buf));
        if (socket_recv_all(sock, buf, sizeof(buf)-1) == -1) {
            log_error("Server disconnected!");
            break;
        }
        printf("> %s\n", buf);
    }

    close(sock);

    return GN_SUCCESS;
}
