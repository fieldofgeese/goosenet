#pragma once

#include <stdbool.h>

#include <unistd.h> // So the including code can use `close`
#include <errno.h>
#include <sys/socket.h>
#include <netdb.h>

//
// Common socket operations
//

struct address {
    char host[INET6_ADDRSTRLEN];
    int port;
};

// Should the fd block? i.e. should it
// wait until data is available or return
// immediately if there's no data.
//
// Works for non-socket fds!
void set_blocking(int fd, bool state);

// Send all data to the socket.
int socket_send_all(int sock, const unsigned char *data, const size_t size);

// Receive all data available in the socket.
ssize_t socket_recv_all(int sock, unsigned char *buf, const size_t buf_size);

// Create a new TCP socket and attempts to connect to.
// the specified host:port.
int socket_connect(const char *host, const char *port);

// Creates and binds a new TCP socket to the specified port. The socket
// is setup to be able to accept connections.
int socket_bind(const char *port);

// Accept a new connection on the socket passed in.
// Requires the socket to be set up for accepting connections
// (e.g. created with socket_bind above) and to have called
// `listen(...)` on the socket previously.
int socket_accept(int sock, struct address *addr);

// Get address (hostname/port) from socket or sockaddr_storage.
void get_address_from_storage(struct sockaddr_storage *storage, struct address *addr);
void get_address(const int sock, struct address *addr);
