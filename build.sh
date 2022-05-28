#!/bin/sh

clang -g src/common/log.c src/common/socket.c src/client.c -o gn-client
clang -g src/common/log.c src/common/socket.c src/server.c -o gn-server
