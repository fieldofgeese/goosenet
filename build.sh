#!/bin/sh

gcc -g src/common/log.c src/common/socket.c src/client.c -o gn-client
gcc -g src/common/log.c src/common/socket.c src/server.c -o gn-server
