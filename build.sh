#!/bin/sh

gcc -g src/log.c src/socket.c src/client.c -o gn-client
gcc -g src/log.c src/socket.c src/server.c -o gn-server
