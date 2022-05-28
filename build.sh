#!/bin/bash

BUILD_DIR=build

COMMON_SRCS="src/common/log.c \
             src/common/socket.c"

COMMON_FLAGS="-Wextra -Wall -std=gnu11"
DEBUG_FLAGS="-fsanitize=address -g -O0"

[ ! -d ${BUILD_DIR} ] && mkdir ${BUILD_DIR}

clang -o ${BUILD_DIR}/gn-client ${COMMON_FLAGS} ${DEBUG_FLAGS} ${COMMON_SRCS} src/client.c
clang -o ${BUILD_DIR}/gn-server ${COMMON_FLAGS} ${DEBUG_FLAGS} ${COMMON_SRCS} src/server.c
