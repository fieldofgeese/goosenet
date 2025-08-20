#!/bin/bash

INSTALL_PREFIX=~/.local

BUILD_DIR=build

COMMON_SRCS="src/common/log.c \
             src/common/socket.c \
             src/crypto.c"

COMMON_FLAGS="-Wextra -Wall -std=gnu11 -I rnp/include -L rnp/lib -lrnp"
DEBUG_FLAGS="-fsanitize=address -g -O3"

[ ! -d ${BUILD_DIR} ] && mkdir ${BUILD_DIR}

[ ! -d rnp ] && mkdir rnp
[ ! -d ${BUILD_DIR}/rnp ] && mkdir ${BUILD_DIR}/rnp && git submodule update --init --recursive && cmake -DCMAKE_INSTALL_PREFIX=${INSTALL_PREFIX} -DBUILD_SHARED_LIBS=on -DBUILD_TESTING=off -S $(pwd)/submodules/rnp -B ${BUILD_DIR}/rnp && make -C ${BUILD_DIR}/rnp install

clang -o ${BUILD_DIR}/gn-client ${COMMON_FLAGS} ${DEBUG_FLAGS} ${COMMON_SRCS} src/client.c
clang -o ${BUILD_DIR}/gn-server ${COMMON_FLAGS} ${DEBUG_FLAGS} ${COMMON_SRCS} src/server.c
