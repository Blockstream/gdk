#! /usr/bin/env bash
set -e

cd "${PRJ_SUBDIR}"

make \
    prefix=${GDK_BUILD_ROOT} \
    BUILD_SHARED=0 BUILD_STATIC=1 \
    CC=${CC} CXX=${CXX} \
    CFLAGS="${CFLAGS} -DWITHOUT_OPEN_MEMSTREAM" LDFLAGS="${LDFLAGS}" \
    lib/libtinycbor.a \
    install
