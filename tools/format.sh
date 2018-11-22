#!/usr/bin/env bash
set -e

if [ -d build-clang ]; then
    BUILD_DIR=build-clang
else
    BUILD_DIR=build-gcc
fi
(cd $BUILD_DIR && ninja src/clang-format)
