#!/usr/bin/env bash
set -e

clang-format -i src/*.{c,h}pp include/*.h

if [ -f "/root/.cargo/env" ]; then
    source /root/.cargo/env
    pushd subprojects/gdk_rust
    cargo fmt --all
    popd
fi
