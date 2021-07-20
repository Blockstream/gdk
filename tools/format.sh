#!/usr/bin/env bash
set -e

files=$(echo src/*.{c,h}pp include/*.h tests/*cpp tools/*cpp)
files=$(echo $files | tr ' ' '\n' | grep -v generated | tr '\n' ' ')
clang-format -i $files

if [ -f "/root/.cargo/env" ]; then
    source /root/.cargo/env
    pushd subprojects/gdk_rust
    cargo fmt --all
    popd
fi
