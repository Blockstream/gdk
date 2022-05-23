#!/usr/bin/env bash
set -e

have_cmd()
{
    command -v "$1" >/dev/null 2>&1
}

if have_cmd clang-format; then
    CLANG_FORMAT=$(command -v clang-format)
    files=$(echo src/*.{c,h}pp include/*.h tests/*cpp)
    files=$(echo $files | tr ' ' '\n' | grep -v generated | tr '\n' ' ')
    $CLANG_FORMAT -i $files
else
    echo "WARNING: clang-format not found, C++ code not formatted"
fi

if ! have_cmd cargo; then
    if [ -f "/root/.cargo/env" ]; then
        # Docker CI
        source /root/.cargo/env
    fi
fi

if have_cmd cargo; then
    CARGO=$(command -v cargo)
    pushd subprojects/gdk_rust >/dev/null
    $CARGO fmt
    popd >/dev/null
else
    echo "WARNING: cargo not found, Rust code not formatted"
fi
