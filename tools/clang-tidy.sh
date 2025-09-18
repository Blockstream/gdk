#!/usr/bin/env bash
set -e

PREBUILT_DIR=$1

have_cmd()
{
    command -v "$1" >/dev/null 2>&1
}

if have_cmd clang-tidy; then
    CLANG_TIDY=$(command -v clang-tidy)
    files=$(echo src/*.{c,h}pp)
    files=$(echo $files | tr ' ' '\n' | grep -v generated | tr '\n' ' ')
    $CLANG_TIDY --quiet $files -- -std=c++17 -Iinclude/ -Isubprojects/gdk_rust/ -I$1/include/ 2>/dev/null
else
    echo "ERROR: clang-tidy not found, C++ code not analyzed"
    exit 1
fi
