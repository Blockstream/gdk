#!/usr/bin/env bash
set -e

PREBUILT_DIR=$1

have_cmd()
{
    command -v "$1" >/dev/null 2>&1
}

if have_cmd clang-tidy; then
    CLANG_TIDY=$(command -v clang-tidy)
    TARGET_BRANCH=${2:-"master"}
    files=$(git diff --name-only --format="" origin/$TARGET_BRANCH...HEAD | grep -E '\.(cpp|h|hpp)$' || true)
    if [ ! -z "$files" ]; then
        files=$(echo $files | tr ' ' '\n' | grep -v generated | tr '\n' ' ')
        cmd="$CLANG_TIDY $files -- -std=c++17 -Iinclude/ -Isubprojects/gdk_rust/ -I${1%/}/include/"
        echo "$cmd"
        $cmd
    else
        echo "No source files changed, skipping clang-tidy analysis"
    fi
else
    echo "ERROR: clang-tidy not found, C++ code not analyzed"
    exit 1
fi
