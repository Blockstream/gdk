#!/usr/bin/env bash
set -e

if [ \( "$(uname)" = "Darwin" \) ]; then
    export XCODE_PATH=$(xcode-select --print-path 2>/dev/null)
    export PLATFORM="MacOSX"
    export SDK_PATH="$XCODE_PATH/Platforms/$PLATFORM.platform/Developer/SDKs/$PLATFORM.sdk"
    export SDK_CFLAGS="$SDK_CFLAGS -isysroot ${SDK_PATH} -mmacosx-version-min=10.13"
    export SDK_CXXFLAGS="$SDK_CXXFLAGS -isysroot ${SDK_PATH} -mmacosx-version-min=10.13"
    export SDK_LDFLAGS="$SDK_LDFLAGS -isysroot ${SDK_PATH} -mmacosx-version-min=10.13"
    export CFLAGS="${SDK_CFLAGS} -O2"
    export CXXFLAGS="${SDK_CXXFLAGS} -O2"
    export LDFLAGS="${SDK_LDFLAGS}"
fi
