#! /usr/bin/env bash
set -e

ZLIB_NAME="$(basename ${MESON_SUBDIR})"

if [ ! -d "${MESON_BUILD_ROOT}/zlib" ]; then
    cp -r "${MESON_SOURCE_ROOT}/subprojects/${ZLIB_NAME}" "${MESON_BUILD_ROOT}/zlib"
fi

cd "${MESON_BUILD_ROOT}/zlib"

if [ \( "$1" = "--ndk" \) ]; then
    . ${MESON_SOURCE_ROOT}/tools/env.sh

    export CFLAGS="$CFLAGS -DPIC -fPIC $EXTRA_FLAGS"
    export LDFLAGS="$LDFLAGS $EXTRA_FLAGS"
    ./configure --static --prefix="${MESON_BUILD_ROOT}/zlib/build"
    ARFLAGS=""
    if [ "$(uname)" = "Darwin" ]; then
        ARFLAGS="rc"
    fi
    sed -ie "s!^AR=.*!AR=$AR $ARFLAGS!" "Makefile"
    make -o configure install -j${NUM_JOBS}
elif [ \( "$1" = "--iphone" \) -o \( "$1" = "--iphonesim" \) ]; then
    . ${MESON_SOURCE_ROOT}/tools/ios_env.sh $1

    export CFLAGS="$IOS_CFLAGS $EXTRA_FLAGS"
    export LDFLAGS="$IOS_LDFLAGS $EXTRA_FLAGS"
    export CC=${XCODE_DEFAULT_PATH}/clang
    export CXX=${XCODE_DEFAULT_PATH}/clang++
    ./configure --static --prefix="${MESON_BUILD_ROOT}/zlib/build"
    sed -ie "s!^AR=.*!AR=$AR -r!" "Makefile"
    sed -ie "s!^ARFLAGS=.*!ARFLAGS=!" "Makefile"
    make -o configure clean -j$NUM_JOBS
    make -o configure -j$NUM_JOBS
    make -o configure install
elif [ \( "$1" = "--windows" \) ]; then
     export CC=x86_64-w64-mingw32-gcc-posix
     export CXX=x86_64-w64-mingw32-g++-posix
    ./configure --static --prefix="${MESON_BUILD_ROOT}/zlib/build"

    make -j$NUM_JOBS
    make install
else
    export CFLAGS="$SDK_CFLAGS -DPIC -fPIC $EXTRA_FLAGS"
    export LDFLAGS="$SDK_LDFLAGS $EXTRA_FLAGS"

    ./configure --static --prefix="${MESON_BUILD_ROOT}/zlib/build"

    make -j$NUM_JOBS
    make install
fi
