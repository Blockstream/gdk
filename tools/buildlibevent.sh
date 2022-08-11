#! /usr/bin/env bash
set -e

LIBEVENT_NAME="$(basename ${PRJ_SUBDIR})"

cd "${LIBEVENT_SRCDIR}"

CONFIGURE_ARGS="--prefix=${GDK_BUILD_ROOT}/libevent/build --enable-static --disable-samples --disable-openssl --disable-shared --disable-libevent-regress --disable-debug-mode --disable-dependency-tracking"
sh autogen.sh

if [ \( "$1" = "--ndk" \) ]; then
    . ${GDK_SOURCE_ROOT}/tools/env.sh

    export CFLAGS="$CFLAGS -DPIC -fPIC $EXTRA_FLAGS"
    export LDFLAGS="$LDFLAGS $EXTRA_FLAGS"

    ./configure --host=${NDK_TARGET_HOST} ${CONFIGURE_ARGS} --with-pic
    make -o configure install -j${NUM_JOBS}
elif [ \( "$1" = "--iphone" \) -o \( "$1" = "--iphonesim" \) ]; then
    . ${GDK_SOURCE_ROOT}/tools/ios_env.sh $1

    export CFLAGS="$IOS_CFLAGS $EXTRA_FLAGS"
    export LDFLAGS="$IOS_LDFLAGS $EXTRA_FLAGS"
    export CC=${XCODE_DEFAULT_PATH}/clang
    export CXX=${XCODE_DEFAULT_PATH}/clang++
    ./configure --host=arm-apple-darwin --with-sysroot=${IOS_SDK_PATH} ${CONFIGURE_ARGS}
    make -o configure clean -j$NUM_JOBS
    make -o configure -j$NUM_JOBS
    make -o configure install
elif [ \( "$1" = "--windows" \) ]; then
     export CC=x86_64-w64-mingw32-gcc-posix
     export CXX=x86_64-w64-mingw32-g++-posix
    ./configure --host=x86_64-w64-mingw32 --build=${HOST_OS} ${CONFIGURE_ARGS}

    make -j$NUM_JOBS
    make install
else
    export CFLAGS="$SDK_CFLAGS -DPIC -fPIC $EXTRA_FLAGS"
    export LDFLAGS="$SDK_LDFLAGS $EXTRA_FLAGS"

    ./configure ${CONFIGURE_ARGS} --with-pic --host=${HOST_OS}

    make -j$NUM_JOBS
    make install
fi
