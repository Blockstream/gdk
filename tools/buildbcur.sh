#! /usr/bin/env bash
set -e

cd "${PRJ_SUBDIR}"

# fixes to the src files
${SED} -i '/#include <limits>/a #include <cstring>' src/xoshiro256.cpp
${SED} -i 's/#include <Windows.h>/#include <windows.h>/g' src/memzero.c

CONFIGURE_ARGS="--prefix=${GDK_BUILD_ROOT}/bc-ur/build "
EXTRA_CFLAGS="-fPIC -DPIC"
EXTRA_CXXFLAGS="-fPIC -DPIC"
EXTRA_LDFLAGS=""


if [[ "$1" == "--ndk" ]]; then

    source ${GDK_SOURCE_ROOT}/tools/env.sh
    CONFIGURE_ARGS+="--host=${NDK_TARGET_HOST} "

elif [[ "$1" == "--windows" ]]; then

    export CC=x86_64-w64-mingw32-gcc-posix
    export CXX=x86_64-w64-mingw32-g++-posix
    CONFIGURE_ARGS+="--host=x86_64-w64-mingw32 --build=${HOST_OS} "

elif [[ "$1" == "--iphone" ]] || [[ "$1" == "--iphonesim" ]]; then

    source ${GDK_SOURCE_ROOT}/tools/ios_env.sh $1
    EXTRA_CFLAGS="$IOS_CFLAGS $EXTRA_CFLAGS"
    EXTRA_CXXFLAGS="$IOS_CXXFLAGS $EXTRA_CXXFLAGS"
    EXTRA_LDFLAGS="$IOS_LDFLAGS $EXTRA_LDFLAGS"
    export CC=${XCODE_DEFAULT_PATH}/clang
    export CXX=${XCODE_DEFAULT_PATH}/clang++
    CONFIGURE_ARGS+="--host=arm-apple-darwin --with-sysroot=${IOS_SDK_PATH} "

else

    EXTRA_CFLAGS="$SDK_CFLAGS $EXTRA_CFLAGS"
    EXTRA_CXXFLAGS="$SDK_CXXFLAGS $EXTRA_CXXFLAGS"
    EXTRA_LDFLAGS="$SDK_LDFLAGS $EXTRA_LDFLAGS"

fi

export CFLAGS="$CFLAGS $EXTRA_CFLAGS"
export CXXFLAGS="$CXXFLAGS $EXTRA_CXXFLAGS"
export LDFLAGS="$LDFLAGS $EXTRA_LDFLAGS"
./configure ${CONFIGURE_ARGS}

# fixes to the generated makefiles
${SED} -i 's/-stdlib=libc++//g' src/Makefile
${SED} -i 's/--debug -O0//g' src/Makefile

make lib
make install
