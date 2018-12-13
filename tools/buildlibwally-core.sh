#! /usr/bin/env bash
set -e

WALLYCORE_NAME="libwally-core-4d655a88aa71c57348db18379819404af7bcbdff"

cp -r "${MESON_SOURCE_ROOT}/subprojects/${WALLYCORE_NAME}" "${MESON_BUILD_ROOT}/libwally-core"

if [ "$(uname)" == "Darwin" ]; then
    export HOST_OS="x86_64-apple-darwin"
    SED=gsed
else
    export HOST_OS="i686-linux-gnu"
    SED=sed
fi

ENABLE_SWIG_JAVA=disable-swig-java
if [ "x$JAVA_HOME" != "x" ]; then
    ENABLE_SWIG_JAVA=enable-swig-java
fi

cd "${MESON_BUILD_ROOT}/libwally-core"
./tools/cleanup.sh
./tools/autogen.sh

$SED -i 's/\"wallycore\"/\"greenaddress\"/' ${MESON_BUILD_ROOT}/libwally-core/src/swig_java/swig.i

ENABLE_DEBUG=""
if [[ $BUILDTYPE == "debug" ]]; then
    ENABLE_DEBUG="--enable-debug"
fi

if [ \( "$1" = "--ndk" \) ]; then
    . ${MESON_SOURCE_ROOT}/tools/env.sh
    . tools/android_helpers.sh

    export CFLAGS="$SDK_CFLAGS -DPIC -fPIC"
    export LDFLAGS="$SDK_LDFLAGS"

    android_build_wally $HOST_ARCH "${MESON_BUILD_ROOT}/toolchain" $ANDROID_VERSION --build=$HOST_OS \
          --enable-static --disable-shared --$ENABLE_SWIG_JAVA --disable-swig-python --target=$SDK_PLATFORM $ENABLE_DEBUG --prefix="${MESON_BUILD_ROOT}/libwally-core/build"

    make -o configure install
elif [ \( "$1" = "--iphone" \) -o \( "$1" = "--iphonesim" \) ]; then
    . ${MESON_SOURCE_ROOT}/tools/ios_env.sh $1

    export CFLAGS="$SDK_CFLAGS -isysroot ${IOS_SDK_PATH} -miphoneos-version-min=9.0 -O3"
    export LDFLAGS="$SDK_LDFLAGS -isysroot ${IOS_SDK_PATH} -miphoneos-version-min=9.0"
    export CC=${XCODE_DEFAULT_PATH}/clang
    export CXX=${XCODE_DEFAULT_PATH}/clang++
    ./configure --host=armv7-apple-darwin --with-sysroot=${IOS_SDK_PATH} --build=$HOST_OS \
                --disable-swig-java --disable-swig-python \
                --enable-static --disable-shared --prefix="${MESON_BUILD_ROOT}/libwally-core/build"
    make -o configure clean -j$NUM_JOBS
    make -o configure -j$NUM_JOBS
    make -o configure install
elif [ \( "$1" = "--windows" \) ]; then
     export CC=x86_64-w64-mingw32-gcc-posix
     export CXX=x86_64-w64-mingw32-g++-posix
    ./configure --disable-swig-java --disable-swig-python --host=x86_64-w64-mingw32 --build=$HOST_OS --enable-static --disable-shared $ENABLE_DEBUG --prefix="${MESON_BUILD_ROOT}/libwally-core/build"

    make -j$NUM_JOBS
    make install
else
    export CFLAGS="$SDK_CFLAGS -DPIC -fPIC"

    ./configure --$ENABLE_SWIG_JAVA --host=$HOST_OS --enable-static --disable-shared $ENABLE_DEBUG --prefix="${MESON_BUILD_ROOT}/libwally-core/build"

    make -j$NUM_JOBS
    make install
fi
