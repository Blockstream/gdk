#! /usr/bin/env bash
set -e

WALLYCORE_NAME="libwally-core-eadc2479dfcab2532195bd2c1a91d9f5bbe7f4d7"

have_cmd()
{
    command -v "$1" >/dev/null 2>&1
}

if have_cmd gsed; then
    SED=$(command -v gsed)
elif have_cmd tar; then
    SED=$(command -v sed)
else
    echo "Could not find sed or gsed. Please install sed and try again."
    exit 1
fi

cp -r "${MESON_SOURCE_ROOT}/subprojects/${WALLYCORE_NAME}" "${MESON_BUILD_ROOT}/libwally-core"

ENABLE_SWIG_JAVA=disable-swig-java
if [ "x$JAVA_HOME" != "x" ]; then
    ENABLE_SWIG_JAVA=enable-swig-java
fi

cd "${MESON_BUILD_ROOT}/libwally-core"
./tools/cleanup.sh
./tools/autogen.sh

$SED -i 's/\"wallycore\"/\"greenaddress\"/' ${MESON_BUILD_ROOT}/libwally-core/src/swig_java/swig.i

ENABLE_DEBUG=""
if [[ $BUILDTYPE = "debug" ]]; then
    ENABLE_DEBUG="--enable-debug"
fi

CONFIGURE_ARGS="--enable-static --disable-shared --enable-elements --enable-ecmult-static-precomputation"

if [ $LTO = "true" ]; then
    EXTRA_FLAGS="-flto"
fi

if [ \( "$1" = "--ndk" \) ]; then
    . ${MESON_SOURCE_ROOT}/tools/env.sh
    . tools/android_helpers.sh
    export CFLAGS="$CFLAGS -DPIC -fPIC $EXTRA_FLAGS"
    export LDFLAGS="$LDFLAGS $EXTRA_FLAGS"
    # FIXME: this function can be removed when wally gets updated
    function android_get_ldflags() {
       echo $LDFLAGS
    }

    case $HOST_ARCH in
        x86) HOST_ARCH=i686;;
    esac

    android_build_wally $HOST_ARCH $NDK_TOOLSDIR $ANDROID_VERSION --build=$HOST_OS \
          $CONFIGURE_ARGS ac_cv_c_bigendian=no --enable-swig-java --disable-swig-python --target=$SDK_PLATFORM $ENABLE_DEBUG --prefix="${MESON_BUILD_ROOT}/libwally-core/build"

    make -o configure install -j$NUM_JOBS
elif [ \( "$1" = "--iphone" \) -o \( "$1" = "--iphonesim" \) ]; then
    . ${MESON_SOURCE_ROOT}/tools/ios_env.sh $1

    export CFLAGS="$SDK_CFLAGS -isysroot ${IOS_SDK_PATH} -miphoneos-version-min=11.0 -O3 $EXTRA_FLAGS"
    export LDFLAGS="$SDK_LDFLAGS -isysroot ${IOS_SDK_PATH} -miphoneos-version-min=11.0 $EXTRA_FLAGS"
    export CC=${XCODE_DEFAULT_PATH}/clang
    export CXX=${XCODE_DEFAULT_PATH}/clang++
    ./configure --host=arm-apple-darwin --with-sysroot=${IOS_SDK_PATH} --build=$HOST_OS \
                --disable-swig-java --disable-swig-python \
                $CONFIGURE_ARGS --prefix="${MESON_BUILD_ROOT}/libwally-core/build"
    make -o configure clean -j$NUM_JOBS
    make -o configure -j$NUM_JOBS
    make -o configure install
elif [ \( "$1" = "--windows" \) ]; then
     export CC=x86_64-w64-mingw32-gcc-posix
     export CXX=x86_64-w64-mingw32-g++-posix
    ./configure --disable-swig-java --disable-swig-python --host=x86_64-w64-mingw32 --build=$HOST_OS $CONFIGURE_ARGS $ENABLE_DEBUG --prefix="${MESON_BUILD_ROOT}/libwally-core/build"

    make -j$NUM_JOBS
    make install
else
    export CFLAGS="$SDK_CFLAGS -DPIC -fPIC $EXTRA_FLAGS"
    export LDFLAGS="$SDK_LDFLAGS $EXTRA_FLAGS"

    ./configure --$ENABLE_SWIG_JAVA --host=$HOST_OS $CONFIGURE_ARGS $ENABLE_DEBUG --prefix="${MESON_BUILD_ROOT}/libwally-core/build"

    make -j$NUM_JOBS
    make install
fi
