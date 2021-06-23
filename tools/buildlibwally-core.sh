#! /usr/bin/env bash
set -e

WALLYCORE_NAME="wallycore-0.8.2"

have_cmd()
{
    command -v "$1" >/dev/null 2>&1
}

if have_cmd gsed; then
    SED=$(command -v gsed)
elif have_cmd sed; then
    SED=$(command -v sed)
else
    echo "Could not find sed or gsed. Please install sed and try again."
    exit 1
fi

if [ ! -d "${MESON_BUILD_ROOT}/libwally-core" ]; then
    cp -r "${MESON_SOURCE_ROOT}/subprojects/${WALLYCORE_NAME}" "${MESON_BUILD_ROOT}/libwally-core"
fi

cd "${MESON_BUILD_ROOT}/libwally-core"
./tools/cleanup.sh
./tools/autogen.sh

${SED} -i 's/\"wallycore\"/\"greenaddress\"/' ${MESON_BUILD_ROOT}/libwally-core/src/swig_java/swig.i

CONFIGURE_ARGS="--enable-static --disable-shared --enable-elements --disable-tests"
CONFIGURE_ARGS="${CONFIGURE_ARGS} --enable-ecmult-static-precomputation"
CONFIGURE_ARGS="${CONFIGURE_ARGS} --prefix=${MESON_BUILD_ROOT}/libwally-core/build"

if [ "${BUILDTYPE}" = "debug" ]; then
    CONFIGURE_ARGS="${CONFIGURE_ARGS} --enable-debug"
fi

if [ "{$LTO}" = "true" ]; then
    EXTRA_FLAGS="-flto"
fi

if [ "$2" = "--asan" ]; then
    EXTRA_FLAGS="${EXTRA_FLAGS} -fsanitize=address"
fi

if ([ "$(uname)" == "Darwin" ] && [ -n "${JAVA_HOME}" ]); then
    EXTRA_FLAGS+=" -I${JAVA_HOME}/include -I${JAVA_HOME}/include/darwin"
fi

if [ "$1" = "--ndk" ]; then
    . ${MESON_SOURCE_ROOT}/tools/env.sh
    . tools/android_helpers.sh
    export CFLAGS="${CFLAGS} -DPIC -fPIC ${EXTRA_FLAGS}"
    export LDFLAGS="${LDFLAGS} ${EXTRA_FLAGS}"

    case ${HOST_ARCH} in
        x86) HOST_ARCH=i686;;
    esac

    android_build_wally ${HOST_ARCH} ${NDK_TOOLSDIR} ${ANDROID_VERSION} --build=${HOST_OS} \
          ${CONFIGURE_ARGS} ac_cv_c_bigendian=no --enable-swig-java --disable-swig-python --target=${SDK_PLATFORM}
elif [ \( "$1" = "--iphone" \) -o \( "$1" = "--iphonesim" \) ]; then
    . ${MESON_SOURCE_ROOT}/tools/ios_env.sh $1
    export CFLAGS="${CFLAGS} ${EXTRA_FLAGS} -O3"
    export LDFLAGS="${LDFLAGS} ${EXTRA_FLAGS}"
    export CC=${XCODE_DEFAULT_PATH}/clang
    export CXX=${XCODE_DEFAULT_PATH}/clang++
    ./configure --host=arm-apple-darwin --with-sysroot=${IOS_SDK_PATH} --build=${HOST_OS} \
                --disable-swig-java --disable-swig-python ${CONFIGURE_ARGS}

    make -o configure -j${NUM_JOBS}
elif [ "$1" = "--windows" ]; then
     export CC=x86_64-w64-mingw32-gcc-posix
     export CXX=x86_64-w64-mingw32-g++-posix

    ./configure --disable-swig-java --disable-swig-python --host=x86_64-w64-mingw32 --build=${HOST_OS} ${CONFIGURE_ARGS}
    make -j${NUM_JOBS}
else
    export CFLAGS="${SDK_CFLAGS} -DPIC -fPIC ${EXTRA_FLAGS}"
    export LDFLAGS="${SDK_LDFLAGS} ${EXTRA_FLAGS}"

    ENABLE_SWIG_JAVA=""
    if [ -n "${JAVA_HOME}" ]; then
        ENABLE_SWIG_JAVA="--enable-swig-java"
    fi

    ./configure ${ENABLE_SWIG_JAVA} --host=${HOST_OS} ${CONFIGURE_ARGS}
    make -j${NUM_JOBS}
fi
make -o configure install -j${NUM_JOBS}
