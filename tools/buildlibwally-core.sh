#! /usr/bin/env bash
set -e

WALLYCORE_BLDDIR=${GDK_BUILD_ROOT}/libwally-core

#if [ ! -f "${WALLYCORE_SRCDIR}/.${SECP_COMMIT}" ]; then
    cd ${WALLYCORE_SRCDIR}
    rm -rf src/secp256k1
    git clone ${SECP_URL} src/secp256k1
    cd src/secp256k1
    git checkout ${SECP_COMMIT}
    cd ${WALLYCORE_SRCDIR}
    touch .${SECP_COMMIT}
    #make clean -k || echo >/dev/null
#fi

if [ ! -d "${WALLYCORE_BLDDIR}" ]; then
    cp -r ${WALLYCORE_SRCDIR} ${WALLYCORE_BLDDIR}
fi

cd ${WALLYCORE_BLDDIR}
./tools/cleanup.sh
./tools/autogen.sh

${SED} -i 's/\"wallycore\"/\"greenaddress\"/' src/swig_java/swig.i

CONFIGURE_ARGS="--enable-static --disable-shared --enable-elements --disable-tests"
CONFIGURE_ARGS="${CONFIGURE_ARGS} --prefix=${WALLYCORE_BLDDIR}/build"

if [ "${BUILDTYPE}" = "debug" ]; then
    CONFIGURE_ARGS="${CONFIGURE_ARGS} --enable-debug"
fi

if [ "$2" = "--asan" ]; then
    EXTRA_FLAGS="${EXTRA_FLAGS} -fsanitize=address"
fi

if ([ "$(uname)" == "Darwin" ] && [ -n "${JAVA_HOME}" ]); then
    EXTRA_FLAGS+=" -I${JAVA_HOME}/include -I${JAVA_HOME}/include/darwin"
fi

if [ "$1" = "--ndk" ]; then
    . ${GDK_SOURCE_ROOT}/tools/env.sh
    . tools/android_helpers.sh
    export CFLAGS="${CFLAGS} -DPIC -fPIC ${EXTRA_FLAGS}"
    export LDFLAGS="${LDFLAGS} ${EXTRA_FLAGS}"

    android_build_wally ${HOST_ARCH} ${NDK_TOOLSDIR} ${ANDROID_VERSION} ${CONFIGURE_ARGS}
elif [ \( "$1" = "--iphone" \) -o \( "$1" = "--iphonesim" \) ]; then
    . ${GDK_SOURCE_ROOT}/tools/ios_env.sh $1
    export CFLAGS="${CFLAGS} ${EXTRA_FLAGS} -O3"
    export LDFLAGS="${LDFLAGS} ${EXTRA_FLAGS}"
    export CC=${XCODE_DEFAULT_PATH}/clang
    export CXX=${XCODE_DEFAULT_PATH}/clang++
    env | sort
    ./configure --host=arm-apple-darwin --with-sysroot=${IOS_SDK_PATH} --build=${HOST_OS} \
                --disable-swig-java --disable-swig-python ${CONFIGURE_ARGS}

    make clean -k || echo >/dev/null
    make -o configure -j${NUM_JOBS}
elif [ "$1" = "--windows" ]; then
     export CC=x86_64-w64-mingw32-gcc-posix
     export CXX=x86_64-w64-mingw32-g++-posix
    ./configure --disable-swig-java --disable-swig-python --host=x86_64-w64-mingw32 --build=${HOST_OS} ${CONFIGURE_ARGS}
    make clean -k || echo >/dev/null
    make -j${NUM_JOBS}
else
    export CFLAGS="${SDK_CFLAGS} -DPIC -fPIC ${EXTRA_FLAGS}"
    export LDFLAGS="${SDK_LDFLAGS} ${EXTRA_FLAGS}"

    ENABLE_SWIG_JAVA=""
    if [ -n "${JAVA_HOME}" ]; then
        ENABLE_SWIG_JAVA="--enable-swig-java"
    fi

    ./configure ${ENABLE_SWIG_JAVA} --host=${HOST_OS} ${CONFIGURE_ARGS}
    make clean -k || echo >/dev/null
    make -j${NUM_JOBS}
fi
make -o configure install -j${NUM_JOBS}
