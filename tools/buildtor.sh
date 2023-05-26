#! /usr/bin/env bash
set -e

trap "cat config.log" ERR

TOR_NAME="$(basename ${PRJ_SUBDIR})"

# fixes to code
cd ${TOR_SRCDIR}
${SED} -i 's/#include <openssl\/opensslv.h>/#include <openssl\/opensslconf.h>/g' src/lib/crypt_ops/crypto_openssl_mgt.h

#FIXME: enable zstd for tor compression
CONFIGURE_ARGS="--prefix=${GDK_BUILD_ROOT}/tor/build --enable-pic \
                --enable-static-libevent --with-libevent-dir=${GDK_BUILD_ROOT}/libevent/build \
                --enable-static-zlib --with-zlib-dir=${GDK_BUILD_ROOT}/zlib/build \
                --enable-static-openssl --with-openssl-dir=${GDK_BUILD_ROOT}/openssl/build \
                --disable-asciidoc --disable-manpage --disable-html-manual \
                --disable-system-torrc --disable-systemd --disable-zstd --disable-lzma --disable-largefile \
                --disable-unittests --disable-tool-name-check --disable-module-dirauth \
                --disable-libscrypt --disable-gcc-hardening --disable-linker-hardening \
                --disable-gcc-warnings-advisory ac_cv_c_bigendian=no"


CFLAGS=$(echo $CFLAGS | $SED 's/-DNDEBUG//')
CXXFLAGS=$(echo $CXXFLAGS | $SED 's/-DNDEBUG//')

if [ \( "$1" = "--ndk" \) ]; then

    . ${GDK_SOURCE_ROOT}/tools/env.sh
    export CFLAGS="$CFLAGS -DPIC -fPIC $EXTRA_FLAGS"
    export LDFLAGS="$LDFLAGS $EXTRA_FLAGS"
    CONFIGURE_ARGS="${CONFIGURE_ARGS} --host=${NDK_TARGET_HOST} --enable-android"

elif [ \( "$1" = "--iphone" \) -o \( "$1" = "--iphonesim" \) ]; then

    . ${GDK_SOURCE_ROOT}/tools/ios_env.sh $1
    export CFLAGS="$IOS_CFLAGS $EXTRA_FLAGS"
    export LDFLAGS="$IOS_LDFLAGS $EXTRA_FLAGS"
    export CC=${XCODE_DEFAULT_PATH}/clang
    export CXX=${XCODE_DEFAULT_PATH}/clang++
    CONFIGURE_ARGS="${CONFIGURE_ARGS} --host=arm-apple-darwin ac_cv_func__NSGetEnviron=no"

elif [ \( "$1" = "--windows" \) ]; then

    export CC=x86_64-w64-mingw32-gcc-posix
    export CXX=x86_64-w64-mingw32-g++-posix
    # $SED -i "754a TOR_LIB_CRYPT32=-lcrypt32" configure.ac
    # $SED -i "755s!^TOR_LIB.*!  TOR_LIB_CRYPT32=-lcrypt32!" configure.ac
    # $SED -i "763a AC_SUBST(TOR_LIB_CRYPT32)" configure.ac
    # $SED -i "912s!^TOR_SEARCH.*!TOR_SEARCH_LIBRARY(openssl, \$tryssldir, \[-lssl -lcrypto \$TOR_LIB_GDI \$TOR_LIB_WS32 \$TOR_LIB_CRYPT32\],!" configure.ac
    # $SED -i "944s!^LIBS=.*!LIBS=\"\$TOR_OPENSSL_LIBS \$LIBS \$TOR_LIB_IPHLPAPI \$TOR_LIB_WS32 \$TOR_LIB_CRYPT32\"!" configure.ac
    # $SED -i "1155s!^all_libs_for_check=.*!all_libs_for_check=\"\$TOR_ZLIB_LIBS \$TOR_LIB_MATH \$TOR_LIBEVENT_LIBS \$TOR_OPENSSL_LIBS \$TOR_SYSTEMD_LIBS \$TOR_LIB_WS32 \$TOR_LIB_CRYPT32 \$TOR_LIB_GDI \$TOR_LIB_USERENV \$TOR_CAP_LIBS\"!" configure.ac
    CONFIGURE_ARGS="${CONFIGURE_ARGS} --host=x86_64-w64-mingw32 --build=${HOST_OS}"

else

    export CFLAGS="$SDK_CFLAGS -DPIC -fPIC $EXTRA_FLAGS"
    export LDFLAGS="$SDK_LDFLAGS $EXTRA_FLAGS"
    # $SED -i "740a TOR_LIB_PTHREAD=-lpthread" configure.ac
    # $SED -i "741s!^TOR_LIB.*!  TOR_LIB_PTHREAD=-lpthread!" configure.ac
    # $SED -i "764a AC_SUBST(TOR_LIB_PTHREAD)" configure.ac
    # $SED -i "912s!^TOR_SEARCH.*!TOR_SEARCH_LIBRARY(openssl, \$tryssldir, \[-lssl -lcrypto \$TOR_LIB_GDI \$TOR_LIB_WS32 \$TOR_LIB_CRYPT32\ -ldl \$TOR_LIB_PTHREAD\],!" configure.ac
    CONFIGURE_ARGS="${CONFIGURE_ARGS} --host=${HOST_OS}"

fi

mkdir build
cd build
../configure ${CONFIGURE_ARGS} # --enable-android
make libtor.a -j ${NUM_JOBS}
# make libtor.a
make install
# manually installing libraries and header files
mkdir -p ${GDK_BUILD_ROOT}/tor/build/lib
cp libtor.a ${GDK_BUILD_ROOT}/tor/build/lib
mkdir -p ${GDK_BUILD_ROOT}/tor/build/include

cp ../src/feature/api/tor_api.h ${GDK_BUILD_ROOT}/tor/build/include

cd -
