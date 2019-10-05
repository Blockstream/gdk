#! /usr/bin/env bash
set -e

trap "cat config.log" ERR

TOR_NAME="tor-tor-0.4.1.6"

cp -r "${MESON_SOURCE_ROOT}/subprojects/${TOR_NAME}" "${MESON_BUILD_ROOT}/tor"

cd "${MESON_BUILD_ROOT}/tor"

cat <<EOF | patch -p0
--- src/core/mainloop/periodic.c	2019-09-23 16:07:43.000000000 +0200
+++ src/core/mainloop/periodic.c	2019-09-23 16:07:24.000000000 +0200
@@ -155,6 +155,7 @@
     return;
   mainloop_event_free(event->ev);
   event->last_action_time = 0;
+  event->enabled = 0;
 }
 
 /** Enable the given event by setting its "enabled" flag and scheduling it to
EOF

#FIXME: enable zstd for tor compression
CONFIGURE_ARGS="--prefix=${MESON_BUILD_ROOT}/tor/build --disable-system-torrc --disable-asciidoc --enable-pic --enable-static-openssl \
                --enable-static-libevent --enable-static-zlib --with-openssl-dir=${MESON_BUILD_ROOT}/openssl/build \
                --with-libevent-dir=${MESON_BUILD_ROOT}/libevent/build --with-zlib-dir=${MESON_BUILD_ROOT}/zlib/build \
                --disable-system-torrc --disable-systemd --disable-zstd --disable-lzma --disable-largefile \
                ac_cv_c_bigendian=no --disable-unittests --disable-tool-name-check --disable-module-dirauth --disable-rust"

if [ $LTO = "true" ]; then
    EXTRA_FLAGS="-flto"
fi

if [ \( "$1" = "--ndk" \) ]; then
    sh autogen.sh
    . ${MESON_SOURCE_ROOT}/tools/env.sh

    export CFLAGS="$CFLAGS -DPIC -fPIC $EXTRA_FLAGS"
    export LDFLAGS="$LDFLAGS $EXTRA_FLAGS"

    ./configure ${CONFIGURE_ARGS} --host=${NDK_TARGET_HOST} --enable-android
    make -o configure install -j${NUM_JOBS}
elif [ \( "$1" = "--iphone" \) -o \( "$1" = "--iphonesim" \) ]; then
    sh autogen.sh
    . ${MESON_SOURCE_ROOT}/tools/ios_env.sh $1

    export CFLAGS="$SDK_CFLAGS -isysroot ${IOS_SDK_PATH} -miphoneos-version-min=11.0 -O3 $EXTRA_FLAGS"
    export LDFLAGS="$SDK_LDFLAGS -isysroot ${IOS_SDK_PATH} -miphoneos-version-min=11.0  $EXTRA_FLAGS"
    export CC=${XCODE_DEFAULT_PATH}/clang
    export CXX=${XCODE_DEFAULT_PATH}/clang++
    ./configure --host=arm-apple-darwin ${CONFIGURE_ARGS} ac_cv_func__NSGetEnviron=no
    make -o configure clean -j$NUM_JOBS
    make -o configure -j$NUM_JOBS
    make -o configure install
elif [ \( "$1" = "--windows" \) ]; then
     export CC=x86_64-w64-mingw32-gcc-posix
     export CXX=x86_64-w64-mingw32-g++-posix
    $SED -i "734a TOR_LIB_CRYPT32=-lcrypt32" configure.ac
    $SED -i "735s!^TOR_LIB.*!  TOR_LIB_CRYPT32=-lcrypt32!" configure.ac
    $SED -i "743a AC_SUBST(TOR_LIB_CRYPT32)" configure.ac
    $SED -i "892s!^TOR_SEARCH.*!TOR_SEARCH_LIBRARY(openssl, \$tryssldir, \[-lssl -lcrypto \$TOR_LIB_GDI \$TOR_LIB_WS32 \$TOR_LIB_CRYPT32\],!" configure.ac
    $SED -i "924s!^LIBS=.*!LIBS=\"\$TOR_OPENSSL_LIBS \$LIBS \$TOR_LIB_IPHLPAPI \$TOR_LIB_WS32 \$TOR_LIB_CRYPT32\"!" configure.ac
    $SED -i "1135s!^all_libs_for_check=.*!all_libs_for_check=\"\$TOR_ZLIB_LIBS \$TOR_LIB_MATH \$TOR_LIBEVENT_LIBS \$TOR_OPENSSL_LIBS \$TOR_SYSTEMD_LIBS \$TOR_LIB_WS32 \$TOR_LIB_CRYPT32 \$TOR_LIB_GDI \$TOR_LIB_USERENV \$TOR_CAP_LIBS\"!" configure.ac
    sh autogen.sh
    ./configure ${CONFIGURE_ARGS} --host=x86_64-w64-mingw32 --build=${HOST_OS}
    $SED -ie "s!^include src/app.*!!" "src/include.am"
    $SED -ie "s!^include src/test.*!!" "src/include.am"
    $SED -ie "s!^include src/tools.*!!" "src/include.am"
    make -j$NUM_JOBS
    make install
else
    export CFLAGS="$SDK_CFLAGS -DPIC -fPIC $EXTRA_FLAGS"
    export LDFLAGS="$SDK_LDFLAGS $EXTRA_FLAGS"
    $SED -i "739a TOR_LIB_PTHREAD=-lpthread" configure.ac
    $SED -i "740s!^TOR_LIB.*!  TOR_LIB_PTHREAD=-lpthread!" configure.ac
    $SED -i "743a AC_SUBST(TOR_LIB_PTHREAD)" configure.ac
    $SED -i "892s!^TOR_SEARCH.*!TOR_SEARCH_LIBRARY(openssl, \$tryssldir, \[-lssl -lcrypto \$TOR_LIB_GDI \$TOR_LIB_WS32 \$TOR_LIB_CRYPT32\ -ldl \$TOR_LIB_PTHREAD\],!" configure.ac
    sh autogen.sh
    ./configure ${CONFIGURE_ARGS} --host=${HOST_OS}
    sed -ie "s!^include src/app.*!!" "src/include.am"
    sed -ie "s!^include src/test.*!!" "src/include.am"
    sed -ie "s!^include src/tools.*!!" "src/include.am"
    make -j$NUM_JOBS
    make install
fi
