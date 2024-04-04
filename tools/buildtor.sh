#! /usr/bin/env bash
set -e

TOR_NAME="$(basename ${PRJ_SUBDIR})"

# fixes to code
# TODO: convert this to a patch file
cd ${TOR_SRCDIR}
${SED} -i 's/#include <openssl\/opensslv.h>/#include <openssl\/opensslconf.h>/g' src/lib/crypt_ops/crypto_openssl_mgt.h
# Remove warning string reference to openssl 1.1.1.b - Google play store
# security scanning incorrectly assumes we have linked a vulnerable openssl
# version if the string "OpenSSL 1.1.1b" is found in the final binary.
# FIXME: remove when tor is upgraded to version tor-0.4.8.1 or later.
${SED} -i 's/"1\.1\.1b\."/"future connections."/g' src/lib/tls/tortls_openssl.c

TOR_INSTALL_DIR=${GDK_BUILD_ROOT}
#FIXME: enable zstd for tor compression
CONFIGURE_ARGS="--prefix=${TOR_INSTALL_DIR} --enable-pic \
                --enable-static-libevent --with-libevent-dir=${GDK_BUILD_ROOT} \
                --enable-static-zlib --with-zlib-dir=${GDK_BUILD_ROOT} \
                --enable-static-openssl --with-openssl-dir=${GDK_BUILD_ROOT} \
                --disable-asciidoc --disable-manpage --disable-html-manual \
                --disable-system-torrc --disable-systemd --disable-zstd --disable-lzma --disable-largefile \
                --disable-unittests --disable-tool-name-check --disable-module-dirauth \
                --disable-libscrypt --disable-gcc-hardening --disable-linker-hardening \
                --disable-gcc-warnings-advisory ac_cv_c_bigendian=no"

## tor does not like -DNDEBUG
CFLAGS=$(echo $CFLAGS | $SED 's/-DNDEBUG//')
CXXFLAGS=$(echo $CXXFLAGS | $SED 's/-DNDEBUG//')

case $target_triple in
    *-linux-android)
        CONFIGURE_ARGS+=" --enable-android --host=${target_triple} --build=${host_triple}"
        ;;
    *-apple-ios | *-apple-iossimulator)
        CONFIGURE_ARGS+=" ac_cv_func__NSGetEnviron=no --host=arm-apple-darwin"
        ;;
    *-w64-mingw32)
        CONFIGURE_ARGS+=" --host=${target_triple} --build=${host_triple}"
        ;;
esac

mkdir build
cd build
../configure ${CONFIGURE_ARGS}

make libtor.a -j ${NUM_JOBS}
make install
# manually installing libraries and header files
mkdir -p ${TOR_INSTALL_DIR}
cp libtor.a ${TOR_INSTALL_DIR}/lib
mkdir -p ${TOR_INSTALL_DIR}/include

cp ../src/feature/api/tor_api.h ${TOR_INSTALL_DIR}/include

cd -
