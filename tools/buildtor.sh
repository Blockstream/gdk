#! /usr/bin/env bash
set -e

TOR_NAME="$(basename ${PRJ_SUBDIR})"

cd ${TOR_SRCDIR}

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
        if [[ "${target_triple}" == "x86_64-apple-iossimulator" ]]; then
            AUTOCONF_HOST="x86_64-apple-darwin"
        elif [[ "${target_triple}" == *"-apple-iossimulator" ]]; then
            AUTOCONF_HOST="arm-apple-darwin"
        else
            AUTOCONF_HOST="arm-apple-darwin"
        fi
        CONFIGURE_ARGS+=" ac_cv_func__NSGetEnviron=no ac_cv_func_pipe2=no --host=${AUTOCONF_HOST} --build=${host_triple}"
        ;;
    *-w64-mingw32)
        CONFIGURE_ARGS+=" --host=${target_triple} --build=${host_triple}"
        ;;
    *-apple-darwin)
        if [ "${target_triple}" != "${host_triple}" ]; then
            AUTOCONF_HOST="${target_triple}"
            if [ "${AUTOCONF_HOST}" = "arm64-apple-darwin" ]; then
                AUTOCONF_HOST="aarch64-apple-darwin"
            fi
            CONFIGURE_ARGS+=" --host=${AUTOCONF_HOST} --build=${host_triple}"
        fi
        ;;
esac

mkdir build
cd build
../configure ${CONFIGURE_ARGS} ${CONFIGURE_LIBDIR_ARG}

make libtor.a -j ${NUM_JOBS}
make install
# manually installing libraries and header files
mkdir -p ${TOR_INSTALL_DIR}
cp libtor.a ${TOR_INSTALL_DIR}/lib
mkdir -p ${TOR_INSTALL_DIR}/include

cp ../src/feature/api/tor_api.h ${TOR_INSTALL_DIR}/include

cd -
