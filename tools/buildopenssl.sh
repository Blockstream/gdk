#! /usr/bin/env bash
set -e

OPENSSL_NAME="openssl-OpenSSL_1_0_2p"
OPENSSL_OPTIONS="no-krb5 no-shared no-dso no-ssl2 no-ssl3 no-idea no-dtls no-dtls1 no-weak-ssl-ciphers no-comp -fvisibility=hidden"
OPENSSL_MOBILE="no-hw no-engine"

cp -r "${MESON_SOURCE_ROOT}/subprojects/${OPENSSL_NAME}" "${MESON_BUILD_ROOT}/openssl"
cd "${MESON_BUILD_ROOT}/openssl"
openssl_prefix="${MESON_BUILD_ROOT}/openssl/build"
if [ \( "$1" = "--ndk" \) ]; then
    if [ "$(uname)" == "Darwin" ]; then
        gsed -i 's/-mandroid//g' ${MESON_BUILD_ROOT}/openssl/Configure
    else
        sed -i 's/-mandroid//g' ${MESON_BUILD_ROOT}/openssl/Configure
    fi
    . ${MESON_SOURCE_ROOT}/tools/env.sh
    ./Configure android --prefix="$openssl_prefix" $OPENSSL_OPTIONS $OPENSSL_MOBILE
    sed -ie "s!-ldl!!" "Makefile"
    make depend
    make -j$NUM_JOBS 2> /dev/null
    make install_sw
elif [ \( "$1" = "--iphone" \) -o \( "$1" = "--iphonesim" \) ]; then
    . ${MESON_SOURCE_ROOT}/tools/ios_env.sh $1

    export CC=${XCODE_DEFAULT_PATH}/clang
    export CROSS_TOP="${XCODE_PATH}/Platforms/${IOS_PLATFORM}.platform/Developer"
    export CROSS_SDK="${IOS_PLATFORM}.sdk"
    export PATH="${XCODE_DEFAULT_PATH}:$PATH"
    if test "x$1" == "x--iphonesim"; then
        all_archs="x86_64"
    else
        all_archs="arm64"
    fi
    for arch in $all_archs; do
        export CURRENT_ARCH=$arch
        ARCH_BITS=32
        NOASM=
        if test "x$arch" == "arm64" || test "x$arch" == "xx86_64"; then
            ARCH_BITS=64
        fi

        if test "x$arch" == "i386" || test "x$arch" == "xx86_64"; then
            NOASM=no-asm
        fi
        KERNEL_BITS=$ARCH_BITS ./Configure iphoneos-cross $NOASM --prefix=$openssl_prefix $OPENSSL_OPTIONS $OPENSSL_MOBILE
        sed -ie "s!-fomit-frame-pointer!!" "Makefile"
        sed -ie "s!^CFLAG=!CFLAG=-isysroot ${CROSS_TOP}/SDKs/${CROSS_SDK} -arch ${CURRENT_ARCH} -miphoneos-version-min=9.0 !" "Makefile"
        rm -rf build-$arch
        rm -rf $openssl_prefix
        make clean
        make depend
        make -j$NUM_JOBS 2> /dev/null
        wait
        make install_sw
        mkdir -p build-$arch/tmp/$arch
        mv $openssl_prefix/* build-$arch/tmp/$arch
    done
    mkdir -p $openssl_prefix
    cp -R build-$arch/tmp/$arch/* $openssl_prefix
    for arch in $all_archs; do
        cp build-$arch/tmp/$arch/include/openssl/opensslconf.h $openssl_prefix/include/openssl/opensslconf-$arch.h
        cp build-$arch/tmp/$arch/include/openssl/bn.h $openssl_prefix/include/openssl/bn-$arch.h
    done

    if test "x$1" == "x--iphonesim"; then
        cat > $openssl_prefix/include/openssl/opensslconf.h << EOF
#if __i386__
#include "opensslconf-i386.h"
#elif __x86_64
#include "opensslconf-x86_64.h"
#else
#error unsupported architecture
#endif
EOF
        cat > $openssl_prefix/include/openssl/bn.h << EOF
#ifndef OPENSSL_MULTIARCH_BN_H
#define OPENSSL_MULTIARCH_BN_H

#if __i386
#include "bn-i386.h"
#elif __x86_64
#include "bn-x86_64.h"
#else
#error unsupported architecture
#endif
#endif
EOF
        cp build-x86_64/tmp/x86_64/lib/libcrypto.a $openssl_prefix/lib/libcrypto.a
        cp build-x86_64/tmp/x86_64/lib/libssl.a $openssl_prefix/lib/libssl.a
    else
        cat > $openssl_prefix/include/openssl/opensslconf.h << EOF
#if __ARM_ARCH_7A__
#include "opensslconf-armv7.h"
#elif __ARM_ARCH_7S__
#include "opensslconf-armv7s.h"
#elif __ARM_ARCH_ISA_A64
#include "opensslconf-arm64.h"
#else
#error unsupported architecture
#endif
EOF
        cat > $openssl_prefix/include/openssl/bn.h << EOF
#ifndef OPENSSL_MULTIARCH_BN_H
#define OPENSSL_MULTIARCH_BN_H

#if __ARM_ARCH_7A__
#include "bn-armv7.h"
#elif __ARM_ARCH_7S__
#include "bn-armv7s.h"
#elif __ARM_ARCH_ISA_A64
#include "bn-arm64.h"
#else
#error unsupported architecture
#endif
#endif
EOF
        cp build-arm64/tmp/arm64/lib/libcrypto.a $openssl_prefix/lib/libcrypto.a
        cp build-arm64/tmp/arm64/lib/libssl.a $openssl_prefix/lib/libssl.a
    fi
elif [ \( "$1" = "--windows" \) ]; then
    ./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --prefix="$openssl_prefix" $OPENSSL_OPTIONS
    make depend
    make -j$NUM_JOBS 2> /dev/null
    make install_sw
else
    if [ "$(uname)" == "Darwin" ]; then
        ./Configure darwin64-x86_64-cc --prefix="$openssl_prefix" $OPENSSL_OPTIONS
    else
        ./config --prefix="$openssl_prefix" $OPENSSL_OPTIONS
        sed -ie "s!^CFLAG=!CFLAG=-fPIC -DPIC !" "Makefile"
    fi
    make depend
    make -j$NUM_JOBS 2> /dev/null
    make install_sw
fi
