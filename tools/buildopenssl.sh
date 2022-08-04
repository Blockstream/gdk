#! /usr/bin/env bash
set -e

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

OPENSSL_NAME="$(basename ${MESON_SUBDIR})"
OPENSSL_OPTIONS="enable-ec_nistp_64_gcc_128 no-gost no-shared no-dso no-ssl2 no-ssl3 no-idea no-dtls no-dtls1 no-weak-ssl-ciphers no-comp -fvisibility=hidden no-err no-psk no-srp"
OPENSSL_MOBILE="no-hw no-engine"

if [ ! -d "${MESON_BUILD_ROOT}/openssl" ]; then
    cp -r "${MESON_SOURCE_ROOT}/subprojects/${OPENSSL_NAME}" "${MESON_BUILD_ROOT}/openssl"
fi

cd "${MESON_BUILD_ROOT}/openssl"
openssl_prefix="${MESON_BUILD_ROOT}/openssl/build"
if [ \( "$1" = "--ndk" \) ]; then
    if [ "$ANDROID_VERSION" = "19" ]; then
            OPENSSL_OPTIONS=$(echo $OPENSSL_OPTIONS | $SED -e "s/enable-ec_nistp_64_gcc_128//g")
    fi
    . ${MESON_SOURCE_ROOT}/tools/env.sh
    $SED -ie "133s!\$triarch\-!!" "Configurations/15-android.conf"
    $SED -ie "137s!\$triarch\-!!" "Configurations/15-android.conf"
    if [ $HOST_ARCH = "armeabi-v7a" ]; then
        OPENSSL_OPTIONS="$OPENSSL_OPTIONS no-asm"
    fi
    ./Configure android-$(echo $HOST_ARCH | tr '-' '\n' | head -1) --prefix="$openssl_prefix" $OPENSSL_OPTIONS $OPENSSL_MOBILE
    $SED -ie "s!-ldl!!" "Makefile"
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
        CONFIG_TARGET="iossimulator-xcrun"
        NOASM=no-asm
        $SED -i "33a cflags           => add(\"-arch x86_64 -mios-version-min=7.0.0 -fno-common -isysroot $CROSS_TOP/SDKs/$CROSS_SDK\")," Configurations/15-ios.conf
    else
        CONFIG_TARGET="ios64-cross"
        NOASM=
    fi
    KERNEL_BITS=64 ./Configure $CONFIG_TARGET $NOASM --prefix=$openssl_prefix $OPENSSL_OPTIONS $OPENSSL_MOBILE
    make depend
    make -j $NUM_JOBS 2> /dev/null
    make install_sw
elif [ \( "$1" = "--windows" \) ]; then
    AR=ar RANLIB=ranlib ./Configure mingw64 --cross-compile-prefix=x86_64-w64-mingw32- --prefix="$openssl_prefix" $OPENSSL_OPTIONS
    $SED -ie "s!^DIRS=.*!DIRS=crypto ssl!" "Makefile"
    make depend
    make -j$NUM_JOBS 2> /dev/null
    make install_sw
else
    if [ "$(uname)" = "Darwin" ]; then
        ARCH=$(uname -m)
        ./Configure darwin64-$ARCH-cc --prefix="$openssl_prefix" $OPENSSL_OPTIONS -mmacosx-version-min=10.13
    else
        ./config --prefix="$openssl_prefix" $OPENSSL_OPTIONS
        $SED -ie "s!^CFLAG=!CFLAG=-fPIC -DPIC !" "Makefile"
    fi
    $SED -ie "s!^DIRS=.*!DIRS=crypto ssl!" "Makefile"
    make depend
    make -j$NUM_JOBS 2> /dev/null
    make install_sw
fi
