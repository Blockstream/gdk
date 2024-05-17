#! /usr/bin/env bash
set -e


# FIXME: Change no-tests to no-apps when openssl is updated to 3.x
OPENSSL_NAME="$(basename ${PRJ_SUBDIR})"
CONFIGURE_ARGS="no-gost no-shared no-dso no-ssl2 no-ssl3 no-idea no-dtls no-dtls1 no-weak-ssl-ciphers no-comp -fvisibility=hidden no-err no-psk no-srp no-tests no-ui-console"

case $target_triple in
    *-linux-gnu)
        CONFIGURE_ARGS+=" enable-ec_nistp_64_gcc_128"
        openssl_triple="linux-${HOST_ARCH}"
        if [ "${CC}" == "clang" ]; then
            openssl_triple+="-clang"
        fi
        ;;

    *-apple-darwin)
        CONFIGURE_ARGS+=""
        openssl_triple="darwin64-${HOST_ARCH}-cc"
        ;;

    armv7a-linux-android)
        CONFIGURE_ARGS+=" no-asm no-hw no-engine -D__ANDROID_API__=${ANDROID_VERSION}"
        openssl_triple="android-arm"
        export ANDROID_NDK_HOME=${ANDROID_NDK}
        export PATH="${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-${HOST_ARCH}/bin:$PATH"
        ;;

    aarch64-linux-android)
        CONFIGURE_ARGS+=" enable-ec_nistp_64_gcc_128 no-hw no-engine -D__ANDROID_API__=${ANDROID_VERSION}"
        openssl_triple="android-arm64"
        export ANDROID_NDK_HOME=${ANDROID_NDK}
        export PATH="${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-${HOST_ARCH}/bin:$PATH"
        ;;

    x86_64-linux-android)
        CONFIGURE_ARGS+=" enable-ec_nistp_64_gcc_128 no-hw no-engine -D__ANDROID_API__=${ANDROID_VERSION}"
        openssl_triple="android-x86_64"
        export ANDROID_NDK_HOME=${ANDROID_NDK}
        export PATH="${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-${HOST_ARCH}/bin:$PATH"
        ;;

    i686-linux-android)
        CONFIGURE_ARGS+=" no-hw no-engine -D__ANDROID_API__=${ANDROID_VERSION}"
        openssl_triple="android-x86"
        export ANDROID_NDK_HOME=${ANDROID_NDK}
        export PATH="${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-${HOST_ARCH}/bin:$PATH"
        ;;

    arm-apple-ios)
        CONFIGURE_ARGS+=" no-hw no-engine"
        openssl_triple="ios64-cross"
        export CROSS_TOP=${IOS_SDK_PLATFORM_PATH}/Developer
        export CROSS_SDK=${SDK_SYSROOT}
        ;;

    *-apple-iossimulator)
        CONFIGURE_ARGS+=" no-asm no-hw no-engine"
        openssl_triple="iossimulator-xcrun"
        export CROSS_TOP=${IOS_SDK_PLATFORM_PATH}/Developer
        export CROSS_SDK=${SDK_SYSROOT}
        ;;

    *-w64-mingw32)
        openssl_triple="mingw64"
        ;;

esac

openssl_prefix="${GDK_BUILD_ROOT}"
cd "${PRJ_SUBDIR}"

./Configure $openssl_triple --prefix=${openssl_prefix} ${CONFIGURE_ARGS}
make -j${NUM_JOBS} 2>/dev/null
make -j${NUM_JOBS} install_sw
