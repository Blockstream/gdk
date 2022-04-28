#! /usr/bin/env bash
set -e

BUILDTYPE="$1"
shift

OUTPUT="$1"
shift

SOURCE_ROOT="$1"
shift

BUILD_ROOT="$1"
shift

OBJCOPY="$1"
shift

RUSTSRC="$SOURCE_ROOT/subprojects"
RUSTDST="$BUILD_ROOT/subprojects"

if [ $(command -v rsync) ]; then
    # reminder that ending slash is required for rsyncing folders ;)
    rsync -a "$RUSTSRC/gdk_rust/" "$RUSTDST/gdk_rust/"
else
    cp -r "$RUSTSRC/gdk_rust" "$RUSTDST"
fi


export CC_i686_linux_android=i686-linux-android19-clang
export CC_x86_64_linux_android=x86_64-linux-android21-clang
export CC_armv7_linux_androideabi=armv7a-linux-androideabi19-clang
export CC_aarch64_linux_android=aarch64-linux-android21-clang

OUT_LIB_FILE="libgdk_rust.a"
CARGO_ARGS=()

cd "$BUILD_ROOT/subprojects/gdk_rust"

if [ "$(uname)" = "Darwin" ]; then
    export CARGO_PROFILE_DEV_LTO=true
fi

if [ \( "$1" = "--ndk" \) ]; then
    if [ "$(uname)" = "Darwin" ]; then
        export PATH=${PATH}:${ANDROID_NDK}/toolchains/llvm/prebuilt/darwin-x86_64/bin
        export AR=${ANDROID_NDK}/toolchains/llvm/prebuilt/darwin-x86_64/bin/llvm-ar
    else
        export PATH=${PATH}:${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin
        export AR=${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-ar
        export OBJCOPY=${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-objcopy
    fi
    if [ "$HOST_ARCH" = "armeabi-v7a" ]; then
        RUSTTARGET=armv7-linux-androideabi
    elif [ "$HOST_ARCH" = "arm64-v8a" ]; then
        RUSTTARGET=aarch64-linux-android
    elif [ "$HOST_ARCH" = "x86" ]; then
        RUSTTARGET=i686-linux-android
    elif [ "$HOST_ARCH" = "x86_64" ]; then
        RUSTTARGET=x86_64-linux-android
    else
        echo "Unkown android platform"
        exit -1
    fi
elif [ \( "$1" = "--windows" \) ]; then
    RUSTTARGET=x86_64-pc-windows-gnu
elif [ \( "$1" = "--iphone" \) ]; then
    RUSTTARGET=aarch64-apple-ios
    LD_ARCH="-arch arm64 -platform_version ios 11.0 11.0"
elif [ \( "$1" = "--iphonesim" \) ]; then
    RUSTTARGET=x86_64-apple-ios
    LD_ARCH="-arch x86_64 -platform_version ios-simulator 11.0 11.0"
elif [ "$(uname)" = "Darwin" ]; then
    SDK_CPU=$(uname -m)
    RUSTTARGET=$HOST_OS
    LD_ARCH="-arch $SDK_CPU -platform_version macos 10.13 10.13"
else
    LD_ARCH="-platform_version macos 10.13 10.13"
fi

if [ "$BUILDTYPE" == "release" ]; then
    CARGO_ARGS+=("--release")
fi

if [ -n "$RUSTTARGET" ]; then
    CARGO_ARGS+=("--target=$RUSTTARGET")
fi

if [ -n "${NUM_JOBS}" ]; then
    CARGO_ARGS+=("--jobs")
    CARGO_ARGS+=(${NUM_JOBS})
fi

printf "cargo args: ${CARGO_ARGS[*]}\n"
OPENSSL_DIR=${BUILD_ROOT}/openssl/build OPENSSL_STATIC=1 \
  cargo build "${CARGO_ARGS[@]}"

if [ -z "$RUSTTARGET" ]; then
    cp "target/${BUILDTYPE}/${OUT_LIB_FILE}" "${BUILD_ROOT}/$OUTPUT"
else
    mkdir -p "target/${BUILDTYPE}"
    cp "target/${RUSTTARGET}/$BUILDTYPE/${OUT_LIB_FILE}" "${BUILD_ROOT}/$OUTPUT"
fi

APPLE_KEEP="${SOURCE_ROOT}/subprojects/gdk_rust/apple-exported-symbols"
KEEP="${SOURCE_ROOT}/subprojects/gdk_rust/exported-symbols"
WEAKEN="${SOURCE_ROOT}/subprojects/gdk_rust/weaken-symbols"

if [ -z "${OBJCOPY}" ]; then
    # on Darwin we use ld to hide all the unnecessary symbols (mostly secp256k1 stuff)
    ld ${LD_ARCH} -o "${BUILD_ROOT}/$OUTPUT" -r -exported_symbols_list "$APPLE_KEEP" "${BUILD_ROOT}/$OUTPUT"
else
    $OBJCOPY --strip-unneeded --keep-symbols="$KEEP" --weaken-symbols="$WEAKEN" "${BUILD_ROOT}/$OUTPUT"
fi
