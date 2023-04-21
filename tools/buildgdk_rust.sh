#! /usr/bin/env bash
set -e

BUILDTYPE="$1"; shift
TRIPLE="$1"; shift
ANDROID_TOOLCHAIN_ROOT=$1; shift
ARCHIVER=$1; shift
OPENSSL_DIR="$1"; shift
SOURCE_DIR="$1"; shift
OUTPUT_DIR="$1"; shift
ARTIFACT="$1"; shift
export MACOSX_DEPLOYMENT_TARGET=$1; shift

export CC_i686_linux_android=i686-linux-android19-clang
export CARGO_TARGET_I686_LINUX_ANDROID_LINKER=${CC_i686_linux_android}
export CC_x86_64_linux_android=x86_64-linux-android21-clang
export CARGO_TARGET_X86_64_LINUX_ANDROID_LINKER=${CC_x86_64_linux_android}
export CC_armv7_linux_androideabi=armv7a-linux-androideabi19-clang
export CARGO_TARGET_ARMV7_LINUX_ANDROIDEABI_LINKER=${CC_armv7_linux_androideabi}
export CC_aarch64_linux_android=aarch64-linux-android21-clang
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=${CC_aarch64_linux_android}
export AR=${ARCHIVER}


if [ "$(uname)" = "Darwin" ]; then
    export CARGO_PROFILE_DEV_LTO=true
    SDK_CPU=$(uname -m)
    export SDKROOT=$(xcrun -sdk macosx --show-sdk-path)
    LD_ARCH="-arch ${SDK_CPU}"
fi

ARTIFACT_PATH_HINT=${OUTPUT_DIR}
CARGO_ARGS=()
CARGO_ARGS+=("--manifest-path=${SOURCE_DIR}/Cargo.toml")
CARGO_ARGS+=("--target-dir=${OUTPUT_DIR}")

if [ "$BUILDTYPE" == "Release" ]; then
    CARGO_ARGS+=("--release")
    ARTIFACT_PATH_HINT=${OUTPUT_DIR}"/release"
else
    ARTIFACT_PATH_HINT=${OUTPUT_DIR}"/debug"
fi

if [ -n "$TRIPLE" ]; then
    CARGO_ARGS+=("--target=$TRIPLE")
    ARTIFACT_PATH_HINT=${OUTPUT_DIR}/${TRIPLE}
fi

if [[ ${TRIPLE} == *"android"* ]];then
    export PATH=${PATH}:${ANDROID_TOOLCHAIN_ROOT}/bin
    export RUSTFLAGS="-L${SOURCE_DIR}/libgcc"
elif [[ ${TRIPLE} == "aarch64-apple-ios" ]]; then
    LD_ARCH="-arch arm64 -platform_version ios ${MACOSX_DEPLOYMENT_TARGET} ${MACOSX_DEPLOYMENT_TARGET}"
elif [[ ${TRIPLE} == "x86_64-apple-ios" ]]; then
    LD_ARCH="-arch x86_64 -platform_version ios-simulator ${MACOSX_DEPLOYMENT_TARGET} ${MACOSX_DEPLOYMENT_TARGET}"
elif [[ ${TRIPLE} == "aarch64-apple-ios-sim" ]]; then
    LD_ARCH="-arch arm64 -platform_version ios-simulator ${MACOSX_DEPLOYMENT_TARGET} ${MACOSX_DEPLOYMENT_TARGET}"
fi

# behaving correctly when no-op
oldT=$(date +%s)

export OPENSSL_DIR=$OPENSSL_DIR 
export OPENSSL_STATIC=1
# echo "cargo args: ${CARGO_ARGS[*]}"
cargo build "${CARGO_ARGS[@]}"
ARTIFACT_FULL_PATH=$(find ${ARTIFACT_PATH_HINT} -name ${ARTIFACT})


# skipping the remaining part if build has been a no-op
statFmt="-c %Y"
if [ "$(uname)" = "Darwin" ]; then
    statFmt="-f %m"
fi
newT=$(stat ${statFmt} ${ARTIFACT_FULL_PATH})
if [[ $newT -lt $oldT ]] && [[ -f "${OUTPUT_DIR}/${ARTIFACT}" ]] ; then
    exit 0
fi

if [ "$(uname)" = "Darwin" ]; then
    echo "stripping away unwanted symbols"
    APPLE_KEEP="${SOURCE_DIR}/apple-exported-symbols"
    ld ${LD_ARCH} -o ${OUTPUT_DIR}/${ARTIFACT} -r -exported_symbols_list "${APPLE_KEEP}" ${ARTIFACT_FULL_PATH}
else
    cp ${ARTIFACT_FULL_PATH} ${OUTPUT_DIR}
fi
