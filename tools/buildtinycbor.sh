#! /usr/bin/env bash
set -e

cp tools/tinycbor.patch ${PRJ_SUBDIR}
cd "${PRJ_SUBDIR}"
#applying patches:
# - quit installing cbordump executable: not needed and breaks the build for windows
# - abort when calling open_memstream in android as ndk is missing key APIs for that function
patch -p1 < tinycbor.patch

if [[ "$1" == "--ndk" ]]; then
    source ${GDK_SOURCE_ROOT}/tools/env.sh
    export CFLAGS="$CFLAGS $EXTRA_FLAGS"
    export LDFLAGS="$LDFLAGS $EXTRA_FLAGS"
elif [[ "$1" == "--windows" ]]; then
    export CC=x86_64-w64-mingw32-gcc-posix
    export CXX=x86_64-w64-mingw32-g++-posix
elif [[ "$1" == "--iphone" ]] || [[ "$1" == "--iphonesim" ]]; then
    source ${GDK_SOURCE_ROOT}/tools/ios_env.sh $1
    export CFLAGS="$IOS_CFLAGS $EXTRA_FLAGS"
    export LDFLAGS="$IOS_LDFLAGS $EXTRA_FLAGS"
    export CC=${XCODE_DEFAULT_PATH}/clang
    export CXX=${XCODE_DEFAULT_PATH}/clang++
elif [[ "$1" == "--clang" ]]; then
    export CFLAGS="$SDK_CFLAGS $EXTRA_FLAGS"
    export LDFLAGS="$SDK_LDFLAGS $EXTRA_FLAGS"
else
    export CFLAGS="$SDK_CFLAGS $EXTRA_FLAGS"
    export LDFLAGS="$SDK_LDFLAGS $EXTRA_FLAGS"
fi

make \
    prefix=${GDK_BUILD_ROOT}/tinycbor/build \
    BUILD_SHARED=0 BUILD_STATIC=1 \
    CC=${CC} CXX=${CXX} \
    CFLAGS="${CFLAGS} -fPIC" LDFLAGS="${LDFLAGS} -fPIC" \
    install
