#!/usr/bin/env bash
set -e

function comma_separate() {
    echo "`python -c "import sys; print('[' + ','.join(map(lambda x: '\'' + x + '\'', sys.argv[1:])) + ']')" $@`"
}

if [ \( "$3" = "android" \) ]; then
    C_COMPILER="$1/toolchain/bin/clang"
    CXX_COMPILER="$1/toolchain/bin/clang++"
    STRIP="$1/toolchain/bin/$SDK_PLATFORM-strip"
    CFLAGS=$(comma_separate "--sysroot=$1/toolchain/sysroot" $SDK_CFLAGS)
    LDFLAGS=$(comma_separate $SDK_LDFLAGS)
    ARCHS="[]"
    HOST_SYSTEM=$3
elif [ \( "$3" = "iphone" \) -o \( "$3" = "iphonesim" \) ]; then
    C_COMPILER="clang"
    CXX_COMPILER="clang++"
    CFLAGS=$(comma_separate "-isysroot $IOS_SDK_PATH" "-stdlib=libc++" $SDK_CFLAGS_NO_ARCH)
    LDFLAGS=$(comma_separate "-isysroot $IOS_SDK_PATH" "-stdlib=libc++" $SDK_LDFLAGS)
    ARCHS=$(comma_separate $ARCHS)
    HOST_SYSTEM="darwin"
elif [ \( "$3" = "windows" \) ]; then
    C_COMPILER="x86_64-w64-mingw32-gcc-posix"
    CXX_COMPILER="x86_64-w64-mingw32-g++-posix"
    STRIP="x86_64-w64-mingw32-strip"
    ARCHS="[]"
else
    echo "cross build type not supported" && exit 1
fi

if [ \( "$3" = "windows" \) ]; then
cat > $2 << EOF

[binaries]
c = '$C_COMPILER'
cpp = '$CXX_COMPILER'
ar = '$AR'
pkgconfig = 'pkg-config'
strip = '$STRIP'

[properties]
target_os = '$4'
archs = $ARCHS

[host_machine]
system = 'windows'
cpu_family = 'x86_64'
cpu = 'x86_64'
endian = 'little'
EOF
else
cat > $2 << EOF

[binaries]
c = '$C_COMPILER'
cpp = '$CXX_COMPILER'
ar = '$AR'
pkgconfig = 'pkg-config'
strip = '$STRIP'

[properties]
target_os = '$4'
ndk_lib_dir = '$5'
archs = $ARCHS
c_args = $CFLAGS
cpp_args = $CFLAGS
c_link_args = $LDFLAGS
cpp_link_args = $LDFLAGS

[host_machine]
system = '$HOST_SYSTEM'
cpu_family = '$SDK_ARCH'
cpu = '$SDK_CPU'
endian = 'little'
EOF
fi
