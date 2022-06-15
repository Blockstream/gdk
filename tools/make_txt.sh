#!/usr/bin/env bash
set -e

function comma_separate() {
    echo "`python -c "import sys; print('[' + ','.join(map(lambda x: '\'' + x + '\'', sys.argv[1:])) + ']')" $@`"
}

if [ \( "$3" = "android" \) ]; then
    C_COMPILER=$(ls $NDK_TOOLSDIR/bin/$clangarchname-linux-android*$ANDROID_VERSION-clang)
    CXX_COMPILER=$(ls $NDK_TOOLSDIR/bin/$clangarchname-linux-android*$ANDROID_VERSION-clang++)
    STRIP="$(ls $NDK_TOOLSDIR/bin/llvm-strip)"
    OBJCOPY="$(ls $NDK_TOOLSDIR/bin/llvm-objcopy)"
    CFLAGS=$(comma_separate "--sysroot=$NDK_TOOLSDIR/sysroot" $SDK_CFLAGS)
    LDFLAGS=$(comma_separate $SDK_LDFLAGS)
    ARCHS="[]"
    HOST_SYSTEM=$3
elif [ \( "$3" = "iphone" \) -o \( "$3" = "iphonesim" \) ]; then
    C_COMPILER="clang"
    CXX_COMPILER="clang++"
    CFLAGS=$(comma_separate $IOS_CFLAGS "-stdlib=libc++")
    LDFLAGS=$(comma_separate $IOS_LDFLAGS "-stdlib=libc++")
    ARCHS=$(comma_separate $ARCHS)
    HOST_SYSTEM="darwin"
elif [ \( "$3" = "windows" \) ]; then
    C_COMPILER="x86_64-w64-mingw32-gcc-posix"
    CXX_COMPILER="x86_64-w64-mingw32-g++-posix"
    STRIP="x86_64-w64-mingw32-strip"
    OBJCOPY="x86_64-w64-mingw32-objcopy"
    ARCHS="[]"
else
    echo "cross build type not supported" && exit 1
fi

if [ \( "$HOST_SYSTEM" = "darwin" \) ]; then
  STRIP="$STRIP -x"
fi

if [ \( "$3" = "windows" \) ]; then
cat > $2 << EOF

[binaries]
c = '$C_COMPILER'
cpp = '$CXX_COMPILER'
ar = '$AR'
pkgconfig = 'pkg-config'
strip = '$STRIP'
objcopy = '$OBJCOPY'

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
objcopy = '$OBJCOPY'

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
