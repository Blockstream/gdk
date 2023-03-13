export PATH=$NDK_TOOLSDIR/bin:$PATH_BASE
export CFLAGS="$SDK_CFLAGS --sysroot=$NDK_TOOLSDIR/sysroot -O2"
export LDFLAGS="$SDK_LDFLAGS --sysroot=$NDK_TOOLSDIR/sysroot -fuse-ld=lld"
export CPPFLAGS="$SDK_CFLAGS"
export SYSROOT="$NDK_TOOLSDIR/sysroot"
export ANDROID_NDK_HOME="$NDK_TOOLSDIR"
export CC=$(ls $NDK_TOOLSDIR/bin/$clangarchname-linux-android*$ANDROID_VERSION-clang)
export CXX=$(ls $NDK_TOOLSDIR/bin/$clangarchname-linux-android*$ANDROID_VERSION-clang++)
case $NDK_ARCH in
armeabi-v7a)
    export NDK_TARGET_HOST=armv7-none-linux-androideabi19
    ;;
arm64-v8a)
    export NDK_TARGET_HOST=aarch64-none-linux-android21
    ;;
x86_64)
    export NDK_TARGET_HOST=x86_64-none-linux-android21
    ;;
*)
    export NDK_TARGET_HOST=i686-none-linux-android19
    ;;
esac
