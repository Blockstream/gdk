export CFLAGS="$SDK_CFLAGS --sysroot=$NDK_TOOLSDIR/sysroot -O3"
export LDFLAGS="$SDK_LDFLAGS --sysroot=$NDK_TOOLSDIR/sysroot -fuse-ld=lld"
export CPPFLAGS="$SDK_CFLAGS"
export SYSROOT="$NDK_TOOLSDIR/sysroot"
export CC=$(ls $NDK_TOOLSDIR/bin/$clangarchname-linux-android*$ANDROID_VERSION-clang)
export CXX=$(ls $NDK_TOOLSDIR/bin/$clangarchname-linux-android*$ANDROID_VERSION-clang++)
