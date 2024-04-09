#!/usr/bin/env bash
set -e

BUILD=$1
TARGET_ARCH=$2

export HOST_ARCH=$(uname -m)
export HOST_PLATFORM=$(uname -s | tr '[:upper:]' '[:lower:]')
case $HOST_PLATFORM in
    linux)
        export host_triple="${HOST_ARCH}-pc-linux-gnu"
        ;;
    darwin)
        export host_triple="${HOST_ARCH}-apple-darwin"
        ;;
    *)
        echo "Unsupported platform: $HOST_PLATFORM"
        exit 1
        ;;
esac

case $BUILD in
    "--clang")
        export target_triple=${HOST_ARCH}-pc-linux-gnu
        export CC="clang"
        export CXX="clang++"
        export AR="ar"
        export RANLIB="ranlib"
        CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/clang.cmake
        if [ $HOST_PLATFORM == "darwin" ]; then
            export target_triple="${HOST_ARCH}-apple-darwin"
            CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/macOS.cmake
            export SDK_SYSROOT=$(xcrun --show-sdk-path)
            SDK_CFLAGS+=" -isysroot${SDK_SYSROOT} -mmacosx-version-min=10.15"
            SDK_CXXFLAGS+=" -isysroot${SDK_SYSROOT} -mmacosx-version-min=10.15"
            SDK_LDFLAGS+=" -isysroot${SDK_SYSROOT} -mmacosx-version-min=10.15"
        fi
        ;;

    "--gcc")
        export target_triple="${HOST_ARCH}-pc-linux-gnu"
        export CC="gcc"
        export CXX="g++"
        export AR="ar"
        export RANLIB="ranlib"
        CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/gcc.cmake
        ;;

    "--ndk")
        if [ -z ${ANDROID_NDK} ]; then
            echo "ANDROID_NDK not set"
            exit 1
        fi
        export NDK_TOOLSDIR="${ANDROID_NDK}/toolchains/llvm/prebuilt/linux-${HOST_ARCH}"
        export ANDROID_VERSION="23"
        export SDK_SYSROOT="${NDK_TOOLSDIR}/sysroot"
        SDK_LDFLAGS="-fuse-ld=lld"
        case $TARGET_ARCH in 
            armeabi-v7a)
                export target_triple="armv7a-linux-android"
                CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/android-armeabi-v7a.cmake
                export SDK_ARCH=armv7a
                SDK_CFLAGS+=" -march=armv7-a -mfloat-abi=softfp -mfpu=neon -mthumb"
                SDK_CXXFLAGS+=" -march=armv7-a -mfloat-abi=softfp -mfpu=neon -mthumb"
                ;;
            arm64-v8a)
                export target_triple="aarch64-linux-android"
                CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/android-arm64-v8a.cmake
                export SDK_ARCH=aarch64
                SDK_CFLAGS+=" -march=armv8-a -flax-vector-conversions"
                SDK_CXXFLAGS+=" -march=armv8-a -flax-vector-conversions"
                ;;
            x86_64)
                export target_triple="x86_64-linux-android"
                CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/android-x86_64.cmake
                export SDK_ARCH=x86_64
                ;;
            x86)
                export target_triple="i686-linux-android"
                CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/android-x86.cmake
                export SDK_ARCH=i686
                ;;
            *)
                echo "Unsupported target architecture: $TARGET_ARCH"
                exit 1
                ;;
        esac
        export CC=$(find $NDK_TOOLSDIR/bin/ -name $SDK_ARCH-linux-android*$ANDROID_VERSION-clang)
        export CXX=$(find $NDK_TOOLSDIR/bin/ -name $SDK_ARCH-linux-android*$ANDROID_VERSION-clang++)
        export AR=$NDK_TOOLSDIR/bin/llvm-ar
        export RANLIB=$NDK_TOOLSDIR/bin/llvm-ranlib
        export AS=$NDK_TOOLSDIR/bin/llvm-as
        export LD=${NDK_TOOLSDIR}/bin/ld
        export STRIP=${NDK_TOOLSDIR}/bin/llvm-strip
        ;;

    "--iphone")
        export target_triple="arm-apple-ios"
        CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/iphoneos.cmake
        export AR=$(xcrun --sdk iphoneos --find ar)
        export RANLIB=$(xcrun --sdk iphones --find ranlib)
        export CC=$(xcrun --sdk iphoneos --find cc)
        export CXX=$(xcrun --sdk iphoneos --find c++)
        export IOS_SDK_PLATFORM=$(xcrun --sdk iphoneos --show-sdk-platform-path)
        SDK_ARCH=aarch64
        IOS_PLATFORM=iPhoneOS
        export SDK_SYSROOT=$(xcrun --sdk iphoneos --show-sdk-path)
        export IOS_SDK_PLATFORM_PATH=$(xcrun --sdk iphonesimulator --show-sdk-platform-path)
        SDK_CFLAGS+=" -isysroot${SDK_SYSROOT} -miphoneos-version-min=13.0 -arch arm64"
        SDK_CXXFLAGS+=" -isysroot${SDK_SYSROOT} -miphoneos-version-min=13.0 -arch arm64"
        SDK_LDFLAGS+=" -isysroot${SDK_SYSROOT} -miphoneos-version-min=13.0 -arch arm64"
        ;;

    "--iphonesim")
        export target_triple="${HOST_ARCH}-apple-iossimulator"
        CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/iphonesimulator.cmake
        export AR=$(xcrun --sdk iphonesimulator --find ar)
        export RANLIB=$(xcrun --sdk iphonesimulator --find ranlib)
        export CC=$(xcrun --sdk iphonesimulator --find cc)
        export CXX=$(xcrun --sdk iphonesimulator --find c++)
        SDK_ARCH=${HOST_ARCH}
        IOS_PLATFORM=iPhoneSimulator
        export SDK_SYSROOT=$(xcrun --sdk iphonesimulator --show-sdk-path)
        export IOS_SDK_PLATFORM_PATH=$(xcrun --sdk iphonesimulator --show-sdk-platform-path)
        SDK_CFLAGS=" -isysroot${SDK_SYSROOT} -mios-simulator-version-min=13.0 -arch ${SDK_ARCH}"
        SDK_CXXFLAGS+=" -isysroot${SDK_SYSROOT} -mios-simulator-version-min=13.0 -arch ${SDK_ARCH}"
        SDK_LDFLAGS+=" -isysroot${SDK_SYSROOT} -mios-simulator-version-min=13.0 -arch ${SDK_ARCH}"
        if [ "$(sw_vers -productVersion)" = "10.15" ]; then
            export DYLD_ROOT_PATH=${SDK_SYSROOT}
        fi
        ;;

    "--mingw-w64")
        export target_triple="${HOST_ARCH}-w64-mingw32"
        export AR=${HOST_ARCH}-w64-mingw32-ar
        export CC=${HOST_ARCH}-w64-mingw32-gcc-posix
        export CXX=${HOST_ARCH}-w64-mingw32-g++-posix
        export RANLIB=${HOST_ARCH}-w64-mingw32-ranlib
        export RC=${HOST_ARCH}-w64-mingw32-windres
        CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/windows-mingw-w64.cmake
        ;;

esac
