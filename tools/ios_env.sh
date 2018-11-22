if test "x$1" == "x--iphone"; then
    export IOS_PLATFORM=iPhoneOS
    export ARCHS="-arch arm64"
else
    export IOS_PLATFORM=iPhoneSimulator
    export ARCHS="-arch x86_64"
fi

export XCODE_PATH=$(xcode-select --print-path 2>/dev/null)
export XCODE_DEFAULT_PATH="$XCODE_PATH/Toolchains/XcodeDefault.xctoolchain/usr/bin"
export XCODE_IOS_PATH="$XCODE_PATH/Platforms/$IOS_PLATFORM.platform/Developer/usr/bin"
export IOS_SDK_PATH="$XCODE_PATH/Platforms/$IOS_PLATFORM.platform/Developer/SDKs/$IOS_PLATFORM.sdk"

export SDK_CFLAGS_NO_ARCH="$SDK_CFLAGS"
export SDK_CFLAGS="$SDK_CFLAGS $ARCHS"
export SDK_CPPFLAGS="$SDK_CFLAGS"
export SDK_LDFLAGS="$SDK_CFLAGS"
