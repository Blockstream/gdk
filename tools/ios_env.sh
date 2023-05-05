if test "x$1" == "x--iphone"; then
    export IOS_PLATFORM=iPhoneOS
    export ARCHS="-arch arm64"
    export IOS_SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path)
    export IOS_SDK_PLATFORM=$(xcrun --sdk iphoneos --show-sdk-platform-path)
    export IOS_MIN_VERSION="-miphoneos-version-min=11.0"
else
    export IOS_PLATFORM=iPhoneSimulator
    export ARCHS="-arch $(uname -m)"
    export IOS_SDK_PATH=$(xcrun --sdk iphonesimulator --show-sdk-path)
    export IOS_SDK_PLATFORM=$(xcrun --sdk iphonesimulator --show-sdk-platform-path)
    export IOS_MIN_VERSION="-mios-simulator-version-min=13.7"
fi

export XCODE_DEFAULT_PATH=$(xcode-select --print-path)"/Toolchains/XcodeDefault.xctoolchain/usr/bin"
export SDK_CFLAGS_NO_ARCH="$q"
export SDK_CFLAGS="$SDK_CFLAGS $ARCHS"
export SDK_CPPFLAGS="$SDK_CFLAGS"
export SDK_LDFLAGS="$SDK_CFLAGS"

export IOS_CFLAGS="${SDK_CFLAGS} -isysroot${IOS_SDK_PATH} ${IOS_MIN_VERSION} -O2"
export IOS_CXXFLAGS="${SDK_CPPFLAGS} -isysroot${IOS_SDK_PATH} ${IOS_MIN_VERSION} -O2"
export IOS_LDFLAGS="${SDK_LDFLAGS} -isysroot${IOS_SDK_PATH} ${IOS_MIN_VERSION}"

if [ \( $1 = "--iphonesim" \)  -a \( "$(sw_vers -productVersion)" = "10.15" \) ]; then
    export DYLD_ROOT_PATH=$IOS_SDK_PATH
fi
