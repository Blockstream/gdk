if test "x$1" == "x--iphone"; then
    export IOS_PLATFORM=iPhoneOS
    export ARCHS="-arch arm64"
    export IOS_SDK_PATH=$(xcrun --sdk iphoneos --show-sdk-path)
else
    export IOS_PLATFORM=iPhoneSimulator
    export ARCHS="-arch x86_64"
    export IOS_SDK_PATH=$(xcrun --sdk iphonesimulator --show-sdk-path)
fi


export SDK_CFLAGS_NO_ARCH="$q"
export SDK_CFLAGS="$SDK_CFLAGS $ARCHS"
export SDK_CPPFLAGS="$SDK_CFLAGS"
export SDK_LDFLAGS="$SDK_CFLAGS"

export IOS_CFLAGS="${SDK_CFLAGS} -isysroot${IOS_SDK_PATH} -miphoneos-version-min=11.0 -O3"
export IOS_LDFLAGS="${SDK_LDFLAGS} -isysroot${IOS_SDK_PATH} -miphoneos-version-min=11.0"

if [ \( $1 = "--iphonesim" \)  -a \( "$(sw_vers -productVersion)" = "10.15" \) ]; then
    export DYLD_ROOT_PATH=$IOS_SDK_PATH
fi