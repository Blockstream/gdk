#! /usr/bin/env bash
set -e

function compile_flags() {
    echo "`python -c "import sys; print('<compile_flags>'.join([''] + map(lambda x: x + '\n', sys.argv[1:])))" $@`"
}

BOOST_NAME="boost_1_69_0"

if [ "x${NUM_JOBS}" = "x" ]; then
    NUM_JOBS=4
fi

BUILD=""
if (($# > 0)); then
    BUILD="$1"
    shift
fi

if [ $LTO = "true" ]; then
    EXTRA_COMPILE_FLAGS="<compileflags>-flto"
    EXTRA_LINK_FLAGS="<linkflags>-flto"
fi

cp -r "${MESON_SOURCE_ROOT}/subprojects/${BOOST_NAME}" "${MESON_BUILD_ROOT}/boost"
boost_src_home="${MESON_BUILD_ROOT}/boost"
boost_bld_home="${MESON_BUILD_ROOT}/boost/build"
cd $boost_src_home
if [ \( "$BUILD" = "--ndk" \) ]; then
    . ${MESON_SOURCE_ROOT}/tools/env.sh
    rm -rf "$boost_src_home/tools/build/src/user-config.jam"
    cat > $boost_src_home/tools/build/src/user-config.jam << EOF
using clang : $SDK_ARCH :
${CXX}
:
<compileflags>-std=c++14
<compileflags>"${SDK_CPPFLAGS}"
$EXTRA_COMPILE_FLAGS
<compileflags>"--sysroot=${SYSROOT}"
<compileflags>"-fvisibility=hidden"
<compileflags>"-DBOOST_LOG_NO_ASIO"
$(compile_flags $@)
<archiver>$AR
<linkflags>"--sysroot=${SYSROOT}"
$EXTRA_LINK_FLAGS
<architecture>${SDK_ARCH}
<target-os>android
;
EOF
    ./bootstrap.sh --prefix="$boost_bld_home" --with-libraries=chrono,log,system,thread
    ./b2 --clean
    ./b2 -j$NUM_JOBS --with-chrono --with-log --with-thread --with-system cxxflags=-fPIC toolset=clang-${SDK_ARCH} target-os=android link=static release install
    if [ "$(uname)" = "Darwin" ]; then
       ${RANLIB} $boost_bld_home/lib/*.a
    fi
elif [ \( "$BUILD" = "--iphone" \) -o \( "$BUILD" = "--iphonesim" \) ]; then
    . ${MESON_SOURCE_ROOT}/tools/ios_env.sh $BUILD

    rm -rf "$boost_src_home/tools/build/src/user-config.jam"
    cat > "$boost_src_home/tools/build/src/user-config.jam" << EOF
using darwin : arm :
${XCODE_DEFAULT_PATH}/clang++
:
<root>${IOS_SDK_PATH}
<compileflags>-std=c++14
<compileflags>"${SDK_CFLAGS}"
$EXTRA_COMPILE_FLAGS
<compileflags>"-miphoneos-version-min=11.0"
<compileflags>"-isysroot ${IOS_SDK_PATH}"
<compileflags>"-fvisibility=hidden"
<compileflags>"-DBOOST_LOG_NO_ASIO"
$(compile_flags $@)
<linkflags>"-miphoneos-version-min=11.0"
$EXTRA_LINK_FLAGS
<linkflags>"-isysroot ${IOS_SDK_PATH}"
<target-os>iphone
;
EOF
    ./bootstrap.sh --prefix="$boost_bld_home" --with-libraries=chrono,log,system,thread
    ./b2 --clean
    ./b2 -j$NUM_JOBS --with-chrono --with-log --with-thread --with-system toolset=darwin-arm target-os=iphone link=static release install
elif [ \( "$BUILD" = "--windows" \) ]; then
    rm -rf "$boost_src_home/tools/build/src/user-config.jam"
    cat > "$boost_src_home/tools/build/src/user-config.jam" << EOF
using gcc : :
x86_64-w64-mingw32-g++-posix
:
<compileflags>-std=c++14
<compileflags>"${SDK_CFLAGS}"
<compileflags>"-fvisibility=hidden"
$(compile_flags $@)
<target-os>windows
;
EOF
    ./bootstrap.sh --prefix="$boost_bld_home" --with-libraries=chrono,log,system,thread
    ./b2 --clean
    ./b2 -j$NUM_JOBS --with-chrono --with-log --with-thread --with-system address-model=64 architecture=x86 toolset=gcc target-os=windows link=static release install
else
    TOOLSET=
    if [[ ${CC} = *"clang"* ]]; then
        TOOLSET=clang
    elif [[ ${CC} = *"gcc"* ]]; then
        TOOLSET=gcc
    fi


    EXTRAFLAGS=""
    LINKFLAGS=""
    if [ $LTO = "true" ]; then
        EXTRAFLAGS="-flto"
        LINKFLAGS="linkflags=-flto"
    fi

    cxxflags="$EXTRAFLAGS -DPIC -fPIC -fvisibility=hidden -DBOOST_LOG_NO_ASIO ${@}"

    ./bootstrap.sh --prefix="$boost_bld_home" --with-libraries=chrono,log,system,thread --with-toolset=${TOOLSET}
    ./b2 --clean
    ./b2 -j$NUM_JOBS --with-chrono --with-log --with-thread --with-system cxxflags="$cxxflags" $LINKFLAGS link=static release install
fi
