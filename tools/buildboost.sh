#! /usr/bin/env bash
set -e

function compile_flags() {
    echo "`python -c "import sys; print('<compile_flags>'.join([''] + map(lambda x: x + '\n', sys.argv[1:])))" $@`"
}

BOOST_NAME="$(basename ${PRJ_SUBDIR})"

if [ "x${NUM_JOBS}" = "x" ]; then
    NUM_JOBS=4
fi

COMPILER=""
if (($# > 0)); then
    COMPILER="$1"
    shift
fi

BUILD=""
if (($# > 0)); then
    BUILD="$1"
    shift
fi


boost_src_home="${PRJ_SUBDIR}"
boost_bld_home="${GDK_BUILD_ROOT}"
cd $boost_src_home
if [ \( "$BUILD" = "--ndk" \) ]; then
    ./bootstrap.sh --prefix="$boost_bld_home" --with-libraries=chrono,date_time,log,system,thread
    rm -rf "$boost_src_home/tools/build/src/user-config.jam"
    cat > $boost_src_home/tools/build/src/user-config.jam << EOF
using clang : :
${CXX}
:
<compileflags>-std=c++17
<compileflags>"${CXXFLAGS}"
<compileflags>"--sysroot=${SDK_SYSROOT}"
<compileflags>"-fvisibility=hidden"
<compileflags>"-DBOOST_LOG_NO_ASIO"
<compileflags>"-DBOOST_LOG_WITHOUT_EVENT_LOG"
<compileflags>"-DBOOST_LOG_WITHOUT_SYSLOG"
<compileflags>"-DBOOST_LOG_WITHOUT_IPC"
<compileflags>"-DBOOST_LOG_WITHOUT_DEBUG_OUTPUT"
<compileflags>"-DBOOST_LOG_WITHOUT_SETTINGS_PARSERS"
$(compile_flags $@)
<archiver>$AR
<ranlib>$RANLIB
<linkflags>"--sysroot=${SDK_SYSROOT}"
$LDFLAGS
<architecture>${SDK_ARCH}
<target-os>android
;
EOF
    ./b2 --clean
    ./b2 -j$NUM_JOBS -d0 --with-chrono --with-date_time --with-log --with-thread --with-system cxxflags=-fPIC toolset=clang target-os=android link=static release install
    if [ "$(uname)" = "Darwin" ]; then
       ${RANLIB} $boost_bld_home/lib/*.a
    fi
elif [ \( "$BUILD" = "--iphone" \) -o \( "$BUILD" = "--iphonesim" \) ]; then
    gsed -i "s!B2_CXXFLAGS_RELEASE=.*!B2_CXXFLAGS_RELEASE=\"-O2 -s -isysroot $(xcrun --show-sdk-path)\"!" \
          ${boost_src_home}/tools/build/src/engine/build.sh
              gsed -i "s!B2_CXXFLAGS_DEBUG=.*!B2_CXXFLAGS_DEBUG=\"-O0 -g -p -isysroot $(xcrun --show-sdk-path)\"!" \
          ${boost_src_home}/tools/build/src/engine/build.sh
    ./bootstrap.sh --prefix="$boost_bld_home" --with-libraries=chrono,date_time,log,system,thread

    rm -rf "$boost_src_home/tools/build/src/user-config.jam"
    cat > "$boost_src_home/tools/build/src/user-config.jam" << EOF
using darwin : arm :
${CXX}
:
<root>${SDK_SYSROOT}
<compileflags>-std=c++17
<compileflags>"${CXXFLAGS}"
<compileflags>"-isysroot ${SDK_SYSROOT}"
<compileflags>"-fvisibility=hidden"
<compileflags>"-DBOOST_LOG_NO_ASIO"
<compileflags>"-DBOOST_LOG_WITHOUT_EVENT_LOG"
<compileflags>"-DBOOST_LOG_WITHOUT_SYSLOG"
<compileflags>"-DBOOST_LOG_WITHOUT_IPC"
<compileflags>"-DBOOST_LOG_WITHOUT_DEBUG_OUTPUT"
<compileflags>"-DBOOST_LOG_WITHOUT_SETTINGS_PARSERS"
$(compile_flags $@)
<linkflags>"${LDFLAGS}"
<linkflags>"-isysroot ${SDK_SYSROOT}"
<target-os>iphone
;
EOF
    ./b2 --clean
    ./b2 -j$NUM_JOBS -d0 --with-chrono --with-date_time --with-log --with-thread --with-system toolset=darwin-arm target-os=iphone link=static release install
elif [ \( "$BUILD" = "--mingw-w64" \) ]; then
    rm -rf "$boost_src_home/tools/build/src/user-config.jam"
    cat > "$boost_src_home/tools/build/src/user-config.jam" << EOF
using gcc : :
x86_64-w64-mingw32-g++-posix
:
<compileflags>-std=c++17
<compileflags>"${CXXFLAGS}"
<compileflags>"-fvisibility=hidden"
$(compile_flags $@)
<target-os>windows
;
EOF
    ./bootstrap.sh --prefix="$boost_bld_home" --with-libraries=chrono,date_time,log,system,thread
    ./b2 --clean
    ./b2 -j$NUM_JOBS -d0 --with-chrono --with-date_time --with-log --with-thread --with-system address-model=64 architecture=x86 toolset=gcc target-os=windows link=static release install
else
    TOOLSET=$COMPILER
    if [[ ${CC} = *"clang"* ]]; then
        TOOLSET=clang
    elif [[ ${CC} = *"gcc"* ]]; then
        TOOLSET=gcc
    fi

    EXTRAFLAGS=""
    LINKFLAGS=""

    cxxflags="$CXXFLAGS -fvisibility=hidden -DBOOST_LOG_NO_ASIO -DBOOST_LOG_WITHOUT_EVENT_LOG -DBOOST_LOG_WITHOUT_SYSLOG -DBOOST_LOG_WITHOUT_IPC -DBOOST_LOG_WITHOUT_DEBUG_OUTPUT -DBOOST_LOG_WITHOUT_SETTINGS_PARSERS ${@}"
    ./bootstrap.sh --prefix="$boost_bld_home" --with-libraries=chrono,date_time,log,system,thread --with-toolset=${TOOLSET}
    ./b2 --clean
    ./b2 -j$NUM_JOBS -d0 --with-chrono --with-date_time --with-log --with-thread --with-system cxxflags="$cxxflags" $LINKFLAGS link=static release install
fi
