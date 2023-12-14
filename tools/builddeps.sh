#!/usr/bin/env bash
set -e

have_cmd()
{
    command -v "$1" >/dev/null 2>&1
}

function set_cross_build_env() {
    export HOST_ARCH=$2
    case $2 in
        armeabi-v7a)
            export SDK_ARCH=arm
            export SDK_CPU=armv7
            export SDK_CFLAGS="-march=armv7-a -mfloat-abi=softfp -mfpu=neon -mthumb"
            export CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/android-armeabi-v7a.cmake
            ;;
        arm64-v8a)
            export SDK_ARCH=aarch64
            export SDK_CPU=arm64-v8a
            export SDK_CFLAGS="-march=armv8-a -flax-vector-conversions"
            export CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/android-arm64-v8a.cmake
            ;;
        iphone)
            export SDK_ARCH=aarch64
            export SDK_CPU=arm64
            ;;
        iphonesim)
            export SDK_ARCH="$(uname -m)"
            export SDK_CPU="$(uname -m)"
            if [ "$SDK_ARCH" = "arm64" ]; then
                export SDK_ARCH="aarch64"
            fi
            ;;
        x86_64)
            export SDK_ARCH=$HOST_ARCH
            export SDK_CPU=$HOST_ARCH
            export CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/android-x86_64.cmake
            ;;
        *)
            export SDK_ARCH=$2
            export SDK_CPU=i686
            export CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/android-x86.cmake
            ;;
    esac
}

if have_cmd gsed; then
    export SED=$(command -v gsed)
elif have_cmd sed; then
    export SED=$(command -v sed)
else
    echo "Could not find sed or gsed. Please install sed and try again."
    exit 1
fi

export HOST_OS="i686-linux-gnu"
if [ "$(uname)" = "Darwin" ]; then
    if [ "$(uname -m)" = "arm64" ]; then
        export HOST_OS="aarch64-apple-darwin"
        export SDK_ARCH="aarch64"
        export SDK_CPU="arm64"
    else
        export SDK_ARCH="x86_64"
        export SDK_CPU="x86_64"
        export HOST_OS="x86_64-apple-darwin"
    fi
fi
BUILD=""
BUILDTYPE="release"
NDK_ARCH=""
COMPILER_VERSION=""
export GDK_BUILD_ROOT=""
export PATH_BASE=$PATH


export NDK_TOOLSDIR="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64"
export GDK_SOURCE_ROOT=$(pwd)
export CFLAGS="$CFLAGS"
export CPPFLAGS="$CFLAGS"
export PATH_BASE=$PATH
export BUILDTYPE


while true; do
    case "$1" in
        -b | --buildtype ) BUILDTYPE=$2; shift 2 ;;
        --clang | --gcc | --mingw-w64 ) BUILD="$1"; shift ;;
        --iphone | --iphonesim ) BUILD="$1"; LIBTYPE="$2"; shift 2 ;;
        --ndk ) BUILD="$1"; NDK_ARCH="$2"; shift 2 ;;
        --compiler-version) COMPILER_VERSION="-$2"; shift 2 ;;
        --prefix ) GDK_BUILD_ROOT="$2"; shift 2 ;;
        --parallel ) NUM_JOBS="$2"; shift 2 ;;
        -- ) shift; break ;;
        *) break ;;
    esac
done

if [ -z ${GDK_BUILD_ROOT} ]; then
    echo "please specify a destination folder with --prefix"
    exit 1
fi

if [ -z "${NUM_JOBS}" ]; then
    if [ -f /proc/cpuinfo ]; then
        NUM_JOBS=${NUM_JOBS:-$(cat /proc/cpuinfo | grep ^processor | wc -l)}
    fi
    NUM_JOBS=${NUM_JOBS:-4}
fi
export NUM_JOBS


C_COMPILER=""
CXX_COMPILER=""
if [ ${BUILD} == "--gcc" ]; then
    C_COMPILER="gcc"
    CXX_COMPILER="g++"
    CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/gcc.cmake
elif [ ${BUILD} == "--clang" ]; then
    C_COMPILER="clang"
    CXX_COMPILER="clang++"
    CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/clang.cmake
    if [ "$(uname)" = "Darwin" ]; then
        source tools/macos_env.sh
        CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/macOS.cmake
    fi
elif [ ${BUILD} == "--ndk" ]; then
    C_COMPILER="clang"
    CXX_COMPILER="clang++"
    set_cross_build_env android $NDK_ARCH
    if [[ $SDK_ARCH = *"64"* ]]; then
        export ANDROID_VERSION="21"
    else
        export ANDROID_VERSION="19"
    fi
    export clangarchname=$HOST_ARCH
    export archfilename=$SDK_ARCH
    case $archfilename in
        armeabi-v7a) archfilename=arm;;
        arm64-v8a) archfilename=aarch64;;
        x86) archfilename=i686;;
    esac
    case $clangarchname in
        armeabi-v7a) clangarchname=armv7a;;
        arm64-v8a) clangarchname=aarch64;;
        x86) clangarchname=i686;;
    esac
    export AR="$NDK_TOOLSDIR/bin/llvm-ar"
    export RANLIB="$NDK_TOOLSDIR/bin/llvm-ranlib"
elif [ ${BUILD} == "--iphone" ]; then
    set_cross_build_env ios iphone
    . tools/ios_env.sh $BUILD
    export AR=ar
    C_COMPILER=${XCODE_DEFAULT_PATH}/clang
    CXX_COMPILER=${XCODE_DEFAULT_PATH}/clang++
    export CFLAGS="${IOS_CFLAGS} ${EXTRA_FLAGS}"
    export LDFLAGS="${IOS_LDFLAGS} ${EXTRA_FLAGS}"
    CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/iphoneos.cmake
elif [ ${BUILD} == "--iphonesim" ]; then
    set_cross_build_env ios iphonesim
    . tools/ios_env.sh $BUILD
    export AR=ar
    C_COMPILER=${XCODE_DEFAULT_PATH}/clang
    CXX_COMPILER=${XCODE_DEFAULT_PATH}/clang++
    export CFLAGS="${IOS_CFLAGS} ${EXTRA_FLAGS}"
    export LDFLAGS="${IOS_LDFLAGS} ${EXTRA_FLAGS}"
    CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/iphonesimulator.cmake
elif [ ${BUILD} == "--mingw-w64" ]; then
    BUILD="--windows"
    C_COMPILER=gcc-posix
    CXX_COMPILER=g++-posix
    CMAKE_TOOLCHAIN_FILE=${GDK_SOURCE_ROOT}/cmake/profiles/windows-mingw-w64.cmake
else
    echo "BUILD \"${BUILD}\" not recognized, exiting"
    exit 0
fi

if [ ${BUILDTYPE} == "debug" ]; then
    if [ ${BUILD} == "--mingw-w64" ]; then
        # when debugging in windows try dwarf-2 or stabs formats
        export CFLAGS="-g -gdwarf-2 -O0 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
        export CXXFLAGS="-gdwarf-2 -O0 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
        export CPPFLAGS="-g -gdwarf-2 -O0 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
        export BUILDTYPE=${BUILDTYPE}
    else
        export CFLAGS="-ggdb3 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
        export CXXFLAGS="-ggdb3 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
        export CPPFLAGS="-ggdb3 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
        export BUILDTYPE=${BUILDTYPE}
    fi
else
    export CFLAGS="$CFLAGS -O2 -DNDEBUG"
    export CXXFLAGS="$CXXFLAGS -O2 -DNDEBUG"
    # export CPPFLAGS="$CPPFLAGS -O2 -DNDEBUG" # tor seems to be annoyed by this variable ¯\_(ツ)_/¯
fi

export CXX=$CXX_COMPILER
export CCC_CXX=$CXX_COMPILER
export CC=$C_COMPILER
export CCC_CC=$C_COMPILER


mkdir -p ${GDK_BUILD_ROOT}

export NDK_ARCH=${NDK_ARCH}


function prepare_sources {
    source_url=$1
    source_filename=$2
    source_hash=$3
    rm_downloaded=""
    downloads_folder="downloads"

    if [ ! -d ${downloads_folder} ]; then
        mkdir -p ${downloads_folder}
    fi

    cd ${downloads_folder}
    if [ ! -f ${source_filename} ]; then
        echo "downloading from ${source_url} ..."
        curl -sL --retry 3 ${source_url} --output ${source_filename}
        rm_downloaded="yes"
    fi
    echo "checking ${source_filename}..."
    echo "${source_hash}  ${source_filename}" | shasum -a 256 -c

    cd -
    tmp_folder="tmp"
    tar -xf ${downloads_folder}/${source_filename} -C ${tmp_folder}
    if [ -n "${rm_downloaded}" -a -z "${GDK_KEEP_DOWNLOADS}" ]; then
        rm ${downloads_folder}/${source_filename}
    fi
}

function build {
    name=$1
    source_subdir=$2
    export PRJ_SUBDIR=${source_subdir}
    ${GDK_SOURCE_ROOT}/tools/build${name}.sh ${BUILD}
    ret_code=$?
    if [ ${ret_code} != 0 ]; then
        echo "something went wrong in building ${name}, aborting"
        exit 1
    fi
}

rm -rf tmp
mkdir tmp
cmake_build_type=${BUILDTYPE^}


# building wally-core
name="libwally-core"
source_url="https://github.com/ElementsProject/libwally-core/tarball/6f67467299a038f9ceaa12272387a7ce71fd533f/ElementsProject-libwally-core-6f67467.tar.gz"
source_name="ElementsProject-libwally-core-6f67467"
source_filename="${source_name}.tar.gz"
source_hash="ac4045073bb34d24f68ce234b0593d608e02ae1774387a338b2539859c1b7700"
secpurl="https://github.com/ElementsProject/secp256k1-zkp.git"
# Update this line to the secp commit used in wally
secpcommit="2192e9d051186754100fd270955fa6e7df26d457"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export WALLYCORE_SRCDIR=`pwd`/tmp/${source_name}
export WALLYCORE_NAME=${source_name}
export SECP_URL=${secpurl}
export SECP_COMMIT=${secpcommit}
build ${name} ${WALLYCORE_SRCDIR}


# building  zlib
name="zlib"
source_url="https://github.com/madler/zlib/archive/v1.3.tar.gz"
source_name="zlib-1.3"
source_filename="${source_name}.tar.gz"
source_hash="b5b06d60ce49c8ba700e0ba517fa07de80b5d4628a037f4be8ad16955be7a7c0"
prepare_sources ${source_url} ${source_filename} ${source_hash}
cmake -B tmp/${source_name}/build -S tmp/${source_name} \
    -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT} \
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} \
    -DCMAKE_BUILD_TYPE=${cmake_build_type}
cmake --build tmp/${source_name}/build --target zlibstatic zlib --parallel $NUM_JOBS
cmake --install tmp/${source_name}/build
# no better way to avoid installing dynamic lib, not to tell cmake to import static zlib
find ${GDK_BUILD_ROOT}/lib -name "libz.so*" -type l -delete
find ${GDK_BUILD_ROOT}/lib -name "libz.so*" -type f -delete
find ${GDK_BUILD_ROOT}/lib -name "libz*.dylib" -type f -delete
find ${GDK_BUILD_ROOT}/lib -name "libz.dll*" -type f -delete
# https://github.com/madler/zlib/issues/652
if [ ${BUILD} == "--windows" ]; then
    mv ${GDK_BUILD_ROOT}/lib/libzlibstatic.a ${GDK_BUILD_ROOT}/lib/libz.a
fi


# building libevent
name="libevent"
source_url="https://github.com/libevent/libevent/archive/release-2.1.12-stable.tar.gz"
source_name="libevent-release-2.1.12-stable"
source_filename="${source_name}.tar.gz"
source_hash="7180a979aaa7000e1264da484f712d403fcf7679b1e9212c4e3d09f5c93efc24"
prepare_sources ${source_url} ${source_filename} ${source_hash}
cmake -B tmp/${source_name}/build -S tmp/${source_name} \
    -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT} \
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} \
    -DCMAKE_BUILD_TYPE=${cmake_build_type} \
    -DEVENT__LIBRARY_TYPE:STRING=STATIC \
    -DEVENT__DISABLE_SAMPLES:BOOL=TRUE \
    -DEVENT__DISABLE_OPENSSL:BOOL=TRUE \
    -DEVENT__DISABLE_REGRESS:BOOL=TRUE \
    -DEVENT__DISABLE_DEBUG_MODE:BOOL=TRUE \
    -DEVENT__DISABLE_TESTS:BOOL=TRUE \
    -DEVENT__DISABLE_BENCHMARK:BOOL=TRUE
cmake --build tmp/${source_name}/build --parallel $NUM_JOBS
cmake --install tmp/${source_name}/build


# building openssl
name="openssl"
source_url="https://github.com/openssl/openssl/releases/download/OpenSSL_1_1_1w/openssl-1.1.1w.tar.gz"
source_name="openssl-1.1.1w"
source_filename="${source_name}.tar.gz"
source_hash="cf3098950cb4d853ad95c0841f1f9c6d3dc102dccfcacd521d93925208b76ac8"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export OPENSSL_SRCDIR=`pwd`/tmp/${source_name}
build ${name} ${OPENSSL_SRCDIR}


# building boost
name="boost"
source_url="https://boostorg.jfrog.io/artifactory/main/release/1.82.0/source/boost_1_82_0.tar.gz"
source_name="boost_1_82_0"
source_filename="boost_1_82_0.tar.gz"
source_hash="66a469b6e608a51f8347236f4912e27dc5c60c60d7d53ae9bfe4683316c6f04c"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export BOOST_SRCDIR=`pwd`/tmp/${source_name}
export PRJ_SUBDIR=${BOOST_SRCDIR}
${GDK_SOURCE_ROOT}/tools/build${name}.sh $C_COMPILER $BUILD ${CXXFLAGS}


# building tor
name="tor"
source_url="https://dist.torproject.org/tor-0.4.7.13.tar.gz"
source_name="tor-0.4.7.13"
source_filename="${source_name}.tar.gz"
source_hash="2079172cce034556f110048e26083ce9bea751f3154b0ad2809751815b11ea9d"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export TOR_SRCDIR=`pwd`/tmp/${source_name}
build ${name} ${source_name} "tmp"


# building nlohmann-json
name="nlohmann_json"
source_url="https://github.com/nlohmann/json/releases/download/v3.11.2/json.tar.xz"
source_name="json"
source_filename="json-3.11.2.tar.xz"
source_hash="8c4b26bf4b422252e13f332bc5e388ec0ab5c3443d24399acb675e68278d341f"
prepare_sources ${source_url} ${source_filename} ${source_hash}
cmake -B tmp/${source_name}/build -S tmp/${source_name} \
    -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT} \
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} \
    -DCMAKE_BUILD_TYPE=${cmake_build_type} \
    -DJSON_BuildTests:BOOL=OFF \
    -DJSON_Install:BOOL=ON \
    -DJSON_MultipleHeaders:BOOL=ON \
    -DJSON_SystemInclude:BOOL=ON
cmake --build tmp/${source_name}/build --parallel $NUM_JOBS
cmake --install tmp/${source_name}/build


# building websocketpp
name="websocketpp"
source_url="https://github.com/blockstream/websocketpp/archive/1026e877449aeee27e0bb51746a96ab42d133652.tar.gz"
source_name="websocketpp-1026e877449aeee27e0bb51746a96ab42d133652"
source_filename="websocketpp-1026e877449aeee27e0bb51746a96ab42d133652.tar.gz"
source_hash="82644fce179590ec73daf3a42383b26378716ba61bbde7ef460816170fed5aeb"
prepare_sources ${source_url} ${source_filename} ${source_hash}
cmake -B tmp/${source_name}/build -S tmp/${source_name} \
    -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT} \
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} \
    -DCMAKE_BUILD_TYPE=${cmake_build_type}
cmake --build tmp/${source_name}/build --parallel $NUM_JOBS
cmake --install tmp/${source_name}/build


# building msgpack
name="msgpack"
source_url="https://github.com/msgpack/msgpack-c/releases/download/cpp-4.1.1/msgpack-cxx-4.1.1.tar.gz"
source_name="msgpack-cxx-4.1.1"
source_filename="msgpack-4.1.1.tar.gz"
source_hash="8115c5edcf20bc1408c798a6bdaec16c1e52b1c34859d4982a0fb03300438f0b"
prepare_sources ${source_url} ${source_filename} ${source_hash}
cmake -B tmp/${source_name}/build -S tmp/${source_name} \
    -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT} \
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} \
    -DCMAKE_BUILD_TYPE=${cmake_build_type} \
    -DBOOST_ROOT:PATH=${GDK_BUILD_ROOT} \
    -DMSGPACK_USE_STATIC_BOOST:BOOL=ON \
    -DMSGPACK_BUILD_DOCS:BOOL=OFF \
    -DMSGPACK_CXX14:BOOL=ON
cmake --build tmp/${source_name}/build --parallel $NUM_JOBS
cmake --install tmp/${source_name}/build


# building autobahn-cpp
name="autobahn-cpp"
source_url="https://codeload.github.com/jgriffiths/autobahn-cpp/tar.gz/976e1f64bf5bc5bf22d7b96e1447467d6e1c063f"
source_name="autobahn-cpp-976e1f64bf5bc5bf22d7b96e1447467d6e1c063f"
source_filename="autobahn-cpp-68a79600efd6b4861e2155ce640108918c538312f6e7d8e1fc7f660d425c2b7c.tar.gz"
source_hash="68a79600efd6b4861e2155ce640108918c538312f6e7d8e1fc7f660d425c2b7c"
prepare_sources ${source_url} ${source_filename} ${source_hash}
rm -f tmp/${source_name}/cmake/Modules/FindWebsocketpp.cmake
rm -f tmp/${source_name}/cmake/Modules/FindMsgpack.cmake
${SED} -ie "s/Boost REQUIRED COMPONENTS program_options system thread random/Boost COMPONENTS system thread/g" tmp/${source_name}/cmake/Includes/CMakeLists.txt
${SED} -ie "s/Threads REQUIRED/Threads/g" tmp/${source_name}/cmake/Includes/CMakeLists.txt
cmake -B tmp/${source_name}/build -S tmp/${source_name} \
    -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT} \
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} \
    -DCMAKE_BUILD_TYPE=${cmake_build_type} \
    -DAUTOBAHN_BUILD_EXAMPLES:BOOL=OFF \
    -DCMAKE_PREFIX_PATH=${GDK_BUILD_ROOT}
cmake --build tmp/${source_name}/build --parallel $NUM_JOBS
cmake --install tmp/${source_name}/build


# building ms-gsl
name="ms-gsl"
source_url="https://github.com/microsoft/GSL/archive/a3534567187d2edc428efd3f13466ff75fe5805c.tar.gz"
source_name="GSL-a3534567187d2edc428efd3f13466ff75fe5805c"
source_filename="GSL-a3534567187d2edc428efd3f13466ff75fe5805c.tar.gz"
source_hash="c0379cff645543d5076216bc5b22a3426de57796fc043527a24a6e494628d8a6"
prepare_sources ${source_url} ${source_filename} ${source_hash}
cmake -B tmp/${source_name}/build -S tmp/${source_name} \
    -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT} \
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} \
    -DCMAKE_BUILD_TYPE=${cmake_build_type} \
    -DGSL_STANDALONE_PROJECT:BOOL=OFF \
    -DGSL_TEST:BOOL=OFF \
    -DGSL_INSTALL:BOOL=ON
cmake --build tmp/${source_name}/build --parallel $NUM_JOBS
cmake --install tmp/${source_name}/build


# build sqlite3
name="sqlite3"
source_url="https://www.sqlite.org/2022/sqlite-autoconf-3390000.tar.gz"
source_name="sqlite-autoconf-3390000"
source_filename="sqlite-autoconf-3390000.tar.gz"
source_hash="e90bcaef6dd5813fcdee4e867f6b65f3c9bfd0aec0f1017f9f3bbce1e4ed09e2"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export SQLITE_SRCDIR=`pwd`/tmp/${source_name}
build ${name} ${SQLITE_SRCDIR}


# build bc-ur
name="bcur"
source_url="https://github.com/BlockchainCommons/bc-ur/archive/refs/tags/0.3.0.tar.gz"
source_name="bc-ur-0.3.0"
source_filename="bc-ur-0.3.0.tar.gz"
source_hash="2b9455766ce84ae9f7013c9a72d749034dddefb3f515145d585c732f17e7fa94"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export BCUR_SRCDIR=`pwd`/tmp/${source_name}
build ${name} ${BCUR_SRCDIR}

# build tinyCBOR
name="tinycbor"
source_url="https://github.com/lightyear15/tinycbor/archive/refs/tags/v0.6.0-memfile-rc1.tar.gz"
source_name="tinycbor-0.6.0-memfile-rc1"
source_filename="tinycbor-0.6.0-memfile-rc1.tar.gz"
source_hash="92a5c9c3622b823a54ba887889ffa90dea15493383f21a42fee02c652fa6e8af"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export BCUR_SRCDIR=`pwd`/tmp/${source_name}
build ${name} ${BCUR_SRCDIR}

# build ur-c
name="ur-c"
source_url="https://github.com/Blockstream/ur-c/archive/refs/tags/v0.3.0-rc3.tar.gz"
source_name="ur-c-0.3.0-rc3"
source_filename="ur-c-0.3.0-rc3.tar.gz"
source_hash="0560fb7cd5e93e0de1c9a1831a5b7081ea9a34c12acd0c32118c5bb4c50683d4"
prepare_sources ${source_url} ${source_filename} ${source_hash}
cmake -B tmp/${source_name}/build -S tmp/${source_name} \
    -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT} \
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} \
    -DCMAKE_BUILD_TYPE=${cmake_build_type} \
    -DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=ON \
    -DFETCH_DEPS:BOOL=OFF \
    -DENABLE_TESTS:BOOL=OFF \
    -DCMAKE_PREFIX_PATH="${GDK_BUILD_ROOT}" \
    -DBUILD_SHARED_LIBS:BOOL=OFF
cmake --build tmp/${source_name}/build --parallel $NUM_JOBS
cmake --install tmp/${source_name}/build

rm -rf tmp
