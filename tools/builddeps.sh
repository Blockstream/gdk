#!/usr/bin/env bash
set -e

if [ -z "${NUM_JOBS}" ]; then
    if [ -f /proc/cpuinfo ]; then
        NUM_JOBS=${NUM_JOBS:-$(cat /proc/cpuinfo | grep ^processor | wc -l)}
    fi
    NUM_JOBS=${NUM_JOBS:-4}
fi
export NUM_JOBS

have_cmd()
{
    command -v "$1" >/dev/null 2>&1
}

function set_cross_build_env() {
    bld_root="$PWD/build-clang-$1-$2"
    export HOST_ARCH=$2
    case $2 in
        armeabi-v7a)
            export SDK_ARCH=arm
            export SDK_CPU=armv7
            export SDK_CFLAGS="-march=armv7-a -mfloat-abi=softfp -mfpu=neon -mthumb"
            ;;
        arm64-v8a)
            export SDK_ARCH=aarch64
            export SDK_CPU=arm64-v8a
            export SDK_CFLAGS="-march=armv8-a -flax-vector-conversions"
            ;;
        iphone)
            export SDK_ARCH=aarch64
            export SDK_CPU=arm64
            ;;
        iphonesim)
            export SDK_ARCH=x86_64
            export SDK_CPU=x86_64
            ;;
        x86_64)
            export SDK_ARCH=$HOST_ARCH
            export SDK_CPU=$HOST_ARCH
            ;;
        *)
            export SDK_ARCH=$2
            export SDK_CPU=i686
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

BUILD=""
BUILDTYPE="release"
NDK_ARCH=""
COMPILER_VERSION=""
export GDK_BUILD_ROOT=""
export PATH_BASE=$PATH


export NDK_TOOLSDIR="$ANDROID_NDK/toolchains/llvm/prebuilt/linux-x86_64"
export GDK_SOURCE_ROOT=$(pwd)

while true; do
    case "$1" in
        -b | --buildtype ) BUILDTYPE=$2; shift 2 ;;
        --clang | --gcc | --mingw-w64 ) BUILD="$1"; shift ;;
        --iphone | --iphonesim ) BUILD="$1"; shift ;;
        --ndk ) BUILD="$1"; NDK_ARCH="$2"; shift 2 ;;
        --compiler-version) COMPILER_VERSION="-$2"; shift 2 ;;
        --prefix ) GDK_BUILD_ROOT="$2"; shift 2 ;;
        -- ) shift; break ;;
        *) break ;;
    esac
done

if [ -z ${GDK_BUILD_ROOT} ]; then
    echo "please specify a destination folder with --prefix"
    exit 1
fi

C_COMPILER=""
CXX_COMPILER=""
if [ ${BUILD} == "--gcc" ]; then
    C_COMPILER="gcc"
    CXX_COMPILER="g++"
elif [ ${BUILD} == "--clang" ]; then
    C_COMPILER="clang"
    CXX_COMPILER="clang++"
    source tools/macos_env.sh
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
    C_COMPILER=${XCODE_DEFAULT_PATH}/clang
    CXX_COMPILER=${XCODE_DEFAULT_PATH}/clang++
elif [ ${BUILD} == "--iphonesim" ]; then
    C_COMPILER=${XCODE_DEFAULT_PATH}/clang
    CXX_COMPILER=${XCODE_DEFAULT_PATH}/clang++
elif [ ${BUILD} == "--mingw-w64" ]; then
    BUILD="--windows"
    C_COMPILER=gcc-posix
    CXX_COMPILER=g++-posix
    CMAKE_COMPILER_PREFIX=x86_64-w64-mingw32-
else
    echo "BUILD \"${BUILD}\" not recognized, exiting"
    exit 0
fi

if [ ${BUILDTYPE} == "debug" ]; then
    export CFLAGS="-ggdb3 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
    export CXXFLAGS="-ggdb3 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
    export CPPFLAGS="-ggdb3 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
    export BUILDTYPE=${BUILDTYPE}
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
    if [ -f ${source_filename} ]; then
        echo "${source_hash}  ${source_filename}" | shasum -a 256 -c || rm ${source_filename}
    fi
    if [ ! -f ${source_filename} ]; then
        echo "downloading from ${source_url} ..."
        curl -sL -o ${source_filename} ${source_url}
        echo "${source_hash}  ${source_filename}" | shasum -a 256 -c
        rm_downloaded="yes"
    fi
    tmp_folder="tmp"
    tar -zxf ${source_filename} -C ${tmp_folder}
    if [ -n "${rm_downloaded}" -a -z "${GDK_KEEP_DOWNLOADS}" ]; then
        rm ${source_filename}
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


# building wally-core
name="libwally-core"
source_url="https://github.com/ElementsProject/libwally-core/tarball/33b0739ae39a5d3a82f7f688bb3fe319de8bc269/ElementsProject-libwally-core-33b0739.tar.gz"
source_name="ElementsProject-libwally-core-33b0739"
source_filename="${source_name}.tar.gz"
source_hash="cc2378192544db059bd73118d67c403184ce054ca5ba5ce4266565575ef68065"
secpurl="https://github.com/ElementsProject/secp256k1-zkp.git"
# Update this line to the secp commit used in wally
secpcommit="71a206fa5bbcbba5792fc6f9eb7e07c69555f2df"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export WALLYCORE_SRCDIR=`pwd`/tmp/${source_name}
export WALLYCORE_NAME=${source_name}
export SECP_URL=${secpurl}
export SECP_COMMIT=${secpcommit}
build ${name} ${WALLYCORE_SRCDIR}
# cleaning up wally
find ${GDK_BUILD_ROOT}/libwally-core/ -name "*.c" -type f -delete
find ${GDK_BUILD_ROOT}/libwally-core/ -name "*.o" -type f -delete


# building  zlib
name="zlib"
source_url="https://github.com/madler/zlib/archive/v1.2.12.tar.gz"
source_name="zlib-1.2.12"
source_filename="${source_name}.tar.gz"
source_hash="d8688496ea40fb61787500e863cc63c9afcbc524468cedeb478068924eb54932"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export ZLIB_SRCDIR=`pwd`/tmp/${source_name}
build ${name} ${ZLIB_SRCDIR}


# building libevent
name="libevent"
source_url="https://github.com/libevent/libevent/archive/release-2.1.11-stable.tar.gz"
source_name="libevent-release-2.1.11-stable"
source_filename="${source_name}.tar.gz"
source_hash="229393ab2bf0dc94694f21836846b424f3532585bac3468738b7bf752c03901e"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export LIBEVENT_SRCDIR=`pwd`/tmp/${source_name}
build ${name} ${LIBEVENT_SRCDIR}


# building openssl
name="openssl"
source_url="https://github.com/openssl/openssl/archive/OpenSSL_1_1_1n.tar.gz"
source_name="openssl-OpenSSL_1_1_1n"
source_filename="${source_name}.tar.gz"
source_hash="6b2d2440ced8c802aaa61475919f0870ec556694c466ebea460e35ea2b14839e"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export OPENSSL_SRCDIR=`pwd`/tmp/${source_name}
build ${name} ${OPENSSL_SRCDIR}


# building boost
name="boost"
source_url="https://boostorg.jfrog.io/artifactory/main/release/1.76.0/source/boost_1_76_0.tar.gz"
source_name="boost_1_76_0"
source_filename="boost-7bd7ddceec1a1dfdcbdb3e609b60d01739c38390a5f956385a12f3122049f0ca.tar.gz"
source_hash="7bd7ddceec1a1dfdcbdb3e609b60d01739c38390a5f956385a12f3122049f0ca"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export BOOST_SRCDIR=`pwd`/tmp/${source_name}
export PRJ_SUBDIR=${BOOST_SRCDIR}
${GDK_SOURCE_ROOT}/tools/build${name}.sh $C_COMPILER $BUILD ${CXXFLAGS}


# building tor
name="tor"
source_url="https://github.com/torproject/tor/archive/tor-0.4.2.7.tar.gz"
source_name="tor-tor-0.4.2.7"
source_filename="${source_name}.tar.gz"
source_hash="526e61ebc5a8093fd0eadc2ebe9d61a413b183043d99bdef7ab95f5086d6601a"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export TOR_SRCDIR=`pwd`/tmp/${source_name}
build ${name} ${source_name} "tmp"
# cleaning up tor's mess
            ### this following, although very powerful and useful in this case, seems not to be working with OS' ``find``
# find ${GDK_BUILD_ROOT}/tor/ -mindepth 1 -maxdepth 1 ! -regex ".*\/tor\/src*" -exec rm -rf {} +
find ${GDK_BUILD_ROOT}/tor/src/ -name "*.c" -type f -delete
find ${GDK_BUILD_ROOT}/tor/src/ -name "*.o" -type f  -delete


# building nlohmann-json
name="nlohmann_json"
source_url="https://github.com/nlohmann/json/archive/refs/tags/v3.10.5.tar.gz"
source_name="json-3.10.5"
source_filename="json-3.10.5.tar.gz"
source_hash="5daca6ca216495edf89d167f808d1d03c4a4d929cef7da5e10f135ae1540c7e4"
prepare_sources ${source_url} ${source_filename} ${source_hash}
# cmake -S tmp/${source_name} -B tmp/${source_name}/build -DCMAKE_CXX_COMPILER=${CMAKE_COMPILER_PREFIX}${CXX_COMPILER} -DCMAKE_CXX_COMPILER_WORKS:BOOL=TRUE -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT}/${name} -DJSON_BuildTests:BOOL=OFF
# cmake --build tmp/${source_name}/build
# cmake --install tmp/${source_name}/build
##### to accommodate ubuntu18.04 very old cmake version
mkdir -p tmp/${source_name}/build
cd tmp/${source_name}/build
cmake .. -DCMAKE_CXX_COMPILER=${CMAKE_COMPILER_PREFIX}${CXX_COMPILER} -DCMAKE_CXX_COMPILER_WORKS:BOOL=TRUE -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT}/${name} -DJSON_BuildTests:BOOL=OFF
make
make install
cd -


# building websocketpp
name="websocketpp"
source_url="https://github.com/blockstream/websocketpp/archive/1026e877449aeee27e0bb51746a96ab42d133652.tar.gz"
source_name="websocketpp-1026e877449aeee27e0bb51746a96ab42d133652"
source_filename="websocketpp-1026e877449aeee27e0bb51746a96ab42d133652.tar.gz"
source_hash="82644fce179590ec73daf3a42383b26378716ba61bbde7ef460816170fed5aeb"
prepare_sources ${source_url} ${source_filename} ${source_hash}
# cmake -S tmp/${source_name} -B tmp/${source_name}/build -DCMAKE_C_COMPILER=${CMAKE_COMPILER_PREFIX}${C_COMPILER} -DCMAKE_C_COMPILER_WORKS:BOOL=TRUE -DCMAKE_CXX_COMPILER=${CMAKE_COMPILER_PREFIX}${CXX_COMPILER} -DCMAKE_CXX_COMPILER_WORKS:BOOL=TRUE -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT}/${name}
# cmake --build tmp/${source_name}/build
# cmake --install tmp/${source_name}/build
##### to accommodate ubuntu18.04 very old cmake version
mkdir -p tmp/${source_name}/build
cd tmp/${source_name}/build
cmake .. -DCMAKE_C_COMPILER=${CMAKE_COMPILER_PREFIX}${C_COMPILER} -DCMAKE_C_COMPILER_WORKS:BOOL=TRUE -DCMAKE_CXX_COMPILER=${CMAKE_COMPILER_PREFIX}${CXX_COMPILER} -DCMAKE_CXX_COMPILER_WORKS:BOOL=TRUE -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT}/${name}
make
make install
cd -


# building msgpack
name="msgpack"
source_url="https://github.com/msgpack/msgpack-c/releases/download/cpp-4.1.1/msgpack-cxx-4.1.1.tar.gz"
source_name="msgpack-cxx-4.1.1"
source_filename="msgpack-4.1.1.tar.gz"
source_hash="8115c5edcf20bc1408c798a6bdaec16c1e52b1c34859d4982a0fb03300438f0b"
prepare_sources ${source_url} ${source_filename} ${source_hash}
# cmake -S tmp/${source_name} -B tmp/${source_name}/build -DCMAKE_CXX_COMPILER=${CMAKE_COMPILER_PREFIX}${CXX_COMPILER} -DCMAKE_CXX_COMPILER_WORKS:BOOL=TRUE -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT}/${name} -DBOOST_ROOT:PATH=${GDK_BUILD_ROOT}/boost/build -DMSGPACK_CXX11:BOOL=ON
# cmake --build tmp/${source_name}/build
# cmake --install tmp/${source_name}/build
##### to accommodate ubuntu18.04 very old cmake version
mkdir -p tmp/${source_name}/build
cd tmp/${source_name}/build
cmake .. -DCMAKE_CXX_COMPILER=${CMAKE_COMPILER_PREFIX}${CXX_COMPILER} -DCMAKE_CXX_COMPILER_WORKS:BOOL=TRUE -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT}/${name} -DBOOST_ROOT:PATH=${GDK_BUILD_ROOT}/boost/build -DMSGPACK_CXX11:BOOL=ON
make
make install
cd -


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
# cmake -S tmp/${source_name} -B tmp/${source_name}/build -DCMAKE_C_COMPILER=${CMAKE_COMPILER_PREFIX}${C_COMPILER} -DCMAKE_C_COMPILER_WORKS:BOOL=TRUE -DCMAKE_CXX_COMPILER=${CMAKE_COMPILER_PREFIX}${CXX_COMPILER} -DCMAKE_CXX_COMPILER_WORKS:BOOL=TRUE -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT}/${name} -DBOOST_ROOT:PATH=${GDK_BUILD_ROOT}/boost/build -DOPENSSL_ROOT_DIR:PATH=${GDK_BUILD_ROOT}/openssl/build -DAUTOBAHN_BUILD_EXAMPLES:BOOL=OFF -DCMAKE_PREFIX_PATH="${GDK_BUILD_ROOT}/websocketpp;${GDK_BUILD_ROOT}/msgpack"
# cmake --build tmp/${source_name}/build
# cmake --install tmp/${source_name}/build
##### to accommodate ubuntu18.04 very old cmake version
mkdir -p tmp/${source_name}/build
cd tmp/${source_name}/build
cmake .. -DCMAKE_C_COMPILER=${CMAKE_COMPILER_PREFIX}${C_COMPILER} -DCMAKE_C_COMPILER_WORKS:BOOL=TRUE -DCMAKE_CXX_COMPILER=${CMAKE_COMPILER_PREFIX}${CXX_COMPILER} -DCMAKE_CXX_COMPILER_WORKS:BOOL=TRUE -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT}/${name} -DBOOST_ROOT:PATH=${GDK_BUILD_ROOT}/boost/build -DOPENSSL_ROOT_DIR:PATH=${GDK_BUILD_ROOT}/openssl/build -DAUTOBAHN_BUILD_EXAMPLES:BOOL=OFF -DCMAKE_PREFIX_PATH="${GDK_BUILD_ROOT}/websocketpp;${GDK_BUILD_ROOT}/msgpack"
make
make install
cd -


# building ms-gsl
name="ms-gsl"
source_url="https://github.com/microsoft/GSL/archive/a3534567187d2edc428efd3f13466ff75fe5805c.tar.gz"
source_name="GSL-a3534567187d2edc428efd3f13466ff75fe5805c"
source_filename="GSL-a3534567187d2edc428efd3f13466ff75fe5805c.tar.gz"
source_hash="c0379cff645543d5076216bc5b22a3426de57796fc043527a24a6e494628d8a6"
prepare_sources ${source_url} ${source_filename} ${source_hash}
# cmake -S tmp/${source_name} -B tmp/${source_name}/build -DCMAKE_CXX_COMPILER=${CMAKE_COMPILER_PREFIX}${CXX_COMPILER} -DCMAKE_CXX_COMPILER_WORKS:BOOL=TRUE -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT}/${name} -DGSL_STANDALONE_PROJECT:BOOL=OFF -DGSL_TEST:BOOL=OFF -DGSL_INSTALL:BOOL=ON
# cmake --build tmp/${source_name}/build
# cmake --install tmp/${source_name}/build
##### to accommodate ubuntu18.04 very old cmake version
mkdir -p tmp/${source_name}/build
cd tmp/${source_name}/build
cmake .. -DCMAKE_CXX_COMPILER=${CMAKE_COMPILER_PREFIX}${CXX_COMPILER} -DCMAKE_CXX_COMPILER_WORKS:BOOL=TRUE -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT}/${name} -DGSL_STANDALONE_PROJECT:BOOL=OFF -DGSL_TEST:BOOL=OFF -DGSL_INSTALL:BOOL=ON
make
make install
cd -


rm -rf tmp
