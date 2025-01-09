#!/usr/bin/env bash
set -e

have_cmd()
{
    command -v "$1" >/dev/null 2>&1
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
SKIP_HASH=""
export GDK_BUILD_ROOT=""


export GDK_SOURCE_ROOT=$(pwd)
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
        --skip-hash ) SKIP_HASH="true"; shift ;;
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


source ./tools/environment_setup.sh ${BUILD} ${NDK_ARCH}

export BUILDTYPE=${BUILDTYPE}
if [ ${BUILDTYPE} == "debug" ]; then
    if [ ${BUILD} == "--mingw-w64" ]; then
        # when debugging in windows try dwarf-2 or stabs formats
        export CFLAGS="-g -gdwarf-2 -O0 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
        export CXXFLAGS="-gdwarf-2 -O0 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
        export CPPFLAGS="-g -gdwarf-2 -O0 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
    else
        export CFLAGS="-ggdb3 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
        export CXXFLAGS="-ggdb3 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
        export CPPFLAGS="-ggdb3 -fno-omit-frame-pointer -D_GLIBCXX_ASSERTIONS -D_GLIBCXX_DEBUG -D_GLIBCXX_DEBUG_PEDANTIC"
    fi
else
    export CFLAGS="$SDK_CFLAGS -O2 -DNDEBUG"
    export CXXFLAGS="$SDK_CXXFLAGS -O2 -DNDEBUG"
    export LDFLAGS="$SDK_LDFLAGS -O2 -DNDEBUG"
fi

export CFLAGS="${CFLAGS} -fPIC -DPIC"
export CXXFLAGS="${CXXFLAGS} -fPIC -DPIC"


mkdir -p ${GDK_BUILD_ROOT}

export NDK_ARCH=${NDK_ARCH}


function prepare_sources {
    source_url=$1
    source_filename=$2
    source_hash=$3
    patchfile=$4
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
    if [ -z "$SKIP_HASH" ]; then
        echo "checking ${source_filename}..."
        echo "${source_hash}  ${source_filename}" | shasum -a 256 -c
    else
        echo "WARNING: not checking download hash for ${source_filename}..."
    fi

    cd -
    tmp_folder="tmp"
    tar -xf ${downloads_folder}/${source_filename} -C ${tmp_folder}
    if [ -n "${rm_downloaded}" -a -z "${GDK_KEEP_DOWNLOADS}" ]; then
        rm ${downloads_folder}/${source_filename}
    fi
    if [ -n "${patchfile}" ]; then
        echo "patching source files with " ${patchfile}
        cd ${tmp_folder}/
        patch -p1 < ${GDK_SOURCE_ROOT}/${patchfile}
        cd -
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


# resume of build information
echo ""
echo "*********************************"
echo "Build information:"
echo "Build type: ${BUILDTYPE}"
echo "Build: ${BUILD}"
echo "Build root: ${GDK_BUILD_ROOT}"
echo "target triple ${target_triple}"
echo "host triple ${host_triple}"
echo "sysroot ${SDK_SYSROOT}"
echo "C COMPILER: ${CC}"
echo "CXX COMPILER: ${CXX}"
echo "CFLAGS: ${CFLAGS}"
echo "CXXFLAGS: ${CXXFLAGS}"
echo "LDFLAGS: ${LDFLAGS}"
echo "cmake toolchain file: ${CMAKE_TOOLCHAIN_FILE}"
echo "*********************************"
echo ""


# building wally-core
name="libwally-core"
source_url="https://github.com/ElementsProject/libwally-core/tarball/67b20a5b7fb95e11f6bed3f3d8afbaeffc163915/ElementsProject-libwally-core-67b20a5.tar.gz"
source_name="ElementsProject-libwally-core-67b20a5"
source_filename="${source_name}.tar.gz"
source_hash="5fd6e2c666c671d18e7ebe74b3c33f93b7a2b40739e24bbe1223be6b8b7a1395"
secpurl="https://github.com/ElementsProject/secp256k1-zkp.git"
# Update this line to the secp commit used in wally
secpcommit="6152622613fdf1c5af6f31f74c427c4e9ee120ce"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export WALLYCORE_SRCDIR=`pwd`/tmp/${source_name}
export WALLYCORE_NAME=${source_name}
export SECP_URL=${secpurl}
export SECP_COMMIT=${secpcommit}
build ${name} ${WALLYCORE_SRCDIR}


# building zlib
name="zlib"
source_url="https://github.com/madler/zlib/archive/v1.3.tar.gz"
source_name="zlib-1.3"
source_filename="${source_name}.tar.gz"
source_hash="b5b06d60ce49c8ba700e0ba517fa07de80b5d4628a037f4be8ad16955be7a7c0"
prepare_sources ${source_url} ${source_filename} ${source_hash}
# WARNING: https://github.com/madler/zlib/issues/856
cd tmp && patch -p1 < ${GDK_SOURCE_ROOT}/tools/zlib-1.3.patch && cd -
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
if [ ${BUILD} == "--mingw-w64" ]; then
    mv ${GDK_BUILD_ROOT}/lib/libzlibstatic.a ${GDK_BUILD_ROOT}/lib/libz.a
fi


# building libevent
name="libevent"
source_url="https://github.com/libevent/libevent/archive/release-2.1.12-stable.tar.gz"
source_name="libevent-release-2.1.12-stable"
source_filename="${source_name}.tar.gz"
source_hash="7180a979aaa7000e1264da484f712d403fcf7679b1e9212c4e3d09f5c93efc24"
prepare_sources ${source_url} ${source_filename} ${source_hash} tools/libevent-2.1.12.patch
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
# building in a subshell to avoid leaking openssl-specific exports
(build ${name} ${OPENSSL_SRCDIR})


# building boost
name="boost"
source_url="https://archives.boost.io/release/1.84.0/source/boost_1_84_0.tar.gz"
source_name="boost_1_84_0"
source_filename="boost_1_84_0.tar.gz"
source_hash="a5800f405508f5df8114558ca9855d2640a2de8f0445f051fa1c7c3383045724"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export BOOST_SRCDIR=`pwd`/tmp/${source_name}
export PRJ_SUBDIR=${BOOST_SRCDIR}
${GDK_SOURCE_ROOT}/tools/build${name}.sh $CC $BUILD ${CXXFLAGS}


# building tor
name="tor"
source_url="https://dist.torproject.org/tor-0.4.8.13.tar.gz"
source_name="tor-0.4.8.13"
source_filename="${source_name}.tar.gz"
source_hash="9baf26c387a2820b3942da572146e6eb77c2bc66862af6297cd02a074e6fba28"
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
source_url="https://github.com/microsoft/GSL/archive/refs/tags/v4.0.0.tar.gz"
source_name="GSL-4.0.0"
source_filename="GSL-4.0.0.tar.gz"
source_hash="f0e32cb10654fea91ad56bde89170d78cfbf4363ee0b01d8f097de2ba49f6ce9"
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
source_url="https://github.com/Blockstream/tinycbor/archive/refs/tags/v0.6.0-memfile-rc1.tar.gz"
source_name="tinycbor-0.6.0-memfile-rc1"
source_filename="tinycbor-0.6.0-memfile-rc1.tar.gz"
source_hash="92a5c9c3622b823a54ba887889ffa90dea15493383f21a42fee02c652fa6e8af"
prepare_sources ${source_url} ${source_filename} ${source_hash}
export BCUR_SRCDIR=`pwd`/tmp/${source_name}
build ${name} ${BCUR_SRCDIR}


# build ur-c
name="ur-c"
source_url="https://github.com/Blockstream/ur-c/archive/refs/tags/v0.5.0-rc1.tar.gz"
source_name="ur-c-0.5.0-rc1"
source_filename="ur-c-0.5.0-rc1.tar.gz"
source_hash="1f8732869c67f235610cc2eff0709a5ea565c4da3107400d6be3ebf40ac2433b "
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
