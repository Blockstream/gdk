#!/usr/bin/env bash

set -e

have_cmd()
{
    command -v "$1" > /dev/null 2>&1
}

# called with BUILD and any supplemental arguments
function build_dependencies() {
    LINKS_DIR="${bld_root}/external_deps"
    if [ -z "${EXTERNAL_DEPS_DIR}" ]; then
        EXTERNAL_DEPS_DIR="${LINKS_DIR}_build"
        echo "no external-deps-dir declared, using ${EXTERNAL_DEPS_DIR}"
    fi
    if [ ! -d ${EXTERNAL_DEPS_DIR} ]; then
        echo "external-deps-dir ${EXTERNAL_DEPS_DIR} does not exist, creating it"
        mkdir -p ${EXTERNAL_DEPS_DIR}
    fi
    if [ ! -d ${bld_root} ]; then
        mkdir -p ${bld_root}
    fi
    rm -f ${LINKS_DIR}
    ln -fs ${EXTERNAL_DEPS_DIR} ${LINKS_DIR}
    if [ -f "${EXTERNAL_DEPS_DIR}/boost/build/lib/libboost_thread.a" ]; then
        echo "using external-deps-dir dependencies from ${EXTERNAL_DEPS_DIR}"
    else
        echo "building external dependencies in ${EXTERNAL_DEPS_DIR}"
        ./tools/builddeps.sh --parallel $parallel --buildtype ${BUILDTYPE} --prefix ${EXTERNAL_DEPS_DIR} $*
    fi
}

EXTERNAL_DEPS_DIR=""
BUILD=""
LIBTYPE="shared"
BUILDTYPE="release"
GETOPT='getopt'
install_prefix="/"
install=false
enable_tests=FALSE # cmake bool format
python_version=3
enable_python=false
no_deps_rebuild=false
bcur=TRUE
parallel=$(cat /proc/cpuinfo | grep ^processor | wc -l)
devmode=FALSE # cmake bool
verbose=false


if [ "$(uname)" = "Darwin" ]; then
    GETOPT='/usr/local/opt/gnu-getopt/bin/getopt'
elif [ "$(uname)" = "FreeBSD" ]; then
    GETOPT='/usr/local/bin/getopt'
fi

if [ -f "/.dockerenv" ] && [ -f "/root/.cargo/env" ]; then
    source /root/.cargo/env
fi

TEMPOPT=`"$GETOPT" -n "build.sh" -o b:,v -l enable-tests,clang,gcc,devmode,mingw-w64,no-deps-rebuild,disable-bcur,install:,ndk:,iphone:,iphonesim:,buildtype:,python-version:,parallel:,external-deps-dir: -- "$@"`
eval set -- "$TEMPOPT"
while true; do
    case "$1" in
        -b | --buildtype ) BUILDTYPE=$2; shift 2 ;;
        -v ) verbose=true; shift 2 ;;
        --install ) install=true; install_prefix="$2"; shift 2 ;;
        --enable-tests ) enable_tests=TRUE; shift ;;
        --disable-bcur ) bcur=FALSE; shift ;;
        --clang | --gcc | --mingw-w64 ) BUILD="$1"; shift ;;
        --no-deps-rebuild ) no_deps_rebuild=true; shift ;;
        --devmode ) devmode=TRUE; shift ;;
        --iphone | --iphonesim ) BUILD="$1"; LIBTYPE="$2"; shift 2 ;;
        --ndk ) BUILD="$1"; NDK_ARCH="$2"; shift 2 ;;
        --python-version) enable_python=true; python_version="$2"; shift 2 ;;
        --external-deps-dir) EXTERNAL_DEPS_DIR=$2; shift 2;;
        --parallel) parallel=$2; shift 2;;
        -- ) shift; break ;;
        *) break ;;
    esac
done


bld_root=$PWD
cmake_profile="common.cmake"
if [ "$BUILD" == "--gcc" ]; then
    bld_root="$PWD/build-gcc"
    cmake_profile="gcc.cmake"
elif [ "$BUILD" == "--clang" ]; then
    bld_root="$PWD/build-clang"
    cmake_profile="clang.cmake"
    if [ "$(uname)" == "Darwin" ]; then
        cmake_profile="macOS.cmake"
    fi
elif [ "$BUILD" == "--ndk" ]; then
    bld_root="$PWD/build-android-$NDK_ARCH"
    cmake_profile="android-$NDK_ARCH.cmake"
elif [ "$BUILD" == "--iphone" ]; then
    bld_root="$PWD/build-iphone"
    cmake_profile="iphoneos.cmake"
elif [ "$BUILD" == "--iphonesim" ]; then
    bld_root="$PWD/build-iphonesim"
    cmake_profile="iphonesimulator.cmake"
elif [ "$BUILD" == "--mingw-w64" ]; then
    bld_root="$PWD/build-windows-mingw-w64"
    cmake_profile="windows-mingw-w64.cmake"
else
    echo "$BUILD unknown build"
    exit 1
fi

cmake_build_type=${BUILDTYPE^}
if [ "$BUILDTYPE" == "debug" ]; then
    bld_root=$bld_root-debug
fi


if ! $no_deps_rebuild; then
    if [[ "${BUILD}" == "--ndk" ]]; then
        build_dependencies ${BUILD} ${NDK_ARCH}
    elif [[ "${BUILD}" == "--iphone" ]] || [[ "${BUILD}" == "--iphonesim" ]] ; then
        build_dependencies ${BUILD} ${LIBTYPE}
    else
        build_dependencies ${BUILD}
    fi
fi

cmake_options="-B $bld_root -S . \
    -DEXTERNAL-DEPS-DIR=$EXTERNAL_DEPS_DIR \
    -DCMAKE_TOOLCHAIN_FILE=cmake/profiles/$cmake_profile \
    -DCMAKE_BUILD_TYPE=$cmake_build_type \
    -DENABLE_TESTS:BOOL=$enable_tests \
    -DDEV_MODE:BOOL=$devmode \
    -DENABLE_BCUR:BOOL=$bcur"

if $enable_python ; then
    if [[ $python_version == "venv" ]]; then
        cmake_options="${cmake_options} -DPython_FIND_VIRTUALENV=ONLY"
    else
        cmake_options="${cmake_options} -DPYTHON_REQUIRED_VERSION=$python_version"
    fi
fi

if [ "$BUILD" == "--iphone" ] || [ "$BUILD" == "--iphonesim" ]; then
    cmake_options="$cmake_options -DENABLE_SWIFT:BOOL=TRUE"
fi

cmake_verbose=""
if $verbose ; then
    cmake_verbose="-v"
fi

cmake ${cmake_options}
cmake --build $bld_root --parallel $parallel $cmake_verbose

if $enable_python ; then
    cmake --build $bld_root --target python-wheel $cmake_verbose
fi

if $install ; then
    if [ "$BUILDTYPE" == "release" ]; then
        cmake --install $bld_root --prefix $install_prefix --strip
    else
        cmake --install $bld_root --prefix $install_prefix
    fi
    cmake --install $bld_root --prefix $install_prefix --component gdk-dev
fi
if [[ "${BUILD}" == "--ndk" ]]; then
    cmake --install $bld_root --prefix $install_prefix --component gdk-java
fi
