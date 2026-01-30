#! /usr/bin/env bash
set -e

cd "${PRJ_SUBDIR}"

cmake -B ./build -S . \
    -DCMAKE_INSTALL_PREFIX:PATH=${GDK_BUILD_ROOT} \
    -DCMAKE_TOOLCHAIN_FILE=${CMAKE_TOOLCHAIN_FILE} \
    -DCMAKE_BUILD_TYPE=${cmake_build_type} \
    -DCMAKE_POSITION_INDEPENDENT_CODE:BOOL=ON \
    -DCMAKE_PREFIX_PATH="${GDK_BUILD_ROOT}" \
    -DBUILD_SHARED_LIBS:BOOL=OFF
cmake --build ./build --parallel $NUM_JOBS
cmake --install ./build
