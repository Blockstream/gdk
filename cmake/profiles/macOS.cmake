include (${CMAKE_CURRENT_LIST_DIR}/common.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/ios-helpers.cmake)


########
init_apple_environment()

set(CMAKE_OSX_DEPLOYMENT_TARGET 10.15 CACHE INTERNAL "")

if(DEFINED ENV{GDK_MACOS_TARGET_ARCH} AND NOT "$ENV{GDK_MACOS_TARGET_ARCH}" STREQUAL "")
    set(_gdk_macos_target_arch "$ENV{GDK_MACOS_TARGET_ARCH}")
else()
    set(_gdk_macos_target_arch "${CMAKE_HOST_SYSTEM_PROCESSOR}")
endif()

if(NOT _gdk_macos_target_arch STREQUAL "arm64" AND NOT _gdk_macos_target_arch STREQUAL "x86_64")
    message(FATAL_ERROR "Unsupported GDK_MACOS_TARGET_ARCH='${_gdk_macos_target_arch}'. Expected arm64 or x86_64")
endif()

set(CMAKE_OSX_ARCHITECTURES "${_gdk_macos_target_arch}" CACHE STRING "" FORCE)

if(_gdk_macos_target_arch STREQUAL "arm64")
    set(RUST_ARCH "aarch64")
else()
    set(RUST_ARCH ${_gdk_macos_target_arch})
endif()

set(CMAKE_LIBRARY_ARCHITECTURE "${RUST_ARCH}-apple-darwin")

set(_rustTriple "${RUST_ARCH}-apple-darwin")