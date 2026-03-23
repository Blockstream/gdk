include (${CMAKE_CURRENT_LIST_DIR}/common.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/ios-helpers.cmake)


########
init_apple_environment()

set(CMAKE_OSX_DEPLOYMENT_TARGET 10.15 CACHE INTERNAL "")

if(${CMAKE_HOST_SYSTEM_PROCESSOR} STREQUAL "arm64")
    set(RUST_ARCH "aarch64")
else()
    set(RUST_ARCH ${CMAKE_HOST_SYSTEM_PROCESSOR})
endif()

set(CMAKE_LIBRARY_ARCHITECTURE "${RUST_ARCH}-apple-darwin")

set(_rustTriple "${RUST_ARCH}-apple-darwin")