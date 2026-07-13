include (${CMAKE_CURRENT_LIST_DIR}/common.cmake)
include (${CMAKE_CURRENT_LIST_DIR}/ios-helpers.cmake)


########
init_apple_environment()
set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_OSX_DEPLOYMENT_TARGET 13.00 CACHE INTERNAL "")

if(DEFINED ENV{GDK_MACOS_TARGET_ARCH} AND NOT "$ENV{GDK_MACOS_TARGET_ARCH}" STREQUAL "")
    set(_gdk_ios_sim_target_arch "$ENV{GDK_MACOS_TARGET_ARCH}")
else()
    set(_gdk_ios_sim_target_arch "${CMAKE_HOST_SYSTEM_PROCESSOR}")
endif()

if(NOT _gdk_ios_sim_target_arch STREQUAL "arm64" AND NOT _gdk_ios_sim_target_arch STREQUAL "x86_64")
    message(FATAL_ERROR "Unsupported GDK_MACOS_TARGET_ARCH='${_gdk_ios_sim_target_arch}'. Expected arm64 or x86_64")
endif()

set(CMAKE_OSX_ARCHITECTURES "${_gdk_ios_sim_target_arch}" CACHE INTERNAL "")
set(CMAKE_IOS_INSTALL_COMBINED FALSE)
set(SDK_NAME iphonesimulator)
set(CMAKE_C_COMPILER_TARGET ${_gdk_ios_sim_target_arch}-apple-ios${CMAKE_OSX_DEPLOYMENT_TARGET}-simulator)
set(CMAKE_CXX_COMPILER_TARGET ${_gdk_ios_sim_target_arch}-apple-ios${CMAKE_OSX_DEPLOYMENT_TARGET}-simulator)
set(CMAKE_LIBRARY_ARCHITECTURE ${_gdk_ios_sim_target_arch}-apple-ios${CMAKE_OSX_DEPLOYMENT_TARGET})
execute_process(COMMAND xcodebuild -version -sdk iphonesimulator Path
    OUTPUT_VARIABLE CMAKE_OSX_SYSROOT
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_VARIABLE _execError
    ERROR_QUIET
)
if(_execError)
    message(FATAL_ERROR "seeking CMAKE_OSX_SYSROOT for iphonesimulator failed with error ${_execError}")
endif()


# Fix for PThread library not in path
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY YES)
set(CMAKE_USE_WIN32_THREADS_INIT NO)
set(CMAKE_USE_PTHREADS_INIT YES)

if(_gdk_ios_sim_target_arch STREQUAL "arm64")
    set(_rustTriple "aarch64-apple-ios-sim")
else()
    set(_rustTriple "x86_64-apple-ios")
endif()
