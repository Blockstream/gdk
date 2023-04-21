include (${CMAKE_CURRENT_LIST_DIR}/common.cmake)
include (${CMAKE_CURRENT_LIST_DIR}/ios-helpers.cmake)


########
init_apple_environment()
set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_OSX_DEPLOYMENT_TARGET 11.00 CACHE INTERNAL "")
set(CMAKE_OSX_ARCHITECTURES ${CMAKE_HOST_SYSTEM_PROCESSOR} CACHE INTERNAL "")
set(CMAKE_IOS_INSTALL_COMBINED FALSE)
set(SDK_NAME iphonesimulator)
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

if(CMAKE_HOST_SYSTEM_PROCESSOR STREQUAL "arm64")
    set(_rustTriple "aarch64-apple-ios-sim")
else()
    set(_rustTriple "x86_64-apple-ios")
endif()
