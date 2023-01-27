include (${CMAKE_CURRENT_LIST_DIR}/common.cmake)
include (${CMAKE_CURRENT_LIST_DIR}/ios-helpers.cmake)


########
init_apple_environment()
set(CMAKE_SYSTEM_NAME iOS)
set(CMAKE_OSX_DEPLOYMENT_TARGET 11.00 CACHE INTERNAL "")
set(CMAKE_OSX_ARCHITECTURES "arm64" CACHE INTERNAL "")
set(CMAKE_IOS_INSTALL_COMBINED FALSE)
set(SDK_NAME iphoneos)


# Fix for PThread library not in path
set(CMAKE_THREAD_LIBS_INIT "-lpthread")
set(CMAKE_HAVE_THREADS_LIBRARY YES)
set(CMAKE_USE_WIN32_THREADS_INIT NO)
set(CMAKE_USE_PTHREADS_INIT YES)

set(_rustTriple "aarch64-apple-ios")
