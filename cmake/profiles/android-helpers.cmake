macro(initialize_android_environment)
    if(NOT ANDROID_ABI OR NOT ANDROID_PLATFORM)
        message(FATAL_ERROR "please, when including this file, be sure you have previously declared $ANDROID_ABI and $ANDROID_PLATFORM")
    endif()

# unfortunately we can't apply what's described in
#https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html#cross-compiling-for-android-with-the-ndk
# as our cmake is lagging behind and it thus expects an android ndk file layout that no longer applies to latest ANDROID_NDKs
    set(ANDROID_NDK $ENV{ANDROID_NDK})
    set(ANDROID_LD "lld")
    set(ANDROID_STL "c++_static")
    if(CMAKE_VERSION VERSION_LESS 3.19)
        set(ANDROID_USE_LEGACY_TOOLCHAIN_FILE TRUE)
    else()
        set(ANDROID_USE_LEGACY_TOOLCHAIN_FILE FALSE)
    endif()
    include(${ANDROID_NDK}/build/cmake/android.toolchain.cmake)
    # allow cmake to search outside of NDK sysroot
    # https://gitlab.kitware.com/cmake/cmake/-/issues/22183
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
    set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)

    # it's weird but it's necessary... can probably be removed when ANDROID_USE_LEGACY_TOOLCHAIN_FILE == False
    if(CMAKE_BUILD_TYPE STREQUAL Release)
        string(REPLACE "-g" "" CMAKE_C_FLAGS ${CMAKE_C_FLAGS})
        string(REPLACE "-g" "" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
        string(REPLACE "-g" "" CMAKE_ASM_FLAGS ${CMAKE_ASM_FLAGS})
    endif()
    # ... another weird thing of the android.toolchain.cmake file... -O3 should be there but it isn't
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
endmacro()
