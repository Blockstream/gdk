include (${CMAKE_CURRENT_LIST_DIR}/common.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/android-helpers.cmake)


########
set(ANDROID_ABI "x86")
set(ANDROID_PLATFORM "android-19")
initialize_android_environment()
set(_rustTriple "i686-linux-android")
