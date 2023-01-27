include (${CMAKE_CURRENT_LIST_DIR}/common.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/android-helpers.cmake)


########
set(ANDROID_ABI "arm64-v8a")
set(ANDROID_PLATFORM "android-21")
initialize_android_environment()
set(_rustTriple "aarch64-linux-android")
