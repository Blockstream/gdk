include (${CMAKE_CURRENT_LIST_DIR}/common.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/android-helpers.cmake)


########
set(ANDROID_ABI "x86_64")
set(ANDROID_PLATFORM "android-21")
initialize_android_environment()
set(_rustTriple "x86_64-linux-android")
