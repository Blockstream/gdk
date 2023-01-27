include (${CMAKE_CURRENT_LIST_DIR}/common.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/android-helpers.cmake)


########
set(ANDROID_ABI "armeabi-v7a")
set(ANDROID_PLATFORM "android-19")
initialize_android_environment()
set(_rustTriple "armv7-linux-androideabi")
