include (${CMAKE_CURRENT_LIST_DIR}/common.cmake)
include(${CMAKE_CURRENT_LIST_DIR}/ios-helpers.cmake)


########
init_apple_environment()

set(CMAKE_OSX_DEPLOYMENT_TARGET 10.13 CACHE INTERNAL "")

