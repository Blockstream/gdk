include (${CMAKE_CURRENT_LIST_DIR}/common.cmake)

set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)

list(APPEND GDK_LINK_OPTIONS
        "-static-libstdc++"
)
if( CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options("-ggdb3" "-fno-omit-frame-pointer")
endif()

set(CMAKE_LIBRARY_ARCHITECTURE "${CMAKE_HOST_SYSTEM_PROCESSOR}-linux-gnu")
