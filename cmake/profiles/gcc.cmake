include (${CMAKE_CURRENT_LIST_DIR}/common.cmake)

set(CMAKE_C_COMPILER gcc)
set(CMAKE_CXX_COMPILER g++)

list(APPEND GDK_LINK_OPTIONS
        "-static-libstdc++"
)
