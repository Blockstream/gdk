include (${CMAKE_CURRENT_LIST_DIR}/common.cmake)

set(CMAKE_C_COMPILER clang)
set(CMAKE_CXX_COMPILER clang++)

list(APPEND GDK_LINK_OPTIONS
    "SHELL:-static-libstdc++"
)
