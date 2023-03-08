set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT DEFINED CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE "Release" CACHE INTERNAL "")
endif()


set(CMAKE_POSITION_INDEPENDENT_CODE TRUE)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(GDK_LINK_OPTIONS
        "LINKER:-z,now"
        "LINKER:-z,relro"
        "LINKER:-z,noexecstack"
        "LINKER:-z,undefs"
    )
    set(CMAKE_CXX_VISIBILITY_PRESET hidden)
    set(CMAKE_C_VISIBILITY_PRESET hidden)
    set(CMAKE_VISIBILITY_INLINES_HIDDEN YES)
elseif( CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_compile_options("-ggdb3" "-fno-omit-frame-pointer")
    add_compile_definitions("_GLIBCXX_ASSERTIONS" "_GLIBCXX_DEBUG" "_GLIBCXX_DEBUG_PEDANTIC")
endif()
