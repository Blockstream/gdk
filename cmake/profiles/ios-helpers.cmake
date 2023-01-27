macro(init_apple_environment)
    set(CMAKE_IOS_INSTALL_COMBINED FALSE)
    # allow cmake to search outside of iOS sysroot
    # https://stackoverflow.com/questions/45931011/finding-boost-framework-with-cmake-for-ios
    set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY BOTH)
    set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE BOTH)
    set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE BOTH)
    unset(GDK_LINK_OPTIONS)
    list(APPEND GDK_LINK_OPTIONS
        "LINKER:-framework,Security"
    )
    set(CMAKE_EXE_LINKER_FLAGS "-stdlib=libc++")
    set(CMAKE_SHARED_LINKER_FLAGS "-stdlib=libc++")
    set(CMAKE_C_COMPILER clang)
    set(CMAKE_CXX_COMPILER clang++)
endmacro()

# macro(set_apple_target_triple)
#     if(NOT DEFINED CMAKE_OSX_DEPLOYMENT_TARGET)
#         message(FATAL_ERROR "please define CMAKE_OSX_DEPLOYMENT_TARGET")
#     endif()
#     if(NOT DEFINED CMAKE_OSX_ARCHITECTURES)
#         message(FATAL_ERROR "please define CMAKE_OSX_ARCHITECTURES")
#     endif()
#     if(NOT DEFINED SDK_NAME)
#         message(FATAL_ERROR "please define SDK_NAME")
#     endif()

#     string(REPLACE ";" "-" ARCHS_SPLIT "${CMAKE_OSX_ARCHITECTURES}")
#     set(APPLE_TARGET_TRIPLE ${ARCHS_SPLIT}-apple-${SDK_NAME}${CMAKE_OSX_DEPLOYMENT_TARGET})
#     foreach(_lang IN ITEMS C CXX ASM)
#         set(CMAKE_${_lang}_COMPILER_TARGET ${APPLE_TARGET_TRIPLE})
#     endforeach()
# endmacro()

# macro(set_cmake_osx_parameters)
#     if(NOT DEFINED SDK_NAME)
#         message(FATAL_ERROR "please define SDK_NAME")
#     endif()
#     execute_process(COMMAND xcodebuild -version -sdk ${SDK_NAME} Path
#         OUTPUT_VARIABLE CMAKE_OSX_SYSROOT
#         OUTPUT_STRIP_TRAILING_WHITESPACE
#         ERROR_VARIABLE _execError
#     )
#     if(_execError)
#         message(FATAL_ERROR "seeking CMAKE_OSX_SYSROOT failed with error ${_execError}")
#     endif()
#     execute_process(COMMAND xcrun -sdk ${CMAKE_OSX_SYSROOT} -find libtool
#         OUTPUT_VARIABLE BUILD_LIBTOOL
#         OUTPUT_STRIP_TRAILING_WHITESPACE
#         ERROR_VARIABLE _execError
#     )
#     if(_execError)
#         message(FATAL_ERROR "seeking BUILD_LIBTOOL failed with error ${_execError}")
#     endif()
#     execute_process(COMMAND xcrun -sdk ${CMAKE_OSX_SYSROOT} -find install_name_tool
#         OUTPUT_VARIABLE CMAKE_INSTALL_NAME_TOOL
#         OUTPUT_STRIP_TRAILING_WHITESPACE
#         ERROR_VARIABLE _execError
#     )
#     if(_execError)
#         message(FATAL_ERROR "seeking CMAKE_INSTALL_NAME_TOOL failed with error ${_execError}")
#     endif()
# endmacro()

# macro(find_compiler)
#     if(NOT DEFINED CMAKE_OSX_SYSROOT)
#         message(FATAL_ERROR "please either define CMAKE_OSX_SYSROOT or call ``set_cmake_osx_parameters`` macro")
#     endif()
# execute_process(COMMAND xcrun -sdk ${CMAKE_OSX_SYSROOT} -find clang
#     OUTPUT_VARIABLE CMAKE_C_COMPILER
#     ERROR_QUIET
#     OUTPUT_STRIP_TRAILING_WHITESPACE
# )
# set(CMAKE_ASM_COMPILER ${CMAKE_C_COMPILER})
# execute_process(COMMAND xcrun -sdk ${CMAKE_OSX_SYSROOT} -find clang++
#     OUTPUT_VARIABLE CMAKE_CXX_COMPILER
#     ERROR_QUIET
#     OUTPUT_STRIP_TRAILING_WHITESPACE
# )
# endmacro()

# macro(print_apple_configuration)
#     ## Print status messages to inform of the current state
#     message(STATUS "Configuring ${SDK_NAME} build for architecture(s): ${CMAKE_OSX_ARCHITECTURES}")
#     message(STATUS "Using SDK: ${CMAKE_OSX_SYSROOT}")
#     message(STATUS "Using C compiler: ${CMAKE_C_COMPILER}")
#     message(STATUS "Using CXX compiler: ${CMAKE_CXX_COMPILER}")
#     message(STATUS "Using libtool: ${BUILD_LIBTOOL}")
#     message(STATUS "Using install name tool: ${CMAKE_INSTALL_NAME_TOOL}")
#     message(STATUS "Rust triple set to : ${_rustTriple}")
# endmacro()
