include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CMakePrintHelpers)


#[[
join_path
------
this function merges a list of strings into a path.
Fundamentally, it's a rudimental replacement of the function
```
cmake_path(APPEND <path-var> [<input>...] [OUTPUT_VARIABLE <out-var>])
```
ref: https://cmake.org/cmake/help/latest/command/cmake_path.html#append
which unfortunately is not present in cmake versions older than 3.20
#]]
### NOTE: to be deprecated by cmake_path in cmake 3.20
function(join_path outvar)
    if(ARGC LESS "2")
        message(FATAL_ERROR "input arguments not provided")
    endif()
    math(EXPR _end "${ARGC} - 1")
    set(_tmp ${ARGV1})
    foreach(idx RANGE 2 ${_end})
        string(CONCAT _tmp ${_tmp} "/" ${ARGV${idx}}) 
    endforeach()
    string(REPLACE "//" "/" _stripped ${_tmp})
    set(${outvar} ${_stripped} PARENT_SCOPE)
endfunction()


function(find_tool out tool)
    join_path(_toolDir ${CMAKE_SOURCE_DIR} "tools")
    find_file(${out} ${tool} PATHS ${_toolDir} REQUIRED)
endfunction()


function(get_library_install_dir outvar)
    if(ANDROID)
        join_path(_libInstallDir ${CMAKE_INSTALL_LIBDIR} ${CMAKE_ANDROID_ARCH_ABI})
    elseif(CMAKE_SYSTEM_NAME STREQUAL iOS)
        join_path(_libInstallDir ${CMAKE_INSTALL_LIBDIR} ${SDK_NAME})
    else()
        set(_libInstallDir ${CMAKE_INSTALL_LIBDIR})
    endif()
    set(${outvar} ${_libInstallDir} PARENT_SCOPE)
endfunction()


function(get_cmake_install_dir outvar lib_install_dir)
    join_path(_cmakeInstallDir ${lib_install_dir} "gdk")
    set(${outvar} ${_cmakeInstallDir} PARENT_SCOPE)
endfunction()


macro(create_gdkrust_target)
    join_path(_gdkRustSrcDir ${CMAKE_SOURCE_DIR} "subprojects" "gdk_rust")
    join_path(_gdkRustBuildDir ${CMAKE_CURRENT_BINARY_DIR} "gdk-rust")
    set(_gdkRustLibArtifact "libgdk_rust.a")
    find_tool(_buildTool "buildgdk_rust.sh")
    add_custom_target(cargo-cmd
        COMMAND ${_buildTool} "${CMAKE_BUILD_TYPE}" "${_rustTriple}" "${ANDROID_TOOLCHAIN_ROOT}" ${CMAKE_AR} ${OPENSSL_ROOT_DIR} ${_gdkRustSrcDir} ${_gdkRustBuildDir} ${_gdkRustLibArtifact} "${CMAKE_OSX_DEPLOYMENT_TARGET}"
        VERBATIM
        BYPRODUCTS ${_gdkRustLibArtifact}
        WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}

    )
    add_library(gdk-rust STATIC IMPORTED GLOBAL)
    add_dependencies(gdk-rust cargo-cmd)
    set_target_properties(gdk-rust PROPERTIES IMPORTED_LOCATION ${_gdkRustBuildDir}/${_gdkRustLibArtifact})
    target_include_directories(gdk-rust INTERFACE ${_gdkRustSrcDir})
    target_link_libraries(gdk-rust
        INTERFACE
            $<$<PLATFORM_ID:Windows>:crypt32>
            $<$<PLATFORM_ID:Windows>:bcrypt>
            $<$<PLATFORM_ID:iOS>:objc>
            $<$<PLATFORM_ID:Windows>:ws2_32>
    )
endmacro()


macro(install_cmake_config)
    get_library_install_dir(_libInstallDir)
    get_cmake_install_dir(LIB_CMAKE_INSTALL_DIR ${_libInstallDir})
    configure_package_config_file(
        ${CMAKE_SOURCE_DIR}/cmake/exports/gdk-config.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/gdk-config.cmake"
        INSTALL_DESTINATION ${LIB_CMAKE_INSTALL_DIR}/cmake
        PATH_VARS LIB_CMAKE_INSTALL_DIR
    )
    write_basic_package_version_file(
        gdk-config-version.cmake
        VERSION ${PROJECT_VERSION}
        COMPATIBILITY SameMajorVersion
    )
    install(
        FILES
            "${CMAKE_CURRENT_BINARY_DIR}/gdk-config.cmake"
            "${CMAKE_CURRENT_BINARY_DIR}/gdk-config-version.cmake"
        COMPONENT gdk-dev
        DESTINATION
            ${LIB_CMAKE_INSTALL_DIR}/cmake
        EXCLUDE_FROM_ALL
    )
endmacro()
