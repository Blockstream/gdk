if (MINGW OR APPLE)
    message("windows/macOS environment: skipping java bindings")
    return()
endif()

if(ENV{JAVA_HOME})
    message("using java in $ENV{JAVA_HOME}")
    set(JAVA_HOME $ENV{JAVA_HOME})
endif()

find_program(SED REQUIRED NAMES sed gsed)
find_package(SWIG) 
find_package(Java COMPONENTS Development)

###  WARNING!!: workaround to fix issue when in Android
## cmake 3.24 fixes this
if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    set(JAVA_AWT_INCLUDE_PATH "not-needed")
    set(JAVA_INCLUDE_PATH2 "not-needed")
endif()
find_package(JNI)

if(NOT SWIG_FOUND OR NOT Java_FOUND OR NOT JNI_FOUND)
    message("skipping swig java binding")
    return()
endif()

include(UseSWIG)

set(_swig_package_option -package com.blockstream.libgreenaddress -DGDK_API)
set_source_files_properties(swig_gasdk.i PROPERTIES
    COMPILE_OPTIONS "${_swig_package_option}"
    USE_SWIG_DEPENDENCIES TRUE
    INCLUDE_DIRECTORIES "${CMAKE_SOURCE_DIR}/include"
)
swig_add_library(greenaddress-java
    TYPE SHARED
    LANGUAGE java
    NO_PROXY
    SOURCES swig_gasdk.i
)
set_target_properties(greenaddress-java PROPERTIES
    OUTPUT_NAME greenaddress
)
target_include_directories(greenaddress-java
    PRIVATE
        ${JNI_INCLUDE_DIRS}
)
target_link_options(greenaddress-java PRIVATE ${GDK_LINK_OPTIONS})

swig_link_libraries(greenaddress-java greenaddress-static)
set(_gdkLinkOptions ${GDK_LINK_OPTIONS})
if(APPLE)
    list(APPEND _gdkLinkOptions "-Wl,-force_load" "SHELL:${_wallycoreLib}")
else()
    list(APPEND _gdkLinkOptions "LINKER:SHELL:--whole-archive" "SHELL:${_wallycoreLib}" "LINKER:SHELL:--no-whole-archive")
endif()
target_link_options(greenaddress-java PRIVATE "${_gdkLinkOptions}")

add_custom_command(TARGET greenaddress-java
    POST_BUILD
    COMMAND rm -f GDK.java
    COMMAND cp GDKJNI.java GDK.java
    COMMAND ${SED} -i 's/GDKJNI/GDK/g' GDK.java
    COMMAND ${SED} -i 's/^}$$//g' GDK.java
    COMMAND grep "public final static" GDKConstants.java >> GDK.java
    COMMAND cat ${CMAKE_CURRENT_SOURCE_DIR}/jni_extra.java_in >> GDK.java
    COMMAND echo "}" >> GDK.java
)

get_library_install_dir(_libInstallDir)
find_program(OBJCOPY NAMES llvm-objcopy ${TOOLCHAIN_PREFIX}-objcopy objcopy HINTS ${ANDROID_TOOLCHAIN_ROOT})
if(OBJCOPY)
    add_custom_command(OUTPUT libgreenaddress.syms
        COMMAND ${OBJCOPY} --only-keep-debug $<TARGET_FILE:greenaddress-java> libgreenaddress.syms
        DEPENDS greenaddress-java
        BYPRODUCTS libgreenaddress.syms
        WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
    )
    add_custom_target(greenaddress-syms ALL
        DEPENDS libgreenaddress.syms
    )
    install(FILES ${CMAKE_BINARY_DIR}/libgreenaddress.syms
        DESTINATION ${_libInstallDir}
        COMPONENT gdk-java
    )
endif()

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/GDK.java
    DESTINATION ${CMAKE_INSTALL_DATADIR}/java/com/blockstream/libgreenaddress
    COMPONENT gdk-java
    EXCLUDE_FROM_ALL
)
join_path(_wallycore_java_dir ${wallycore_PREFIX} "share" "java" "com" "blockstream" "libwally")
find_file(_wallycore_java Wally.java PATHS ${_wallycore_java_dir})
install(
    FILES ${_wallycore_java}
    DESTINATION ${CMAKE_INSTALL_DATADIR}/java/com/blockstream/libwally
    COMPONENT gdk-java
    EXCLUDE_FROM_ALL
)
install(
    TARGETS greenaddress-java
    DESTINATION ${_libInstallDir}
    COMPONENT gdk-java
    EXCLUDE_FROM_ALL
)
