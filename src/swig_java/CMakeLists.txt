if (MINGW OR APPLE)
    message("windows/macOS environment: skipping java bindings")
    return()
endif()

if(DEFINED ENV{JAVA_HOME})
    message("using java in $ENV{JAVA_HOME}")
    set(JAVA_HOME $ENV{JAVA_HOME})
else()
    message(WARNING "JAVA_HOME not set, skipping java bindings")
    return()
endif()

find_program(SED REQUIRED NAMES sed gsed)
find_package(SWIG)
if(NOT SWIG_FOUND)
    message("swig not found: skipping swig java binding")
    return()
endif()
find_package(Java COMPONENTS Development)

###  WARNING!!: workaround to fix issue when in Android
## cmake 3.24 fixes this
if(CMAKE_SYSTEM_NAME STREQUAL "Android")
    set(JAVA_AWT_INCLUDE_PATH "not-needed")
    set(JAVA_INCLUDE_PATH2 "not-needed")
endif()
find_package(JNI)
if(NOT Java_FOUND OR NOT JNI_FOUND)
    message("java not found: skipping swig java binding")
    return()
endif()

include(UseSWIG)

set(_swig_package_option -package com.blockstream.libgreenaddress -DGDK_BUILD)
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

swig_link_libraries(greenaddress-java PUBLIC greenaddress)

add_custom_command(TARGET greenaddress-java
    POST_BUILD
    COMMAND ${SED} -i 's/^}$$//g' GDKJNI.java
    COMMAND grep "public final static" GDKConstants.java >> GDKJNI.java
    COMMAND cat ${CMAKE_CURRENT_SOURCE_DIR}/jni_extra.java_in >> GDKJNI.java
    COMMAND echo "}" >> GDKJNI.java
)

get_library_install_dir(_libInstallDir)
add_custom_command(
    OUTPUT libgreenaddress.syms
    COMMAND ${CMAKE_OBJCOPY} --only-keep-debug $<TARGET_FILE:greenaddress-java> libgreenaddress.syms
    DEPENDS greenaddress-java
    BYPRODUCTS libgreenaddress.syms
    WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
)
add_custom_target(greenaddress-syms ALL DEPENDS libgreenaddress.syms)
install(
    FILES ${CMAKE_BINARY_DIR}/libgreenaddress.syms
    DESTINATION ${_libInstallDir}
    COMPONENT gdk-java
    EXCLUDE_FROM_ALL
)

install(
    FILES ${CMAKE_CURRENT_BINARY_DIR}/GDKJNI.java
    DESTINATION ${CMAKE_INSTALL_DATADIR}/java/com/blockstream/libgreenaddress
    COMPONENT gdk-java
    EXCLUDE_FROM_ALL
)
find_file(_wallycore_java Wally.java PATHS ${wallycore_PREFIX}/share/java/com/blockstream/libwally REQUIRED)
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
