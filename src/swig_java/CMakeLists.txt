if (MINGW OR APPLE)
    message("windows/macOS environment: skipping java bindings")
    return()
endif()

if(ENV{JAVA_HOME})
    message("using java in $ENV{JAVA_HOME}")
    set(JAVA_HOME $ENV{JAVA_HOME})
endif()

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

include(UseJava)
### WARNING dirty trick due to wallycore not properly installing java binding
join_path(_wallycoreSrcDir ${EXTERNAL-DEPS-DIR} "libwally-core" "src")

set(_requiredJavaVersion 1.8)
if(Java_VERSION VERSION_LESS _requiredJavaVersion)
    message(fatal "version ${Java_VERSION} of java found in ${Java_JAVA_EXECUTABLE} not matching minimum requirement of ${_requiredJavaVersion}")
endif()
find_program(SED REQUIRED NAMES sed gsed)


set(_swigDestDir ${CMAKE_CURRENT_BINARY_DIR})
join_path(_swigCFile ${_swigDestDir} "gasdk_wrap.c")
join_path(_hackyGDKInclude ${CMAKE_SOURCE_DIR} "include")

find_tool(_buildJavaSwig "swig.sh")

add_custom_command(OUTPUT ${_swigCFile}
    COMMAND ${_buildJavaSwig} ${SED} ${SWIG_EXECUTABLE} ${Java_JAVAC_EXECUTABLE} ${Java_JAR_EXECUTABLE} ${_swigCFile} ${_swigDestDir} swig_gasdk.i jni_extra.java_in ${_hackyGDKInclude} ${WALLYCORE_JAR} ${_requiredJavaVersion}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS greenaddress-objects
)
add_custom_target(swig_java-cmd
    DEPENDS ${_swigCFile}
)

add_library(swig_java OBJECT ${_swigCFile})
get_target_property(_gdkIncludes greenaddress-objects INTERFACE_INCLUDE_DIRECTORIES)
target_include_directories(swig_java PRIVATE ${_gdkIncludes} ${JNI_INCLUDE_DIRS})
target_compile_options(swig_java 
    PRIVATE 
        "-fasynchronous-unwind-tables"
        "-fexceptions"
        "-fstack-protector-strong"
        "-fno-strict-aliasing"
        $<$<AND:$<CXX_COMPILER_ID:GNU,Clang>,$<PLATFORM_ID:Linux>>:
            "-Werror"
            "-Wall"
            "-Wextra"
            "-Wpedantic"
            "-Wshadow"
            ##### should be un-commented and errors should be fixed
            # "-Wconversion"
        >
)
target_compile_definitions(swig_java PRIVATE _FORTIFY_SOURCE=2)

add_dependencies(swig_java-cmd greenaddress-objects)
add_dependencies(swig_java swig_java-cmd)

INSTALL(
    FILES
        ${_swigDestDir}/com/blockstream/libgreenaddress/GDK.java
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/java/com/blockstream/libgreenaddress
     COMPONENT
        gdk-dev
)
INSTALL(
    FILES
        ${_wallycoreSrcDir}/swig_java/src/com/blockstream/libwally/Wally.java
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/java/com/blockstream/libwally
     COMPONENT
        gdk-dev
)
