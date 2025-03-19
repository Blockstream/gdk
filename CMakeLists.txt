cmake_minimum_required(VERSION 3.10)
project(gdk VERSION 0.75.0 LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(cmake/includes/helpers.cmake)
include(cmake/includes/greengdk.cmake)


cmake_policy(SET CMP0074 NEW)

### project options
option(ENABLE_TESTS "enable building tests" FALSE)
option(BUILD_SHARED_LIBS "build gdk as shared library" FALSE)
option(DEV_MODE "dev mode enables a faster developing-testing loop when working with the python-wheel" FALSE)
option(ENABLE_SWIFT "enable build of swift bindings" FALSE)
OPTION(ENABLE_BCUR "enable support QR code encoding/decoding" TRUE)
set(PYTHON_REQUIRED_VERSION 3 CACHE STRING "required python version")
list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/modules)

### avoiding in-build compilation, your local gdk folder would turn into a real mess
### WARNING. please refine this once cmake_path becomes available
if (PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not allowed")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)


###### searching for dependencies
#### projects with cmake-provided FindXXX module
# boost
set(Boost_USE_STATIC_LIBS ON)
if (CMAKE_BUILD_TYPE STREQUAL Debug)
    set(Boost_USE_DEBUG_LIBS ON)
else()
    set(Boost_USE_DEBUG_LIBS OFF)
endif()
set(Boost_NO_SYSTEM_PATHS ON)
if (POLICY CMP0167)
    # Search for the BoostConfig.cmake file to configure boost
    cmake_policy(SET CMP0167 NEW)
    set(Boost_DIR ${CMAKE_PREFIX_PATH} CACHE INTERNAL "")
    list(APPEND CMAKE_MODULE_PATH ${CMAKE_PREFIX_PATH}/lib/cmake/Boost-1.87.0)
    # Set Boost_LIBRARY_DIRS which appears to no longer be defined
    set(Boost_LIBRARY_DIRS ${CMAKE_PREFIX_PATH}/lib CACHE INTERNAL "")
endif()
find_package(Boost 1.87.0 EXACT REQUIRED COMPONENTS date_time thread log chrono system)
# zlib
set(ZLIB_ROOT ${CMAKE_PREFIX_PATH})
find_package(ZLIB 1.3 EXACT REQUIRED)
# openSSL
set(OPENSSL_USE_STATIC_LIBS ON)
find_package(OpenSSL 1.1.1 EXACT REQUIRED)

#### cmake-based projects with xxx-config.cmake file
find_package(nlohmann_json REQUIRED CONFIG)
find_package(Microsoft.GSL REQUIRED CONFIG)
find_package(websocketpp REQUIRED CONFIG)
find_package(msgpack REQUIRED CONFIG)
find_package(Libevent REQUIRED CONFIG COMPONENTS core extra OPTIONAL_COMPONENTS pthreads)
# ur-c
set(URC_INCLUDE_DIRS "")
set(URC_LINK_LIBRARIES "")
if (ENABLE_BCUR)
    find_package(bcur REQUIRED MODULE)
    find_package(urc REQUIRED)
    get_target_property(URC_INCLUDE_DIRS urc::urc INTERFACE_INCLUDE_DIRECTORIES)
    string(TOUPPER ${CMAKE_BUILD_TYPE} _upcase_build_type)
    get_target_property(URC_LINK_LIBRARIES urc::urc IMPORTED_LOCATION_${_upcase_build_type})
    set_target_properties(urc::urc PROPERTIES INTERFACE_LINK_LIBRARIES "PkgConfig::TinyCBOR")
    add_compile_definitions(USE_REAL_BCUR)
endif()

#### dependencies relying on pkg-config
find_package(PkgConfig REQUIRED)
set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH ON)
# wallycore
pkg_check_modules(wallycore REQUIRED IMPORTED_TARGET wallycore)
pkg_check_modules(libsecp256k1 REQUIRED IMPORTED_TARGET libsecp256k1)
set(TINYCBOR_INCLUDE_DIRS "")
if (ENABLE_BCUR)
    pkg_check_modules(TinyCBOR REQUIRED IMPORTED_TARGET tinycbor)
    get_target_property(TINYCBOR_INCLUDE_DIRS PkgConfig::TinyCBOR INTERFACE_INCLUDE_DIRECTORIES)
    message(STATUS "TINYCBOR_INCLUDE_DIRS: ${TINYCBOR_INCLUDE_DIRS}")
endif()

#### custom packages
find_package(tor REQUIRED MODULE)
find_package(sqlite3 REQUIRED MODULE)
find_package(autobahn REQUIRED MODULE)


####################################################################
create_gdkrust_target()
add_subdirectory(src)
if (NOT BUILD_SHARED_LIBS)
    create_greengdkfull_target()
endif()

## bindings
find_package(SWIG)
add_subdirectory(src/swig_java)
find_package(Python ${PYTHON_REQUIRED_VERSION} EXACT COMPONENTS Interpreter)
add_subdirectory(src/swig_python)
add_subdirectory(src/swift)

### installation directives
install_cmake_config()

#### test testing tests
if(NOT ENABLE_TESTS)
    return()
endif()

enable_testing()
add_subdirectory(tests)
