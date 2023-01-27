cmake_minimum_required(VERSION 3.10)
project(gdk VERSION 0.0.58 LANGUAGES C CXX)

include(cmake/includes/helpers.cmake)
include(cmake/includes/greenaddress.cmake)


### project options
option(ENABLE_TESTS "enable building tests" FALSE)
option(SHARED_ONLY "build only shared library" FALSE)
option(ADD_COVERAGE "add coverage report when in debug" FALSE)
set(PYTHON_REQUIRED_VERSION 3 CACHE STRING "required python version")

### avoiding in-build compilation, your local gdk folder would turn into a real mess
### WARNING. please refine this once cmake_path becomes available
if (PROJECT_SOURCE_DIR STREQUAL PROJECT_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not allowed")
endif()

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT EXTERNAL-DEPS-DIR)
    message(FATAL_ERROR "please define variable EXTERNAL-DEPS-DIR with -D option")
endif()



###### searching for dependencies
#### projects with cmake-provided FindXXX module
# boost
join_path(BOOST_ROOT ${EXTERNAL-DEPS-DIR} "boost" "build")
set(Boost_USE_STATIC_LIBS ON)
if (CMAKE_BUILD_TYPE STREQUAL Debug)
    set(Boost_USE_DEBUG_LIBS ON)
else()
    set(Boost_USE_DEBUG_LIBS OFF)
endif()
set(Boost_NO_SYSTEM_PATHS ON)
find_package(Boost 1.76.0 EXACT REQUIRED COMPONENTS thread log)
if(CMAKE_VERSION VERSION_LESS_EQUAL 3.12)
    ###NOTE: cmake is too old to recognize this boost version, targets and dependencies must be declared manually
    add_library(Boost::thread IMPORTED INTERFACE)
    set_target_properties(Boost::thread PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIR}
        INTERFACE_LINK_LIBRARIES "${Boost_LIBRARY_DIR_RELEASE}/libboost_thread.a;${Boost_LIBRARY_DIR_RELEASE}/libboost_chrono.a;${Boost_LIBRARY_DIR_RELEASE}/libboost_date_time.a;${Boost_LIBRARY_DIR_RELEASE}/libboost_atomic.a;Threads::Threads"
    )
    add_library(Boost::log IMPORTED INTERFACE)
    set_target_properties(Boost::log PROPERTIES
        INTERFACE_INCLUDE_DIRECTORIES ${Boost_INCLUDE_DIR}
        INTERFACE_LINK_LIBRARIES "${Boost_LIBRARY_DIR_RELEASE}/libboost_log.a;${Boost_LIBRARY_DIR_RELEASE}/libboost_date_time.a;${Boost_LIBRARY_DIR_RELEASE}/libboost_log_setup.a;${Boost_LIBRARY_DIR_RELEASE}/libboost_filesystem.a;${Boost_LIBRARY_DIR_RELEASE}/libboost_thread.a;${Boost_LIBRARY_DIR_RELEASE}/libboost_regex.a;${Boost_LIBRARY_DIR_RELEASE}/libboost_chrono.a;${Boost_LIBRARY_DIR_RELEASE}/libboost_atomic.a"
    )
elseif(CMAKE_VERSION VERSION_LESS_EQUAL 3.20)
    #https://gitlab.kitware.com/cmake/cmake/-/issues/20638
    set_target_properties(Boost::log_setup PROPERTIES
        INTERFACE_LINK_LIBRARIES Boost::log
    )
endif()
# openSSL
join_path(OPENSSL_ROOT_DIR ${EXTERNAL-DEPS-DIR} "openssl" "build")
set(OPENSSL_USE_STATIC_LIBS ON)
find_package(OpenSSL 1.1.1 EXACT REQUIRED)
# zlib
join_path(ZLIB_ROOT ${EXTERNAL-DEPS-DIR} "zlib" "build")
find_package(ZLIB 1.2.12 EXACT REQUIRED)

#### cmake-based projects with xxx-config.cmake file
# nlohmann_json
join_path(_nlohmannDir ${EXTERNAL-DEPS-DIR} "nlohmann_json") 
find_package(nlohmann_json REQUIRED PATHS ${_nlohmannDir})
# ms-gsl
join_path(_msgGslDir ${EXTERNAL-DEPS-DIR} "ms-gsl") 
find_package(Microsoft.GSL REQUIRED PATHS ${_msgGslDir})
# websocketpp
join_path(_weboscketppDir ${EXTERNAL-DEPS-DIR} "websocketpp") 
find_package(websocketpp REQUIRED PATHS ${_weboscketppDir})
# msgpack
join_path(_msgpackDir ${EXTERNAL-DEPS-DIR} "msgpack") 
find_package(msgpack REQUIRED PATHS ${_msgpackDir})

#### dependencies relying on pkg-config
find_package(PkgConfig REQUIRED)
set(PKG_CONFIG_USE_CMAKE_PREFIX_PATH ON)
# libevent
join_path(_libeventPkgDir ${EXTERNAL-DEPS-DIR} "libevent" "build")
list(APPEND CMAKE_PREFIX_PATH ${_libeventPkgDir})
pkg_check_modules(libevent REQUIRED IMPORTED_TARGET libevent)
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
    pkg_check_modules(libevent_pthreads REQUIRED IMPORTED_TARGET libevent_pthreads)
else()
    target_link_libraries(PkgConfig::libevent INTERFACE 
        ws2_32
    )
endif()
# wallycore
join_path(_wallycorePkgDir ${EXTERNAL-DEPS-DIR} "libwally-core" "build")
list(APPEND CMAKE_PREFIX_PATH ${_wallycorePkgDir})
pkg_check_modules(wallycore REQUIRED IMPORTED_TARGET wallycore)
pkg_check_modules(libsecp256k1 REQUIRED IMPORTED_TARGET libsecp256k1)

#### weird beasts
# autobahnn-cpp - cmake-based, yet really messed-up
include(cmake/extern/autobahn.cmake)
# tor - no package manager files whatsoever
include(cmake/extern/tor.cmake)


####################################################################
#### building gdk-rust
add_subdirectory(src)
find_package(SWIG)
add_subdirectory(src/swig_java)
findPython()
add_subdirectory(src/swig_python)
add_subdirectory(src/swift)
add_subdirectory(src/sqlite3)

#### building final greenaddress libraries
create_gdkrust_target()
create_greenaddress_target()
create_greenaddressfull_target()

### installation directives
install_cmake_config()

#### test testing tests
if(NOT ENABLE_TESTS)
    return()
endif()

create_greenaddressstatic_target()

enable_testing()
add_subdirectory(tests)