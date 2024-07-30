include(GNUInstallDirs)

# version file
find_package(Git REQUIRED)
execute_process(
    COMMAND ${GIT_EXECUTABLE} rev-parse HEAD
    RESULT_VARIABLE VCS_SHA_RESULT
    OUTPUT_VARIABLE VCS_SHA
    OUTPUT_STRIP_TRAILING_WHITESPACE
)
find_file(version_file version.h.in PATHS ${CMAKE_CURRENT_SOURCE_DIR})
configure_file(${version_file} version.h @ONLY)

add_library(green_gdk)
target_sources(green_gdk PRIVATE
    amount.cpp amount.hpp
    assertion.cpp assertion.hpp
    auth_handler.cpp auth_handler.hpp
    bcur_auth_handlers.cpp bcur_auth_handlers.hpp
    client_blob.cpp client_blob.hpp
    containers.hpp
    exception.cpp exception.hpp
    ffi_c.cpp
    ga_auth_handlers.cpp ga_auth_handlers.hpp
    ga_cache.cpp ga_cache.hpp
    ga_psbt.cpp ga_psbt.hpp
    ga_rust.cpp ga_rust.hpp
    ga_session.cpp ga_session.hpp
    ga_strings.cpp ga_strings.hpp
    ga_tor.cpp ga_tor.hpp
    ga_tx.cpp ga_tx.hpp
    ga_wally.cpp ga_wally.hpp
    http_client.cpp http_client.hpp
    io_runner.hpp io_container.cpp
    json_utils.cpp json_utils.hpp
    network_parameters.cpp network_parameters.hpp
    session.cpp session.hpp
    session_impl.cpp session_impl.hpp
    signer.cpp signer.hpp
    socks_client.cpp socks_client.hpp
    swap_auth_handlers.cpp swap_auth_handlers.hpp
    transaction_utils.cpp transaction_utils.hpp
    validate.cpp validate.hpp
    utils.cpp utils.hpp
    wamp_transport.cpp wamp_transport.hpp
    xpub_hdkey.cpp xpub_hdkey.hpp
)

target_compile_definitions(green_gdk
    PRIVATE
        GDK_BUILD
        _FORTIFY_SOURCE=2
)
if(Windows)
    target_compile_definitions(green_gdk PUBLIC
        BOOST_ASIO_DISABLE_IOCP
        BOOST_ASIO_DISABLE_VISIBILITY
    )
endif()

target_compile_options(green_gdk
    PRIVATE
        ${COMPILE_OPTIONS}
        "-Wno-deprecated-declarations"
        "-funsigned-char"
        "-fasynchronous-unwind-tables"
        "-fexceptions"
        "-fstack-protector-strong"
        "-fno-strict-aliasing"
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall>
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wextra>
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wpedantic>
        $<$<CXX_COMPILER_ID:GNU,Clang>:-Wshadow>
        ##### should be un-commented and errors should be fixed
        # -Werror
        # -Wconversion
)
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND MINGW)
    set_source_files_properties(ga_session.cpp PROPERTIES COMPILE_FLAGS "-O1")
    set_source_files_properties(http_client.cpp PROPERTIES COMPILE_FLAGS "-O1")
    set_source_files_properties(wamp_transport.cpp PROPERTIES COMPILE_FLAGS "-O1")
    target_link_options(green_gdk PRIVATE "-Wa,-mbig-obj")
endif()

target_include_directories(green_gdk
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/gdk>
)

### deps
#### wallycore special
#cmake 3.24 ==> $<LINK_LIBRARY:WHOLE_ARCHIVE,PkgConfig::wallycore>
target_include_directories(
    green_gdk SYSTEM PRIVATE $<TARGET_PROPERTY:PkgConfig::wallycore,INTERFACE_INCLUDE_DIRECTORIES>
)
set(_gdkLinkOptions ${GDK_LINK_OPTIONS})
if(APPLE)
    list(APPEND _gdkLinkOptions "-Wl,-force_load" "SHELL:$<TARGET_PROPERTY:PkgConfig::wallycore,INTERFACE_LINK_LIBRARIES>")
else()
    list(APPEND _gdkLinkOptions "LINKER:SHELL:--whole-archive" "SHELL:$<TARGET_PROPERTY:PkgConfig::wallycore,INTERFACE_LINK_LIBRARIES>"
         "LINKER:SHELL:--no-whole-archive"
    )
endif()
target_link_options(green_gdk PUBLIC $<BUILD_INTERFACE:${_gdkLinkOptions}>)
#### rest
target_link_libraries(
    green_gdk
    PRIVATE gdk-rust
            extern::sqlite3
            Microsoft.GSL::GSL
            extern::autobahn-cpp
            msgpackc-cxx
            websocketpp::websocketpp
            nlohmann_json::nlohmann_json
            extern::tor
            libevent::core
            PkgConfig::wallycore
            PkgConfig::libsecp256k1
            Boost::boost
            Boost::log
            Boost::thread
            OpenSSL::SSL
            $<$<PLATFORM_ID:Android>:log>
            ZLIB::ZLIB
            $<TARGET_NAME_IF_EXISTS:extern::bc-ur>
            $<TARGET_NAME_IF_EXISTS:urc::urc>
)

set(_publicHeaders ${CMAKE_SOURCE_DIR}/include/gdk.h
    ${CMAKE_SOURCE_DIR}/include/wally_wrapper.h
)
if (ENABLE_SWIFT)
    list(APPEND _publicHeaders ${CMAKE_SOURCE_DIR}/include/module.modulemap)
endif()

set_target_properties(green_gdk PROPERTIES PUBLIC_HEADER "${_publicHeaders}")

get_library_install_dir(_libInstallDir)
install(
    TARGETS green_gdk
    EXPORT "green_gdk-target"
    RUNTIME EXCLUDE_FROM_ALL
    OBJECTS EXCLUDE_FROM_ALL
    ARCHIVE
        COMPONENT gdk-dev
        EXCLUDE_FROM_ALL
    LIBRARY DESTINATION ${_libInstallDir}
            COMPONENT gdk-runtime
            OPTIONAL
    PUBLIC_HEADER
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/gdk
        COMPONENT gdk-dev
        EXCLUDE_FROM_ALL
)
install(
    FILES ${wallycore_INCLUDE_DIRS}/wally.hpp
          ${wallycore_INCLUDE_DIRS}/wally_address.h
          ${wallycore_INCLUDE_DIRS}/wally_anti_exfil.h
          ${wallycore_INCLUDE_DIRS}/wally_bip32.h
          ${wallycore_INCLUDE_DIRS}/wally_bip38.h
          ${wallycore_INCLUDE_DIRS}/wally_bip39.h
          ${wallycore_INCLUDE_DIRS}/wally_bip85.h
          ${wallycore_INCLUDE_DIRS}/wally_core.h
          ${wallycore_INCLUDE_DIRS}/wally_coinselection.h
          ${wallycore_INCLUDE_DIRS}/wally_crypto.h
          ${wallycore_INCLUDE_DIRS}/wally_descriptor.h
          ${wallycore_INCLUDE_DIRS}/wally_elements.h
          ${wallycore_INCLUDE_DIRS}/wally_map.h
          ${wallycore_INCLUDE_DIRS}/wally_psbt.h
          ${wallycore_INCLUDE_DIRS}/wally_psbt_members.h
          ${wallycore_INCLUDE_DIRS}/wally_script.h
          ${wallycore_INCLUDE_DIRS}/wally_symmetric.h
          ${wallycore_INCLUDE_DIRS}/wally_transaction.h
          ${wallycore_INCLUDE_DIRS}/wally_transaction_members.h
    COMPONENT gdk-dev
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/gdk/libwally-core/
    EXCLUDE_FROM_ALL
)
get_cmake_install_dir(LIB_CMAKE_INSTALL_DIR ${_libInstallDir})
install(
    EXPORT "green_gdk-target"
    COMPONENT gdk-dev
    DESTINATION ${LIB_CMAKE_INSTALL_DIR}/cmake
    NAMESPACE ${PROJECT_NAME}::
    FILE "green_gdk-targets.cmake"
    EXCLUDE_FROM_ALL
)
