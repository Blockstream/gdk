include(GenerateExportHeader)

# version file 
join_path(_versionFileIn ${CMAKE_SOURCE_DIR} "src" "version.h.in")
join_path(_versionFileOut ${CMAKE_SOURCE_DIR} "src" "version.h")
configure_file( ${_versionFileIn} ${_versionFileOut} @ONLY)

add_library(greenaddress-objects OBJECT
    amount.cpp amount.hpp
    assertion.cpp assertion.hpp
    auth_handler.cpp auth_handler.hpp
    bcur_auth_handlers.cpp bcur_auth_handlers.hpp
    client_blob.cpp client_blob.hpp
    containers.cpp containers.hpp
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
    io_runner.cpp io_runner.hpp
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

generate_export_header(greenaddress-objects 
    BASE_NAME gdk 
    EXPORT_MACRO_NAME GDK_API
)
# TODO: rework the whole gdk CMakeFile to remove the intermediate
# greenaddress-objects target, making this hacky stuff unnecessary
target_compile_definitions(greenaddress-objects
    PRIVATE
        greenaddress_objects_EXPORTS
        _FORTIFY_SOURCE=2
)
if(Windows)
    target_compile_definitions(greenaddress-objects PUBLIC
        BOOST_ASIO_DISABLE_IOCP
        BOOST_ASIO_DISABLE_VISIBILITY
    )
endif()

target_compile_options(greenaddress-objects 
    PRIVATE
        ${COMPILE_OPTIONS}
        "-Wno-deprecated-declarations"
        "-funsigned-char"
        "-fasynchronous-unwind-tables"
        "-fexceptions"
        "-fstack-protector-strong"
        "-fno-strict-aliasing"
)
if(CMAKE_BUILD_TYPE STREQUAL "Debug" AND MINGW)
    set_source_files_properties(ga_session.cpp PROPERTIES COMPILE_FLAGS "-O1")
    set_source_files_properties(http_client.cpp PROPERTIES COMPILE_FLAGS "-O1")
    set_source_files_properties(wamp_transport.cpp PROPERTIES COMPILE_FLAGS "-O1")
    target_link_options(greenaddress-objects PRIVATE "-Wa,-mbig-obj")
endif()
target_compile_options(greenaddress-objects PRIVATE
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wall>
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wextra>
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wpedantic>
    $<$<CXX_COMPILER_ID:GNU,Clang>:-Wshadow>
    ##### should be un-commented and errors should be fixed
    # -Werror
    # -Wconversion
)
target_include_directories(greenaddress-objects
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/include>
        $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}>
        $<BUILD_INTERFACE:${wallycore_INCLUDE_DIRS}>
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}/gdk>
    PRIVATE
        ${LIBEVENT_INCLUDE_DIRS}
)
target_include_directories(greenaddress-objects SYSTEM PRIVATE
    $<TARGET_PROPERTY:gdk-rust,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:Microsoft.GSL::GSL,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:extern::autobahn-cpp,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:msgpackc-cxx,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:websocketpp::websocketpp,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:nlohmann_json::nlohmann_json,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:extern::tor,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:libevent::core,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:extern::sqlite3,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:Boost::boost,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:OpenSSL::SSL,INTERFACE_INCLUDE_DIRECTORIES>
    $<TARGET_PROPERTY:ZLIB::ZLIB,INTERFACE_INCLUDE_DIRECTORIES>
    ${BCUR_INCLUDE_DIRS}
    ${URC_INCLUDE_DIRS}
    ${TINYCBOR_INCLUDE_DIRS}
)
set(_publicHeaders ${CMAKE_SOURCE_DIR}/include/gdk.h
    ${CMAKE_SOURCE_DIR}/include/module.modulemap
    ${CMAKE_SOURCE_DIR}/include/wally_wrapper.h
    ${CMAKE_CURRENT_BINARY_DIR}/gdk_export.h
)

set_target_properties(greenaddress-objects PROPERTIES PUBLIC_HEADER "${_publicHeaders}")
# with only purpose of sequencing rust and c++ builds and avoid CPU/RAM overload
if(ENABLE_RUSTCPP)
    add_dependencies(greenaddress-objects gdk-rust)
endif()
