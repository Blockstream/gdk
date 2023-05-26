include(GNUInstallDirs)
include(CMakePrintHelpers)



macro(create_greenaddress_target)
    add_library(greenaddress SHARED $<TARGET_OBJECTS:greenaddress-objects>)
    if(TARGET swig-java-obj)
        target_sources(greenaddress PRIVATE $<TARGET_OBJECTS:swig-java-obj>)
    endif()
    set_target_properties(greenaddress PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        PUBLIC_HEADER $<TARGET_PROPERTY:greenaddress-objects,PUBLIC_HEADER>
    )
    get_target_property(_gaIncludeDir greenaddress-objects INTERFACE_INCLUDE_DIRECTORIES)
    target_include_directories(greenaddress INTERFACE ${_gaIncludeDir})
    target_link_libraries(greenaddress PRIVATE
        gdk-rust
        sqlite3
        Microsoft.GSL::GSL
        autobahn-cpp
        msgpackc-cxx
        websocketpp::websocketpp
        nlohmann_json::nlohmann_json
        external::tor
        event_static
        PkgConfig::libsecp256k1
        $<$<NOT:$<PLATFORM_ID:Windows>>:event_pthreads_static>
        Boost::boost
        Boost::log
        Boost::thread
        OpenSSL::SSL
        $<$<PLATFORM_ID:Android>:log>
        ZLIB::ZLIB
        $<$<NOT:$<PLATFORM_ID:Android>>:pthread>
    )
    if(TARGET bc-ur)
        target_link_libraries(greenaddress PRIVATE bc-ur)
    endif()
    get_target_property(_wallycoreLib PkgConfig::wallycore INTERFACE_LINK_LIBRARIES)
    #cmake 3.24 ==> $<LINK_LIBRARY:WHOLE_ARCHIVE,PkgConfig::wallycore>
    set(_gdkLinkOptions ${GDK_LINK_OPTIONS})
    if(APPLE)
        list(APPEND _gdkLinkOptions "-Wl,-force_load" "SHELL:${_wallycoreLib}")
    else()
        list(APPEND _gdkLinkOptions "LINKER:SHELL:--whole-archive" "SHELL:${_wallycoreLib}" "LINKER:SHELL:--no-whole-archive")
    endif()
    target_link_options(greenaddress PRIVATE "${_gdkLinkOptions}")
    get_library_install_dir(_libInstallDir)
    install(TARGETS greenaddress
        EXPORT "greenaddress-target"
        RUNTIME EXCLUDE_FROM_ALL
        OBJECTS EXCLUDE_FROM_ALL
        ARCHIVE EXCLUDE_FROM_ALL
        LIBRARY DESTINATION ${_libInstallDir}
                COMPONENT gdk-runtime
        OPTIONAL
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/gdk
                COMPONENT gdk-dev
                EXCLUDE_FROM_ALL
    )
    install(
        FILES
            ${wallycore_INCLUDE_DIRS}/wally.hpp
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
        COMPONENT gdk-dev
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/gdk/libwally-core/
        EXCLUDE_FROM_ALL
    )
    get_cmake_install_dir(LIB_CMAKE_INSTALL_DIR ${_libInstallDir})
    install(EXPORT "greenaddress-target"
        COMPONENT gdk-dev
        DESTINATION ${LIB_CMAKE_INSTALL_DIR}/cmake
        NAMESPACE ${PROJECT_NAME}::
        FILE "greenaddress-targets.cmake"
        EXCLUDE_FROM_ALL
    )
    find_program(OBJCOPY NAMES llvm-objcopy ${TOOLCHAIN_PREFIX}-objcopy objcopy HINTS ${ANDROID_TOOLCHAIN_ROOT})
    if(OBJCOPY)
        add_custom_command(OUTPUT libgreenaddress.syms
            COMMAND ${OBJCOPY} --only-keep-debug $<TARGET_FILE:greenaddress> libgreenaddress.syms
            DEPENDS greenaddress
            BYPRODUCTS libgreenaddress.syms
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
        )
        add_custom_target(greenaddress-syms ALL
            DEPENDS libgreenaddress.syms
        )
        install(FILES ${CMAKE_BINARY_DIR}/libgreenaddress.syms
            DESTINATION ${_libInstallDir}
            COMPONENT gdk-runtime
            OPTIONAL
        )
    endif()
endmacro()


macro(create_greenaddressstatic_target)
    add_library(greenaddress-static STATIC $<TARGET_OBJECTS:greenaddress-objects>)
    if(TARGET swig_java)
        target_sources(greenaddress-static PRIVATE $<TARGET_OBJECTS:swig_java>)
        target_link_libraries(greenaddress-static PRIVATE swig_java)
    endif()
    get_target_property(_gaIncludeDir greenaddress-objects INTERFACE_INCLUDE_DIRECTORIES)
    target_include_directories(greenaddress-static INTERFACE ${_gaIncludeDir})
    target_link_libraries(greenaddress-static PUBLIC
        PkgConfig::wallycore
        PkgConfig::libsecp256k1
        gdk-rust
        sqlite3
        Microsoft.GSL::GSL
        autobahn-cpp
        msgpackc-cxx
        websocketpp::websocketpp
        nlohmann_json::nlohmann_json
        external::tor
        event_static
        $<$<NOT:$<PLATFORM_ID:Windows>>:event_pthreads_static>
        Boost::boost
        Boost::log
        Boost::thread
        OpenSSL::SSL
        $<$<PLATFORM_ID:Android>:log>
        ZLIB::ZLIB
        $<$<NOT:$<PLATFORM_ID:Android>>:pthread>
    )
    if(TARGET bc-ur)
        target_link_libraries(greenaddress-static PRIVATE bc-ur)
    endif()
    target_link_options(greenaddress-static INTERFACE "${GDK_LINK_OPTIONS}")
endmacro()



macro(create_greenaddressfull_target)
    add_library(greenaddress-full STATIC $<TARGET_OBJECTS:greenaddress-objects>)
    set_target_properties(greenaddress-full PROPERTIES OUTPUT_NAME greenaddress_full)
    ### WARNING once on cmake > 3.12 ``target_sources(greenaddress-objects $<TARGET_NAME_IF_EXISTS:swig_java>)``
    if(TARGET swig_java)
        target_sources(greenaddress-full PRIVATE $<TARGET_OBJECTS:swig_java>)
    endif()
    set_target_properties(greenaddress-full PROPERTIES
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        PUBLIC_HEADER $<TARGET_PROPERTY:greenaddress-objects,PUBLIC_HEADER>
    )
    add_dependencies(greenaddress-full gdk-rust)
    get_target_property(_gaIncludeDir greenaddress-objects INTERFACE_INCLUDE_DIRECTORIES)
    target_include_directories(greenaddress-full INTERFACE ${_gaIncludeDir})
    set(_maybeLibeventPthreads "")
    if(NOT CMAKE_SYSTEM_NAME STREQUAL "Windows")
        if(CMAKE_BUILD_TYPE STREQUAL Debug)
            get_target_property(_maybeLibeventPthreads event_pthreads_static IMPORTED_LOCATION_DEBUG)
        else()
            get_target_property(_maybeLibeventPthreads event_pthreads_static IMPORTED_LOCATION_RELEASE)
        endif()
    endif()
    configure_file(${CMAKE_SOURCE_DIR}/tools/archiver.sh.gen.in  archiver.sh.gen)
    file(GENERATE OUTPUT archiver.sh INPUT ${CMAKE_CURRENT_BINARY_DIR}/archiver.sh.gen)
    add_custom_command(TARGET greenaddress-full POST_BUILD
        COMMAND mv $<TARGET_FILE:greenaddress-full> libgreenaddress-partial.a
        COMMAND ./archiver.sh
        COMMAND rm libgreenaddress-partial.a
    )
    target_link_options(greenaddress-full PRIVATE "${GDK_LINK_OPTIONS}")
    get_library_install_dir(_libInstallDir)
    get_cmake_install_dir(LIB_CMAKE_INSTALL_DIR ${_libInstallDir})
    install(TARGETS greenaddress-full
        EXPORT "greenaddress-full-target"
        RUNTIME EXCLUDE_FROM_ALL
        OBJECTS EXCLUDE_FROM_ALL
        LIBRARY EXCLUDE_FROM_ALL
        ARCHIVE DESTINATION ${_libInstallDir}
            COMPONENT gdk-dev
            EXCLUDE_FROM_ALL
        PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/gdk
            COMPONENT gdk-dev
            EXCLUDE_FROM_ALL
        OPTIONAL
    )
    install(EXPORT "greenaddress-full-target"
        COMPONENT gdk-dev
        DESTINATION ${LIB_CMAKE_INSTALL_DIR}/cmake
        NAMESPACE ${PROJECT_NAME}::
        FILE "greenaddress-full-targets.cmake"
        EXCLUDE_FROM_ALL
    )
    install(
        FILES 
            ${wallycore_INCLUDE_DIRS}/wally.hpp
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
        COMPONENT gdk-dev
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/gdk/libwally-core/
        EXCLUDE_FROM_ALL
    )
endmacro()



