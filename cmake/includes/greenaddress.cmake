
macro(create_greenaddressfull_target)
    add_library(greenaddress-full STATIC $<TARGET_OBJECTS:greenaddress>)
    set_target_properties(greenaddress-full PROPERTIES
        OUTPUT_NAME greenaddress_full
        VERSION ${PROJECT_VERSION}
        SOVERSION ${PROJECT_VERSION_MAJOR}
        PUBLIC_HEADER $<TARGET_PROPERTY:greenaddress,PUBLIC_HEADER>
    )
    get_target_property(_gaIncludeDir greenaddress INTERFACE_INCLUDE_DIRECTORIES)
    target_include_directories(greenaddress-full INTERFACE ${_gaIncludeDir})
    file(GENERATE OUTPUT archiver.sh INPUT ${CMAKE_SOURCE_DIR}/tools/archiver.sh.gen)
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
            ${wallycore_INCLUDE_DIRS}/wally_transaction_members.h
        COMPONENT gdk-dev
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/gdk/libwally-core/
        EXCLUDE_FROM_ALL
    )
endmacro()



