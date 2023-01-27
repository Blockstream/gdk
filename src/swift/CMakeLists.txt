if(NOT APPLE)
    message("not on apple, skipping swift bindings")
    return()
endif()

find_program(SWIFT "swift")
if(SWIFT-NOTFOUND)
    message("swift exec not found, skipping swift bindings")
    return()
endif()

join_path(_packagePath ${CMAKE_CURRENT_LIST_DIR} "GreenAddress")
get_target_property(_gdkSrcPath greenaddress-objects SOURCE_DIR)
join_path(_gdkIncPath ${CMAKE_SOURCE_DIR} "include")
get_target_property(_gdkBinPath greenaddress-objects BINARY_DIR)

add_custom_command(OUTPUT GreenAddress.swiftmodule
    COMMAND ${SWIFT} build --package-path ${_packagePath} 
        --build-path ${CMAKE_CURRENT_BINARY_DIR}
        -Xswiftc -I${_gdkSrcPath} 
        -Xswiftc -I${_gdkIncPath} 
        -Xswiftc -I${_gdkBinPath} 
        -Xswiftc -L${_gdkBinPath}
        -Xswiftc -I${wallycore_INCLUDE_DIRS}
    DEPENDS greenaddress-objects
)
add_custom_target(swift-cmd ALL
    DEPENDS GreenAddress.swiftmodule
)
INSTALL(
    FILES
        GreenAddress/Sources/GreenAddress/GreenAddress.swift
    DESTINATION
        ${CMAKE_INSTALL_DATADIR}/gdk/
     COMPONENT
        gdk-dev
)
