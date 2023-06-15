join_path(TOR_LINK_LIBRARIES ${EXTERNAL-DEPS-DIR} "tor" "build" "lib" "libtor.a")
join_path(TOR_INCLUDE_DIRS ${EXTERNAL-DEPS-DIR} "tor" "build" "include")


add_library(extern::tor STATIC IMPORTED)
set_target_properties(extern::tor PROPERTIES
    IMPORTED_LOCATION ${TOR_LINK_LIBRARIES}
    INTERFACE_INCLUDE_DIRECTORIES ${TOR_INCLUDE_DIRS}
)

target_link_libraries(extern::tor INTERFACE
    event_static
    $<$<PLATFORM_ID:Windows>:ssp>
    $<$<PLATFORM_ID:Windows>:iphlpapi>
    $<$<PLATFORM_ID:Windows>:shlwapi>
)
