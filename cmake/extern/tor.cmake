join_path(tor_LINK_LIBRARIES ${EXTERNAL-DEPS-DIR} "tor" "build" "lib" "libtor.a")
join_path(tor_INCLUDE_DIRS ${EXTERNAL-DEPS-DIR} "tor" "build" "include")


add_library(external::tor STATIC IMPORTED)
set_target_properties(external::tor PROPERTIES
    IMPORTED_LOCATION ${tor_LINK_LIBRARIES}
    INTERFACE_INCLUDE_DIRECTORIES ${tor_INCLUDE_DIRS}
)

target_link_libraries(external::tor INTERFACE
    event_static
    $<$<PLATFORM_ID:Windows>:ssp>
    $<$<PLATFORM_ID:Windows>:iphlpapi>
    $<$<PLATFORM_ID:Windows>:shlwapi>
)
