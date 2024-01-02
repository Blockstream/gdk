# * Try to find the tor library
#
# optional hint: tor_ROOT_DIR
#
# once done this will define
# - tor_FOUND
# - tor_INCLUDE_DIRS
# - tor_LINK_LIBRARIES
#
# and the imported target
# - extern::tor

include(FindPackageHandleStandardArgs)

set(tor_ROOT_DIR
    ""
    CACHE PATH "Folder contains tor install dir"
)
find_path(tor_INCLUDE_DIR tor_api.h PATHS ${tor_ROOT_DIR})
find_library(
    tor_LIBRARIES
    NAMES tor
    PATHS ${tor_ROOT_DIR}/lib
)

find_package_handle_standard_args(tor DEFAULT_MSG tor_LIBRARIES tor_INCLUDE_DIR)
if(tor_FOUND)
    set(tor_LINK_LIBRARIES ${tor_LIBRARIES})
    set(tor_INCLUDE_DIRS ${tor_INCLUDE_DIR})
    add_library(extern::tor STATIC IMPORTED)
    set_target_properties(
        extern::tor PROPERTIES IMPORTED_LOCATION ${tor_LIBRARIES} INTERFACE_INCLUDE_DIRECTORIES ${tor_INCLUDE_DIR}
    )

    target_link_libraries(
        extern::tor INTERFACE libevent::extra $<$<PLATFORM_ID:Windows>:ssp> $<$<PLATFORM_ID:Windows>:iphlpapi>
                              $<$<PLATFORM_ID:Windows>:shlwapi> $<TARGET_NAME_IF_EXISTS:libevent::pthreads>
    )

endif()
