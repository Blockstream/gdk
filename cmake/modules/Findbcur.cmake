# * Try to find the bcur library
#
# optional hint: bcur_ROOT_DIR
#
# once done this will define
# - bcur_FOUND
# - bcur_INCLUDE_DIRS
# - bcur_LINK_LIBRARIES
#
# and the imported target
# - extern::bcur

include(FindPackageHandleStandardArgs)

set(bcur_ROOT_DIR
    ""
    CACHE PATH "Folder contains bcur install dir"
)
find_path(bcur_INCLUDE_DIR bc-ur/bc-ur.hpp PATHS ${bcur_ROOT_DIR})
find_library(
    bcur_LIBRARIES
    NAMES bc-ur
    PATHS ${bcur_ROOT_DIR}/lib
)

find_package_handle_standard_args(bcur DEFAULT_MSG bcur_LIBRARIES bcur_INCLUDE_DIR)
if(bcur_FOUND)
    set(bcur_LINK_LIBRARIES ${bcur_LIBRARIES})
    set(bcur_INCLUDE_DIRS ${bcur_INCLUDE_DIR})
    add_library(extern::bc-ur STATIC IMPORTED)
    set_target_properties(
        extern::bc-ur PROPERTIES IMPORTED_LOCATION ${bcur_LIBRARIES} INTERFACE_INCLUDE_DIRECTORIES ${bcur_INCLUDE_DIR}
    )

endif()
