# * Try to find the sqlite3 library
#
# optional hint: sqlite3_ROOT_DIR
#
# once done this will define
# - sqlite3_FOUND
# - sqlite3_INCLUDE_DIRS
# - sqlite3_LINK_LIBRARIES
#
# and the imported target
# - extern::sqlite3

include(FindPackageHandleStandardArgs)

set(sqlite3_ROOT_DIR
    ""
    CACHE PATH "Folder contains sqlite3 install dir"
)
find_path(sqlite3_INCLUDE_DIR sqlite3.h PATHS ${sqlite3_ROOT_DIR})
find_library(
    sqlite3_LIBRARIES
    NAMES sqlite3
    PATHS ${sqlite3_ROOT_DIR}/lib NO_CMAKE_SYSTEM_PATH
)

find_package_handle_standard_args(sqlite3 DEFAULT_MSG sqlite3_LIBRARIES sqlite3_INCLUDE_DIR)
if(sqlite3_FOUND)
    set(sqlite3_LINK_LIBRARIES ${sqlite3_LIBRARIES})
    set(sqlite3_INCLUDE_DIRS ${sqlite3_INCLUDE_DIR})
    add_library(extern::sqlite3 STATIC IMPORTED)
    set_target_properties(
        extern::sqlite3 PROPERTIES IMPORTED_LOCATION ${sqlite3_LIBRARIES} INTERFACE_INCLUDE_DIRECTORIES
                                                                          ${sqlite3_INCLUDE_DIR}
    )
endif()
