
find_library(SQLITE3_LINK_LIBRARIES "libsqlite3.a")
find_path(SQLITE3_INCLUDE_DIRS NAMES "sqlite3.h")

add_library(extern::sqlite3 STATIC IMPORTED)
set_target_properties(extern::sqlite3 PROPERTIES
    IMPORTED_LOCATION ${SQLITE3_LINK_LIBRARIES}
    INTERFACE_INCLUDE_DIRECTORIES ${SQLITE3_INCLUDE_DIRS}
)
