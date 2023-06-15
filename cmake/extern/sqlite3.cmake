#sqlite
join_path(_sqlitePkgDir ${EXTERNAL-DEPS-DIR} "sqlite" "build")
join_path(SQLITE3_LINK_LIBRARIES ${_sqlitePkgDir} "lib" "libsqlite3.a")
join_path(SQLITE3_INCLUDE_DIRS ${_sqlitePkgDir} "include")

add_library(extern::sqlite3 STATIC IMPORTED)
set_target_properties(extern::sqlite3 PROPERTIES
    IMPORTED_LOCATION ${SQLITE3_LINK_LIBRARIES}
    INTERFACE_INCLUDE_DIRECTORIES ${SQLITE3_INCLUDE_DIRS}
)
