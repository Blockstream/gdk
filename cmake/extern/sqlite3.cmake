#sqlite
join_path(_sqlitePkgDir ${EXTERNAL-DEPS-DIR} "sqlite" "build")
join_path(sqlite3_LINK_LIBRARIES ${_sqlitePkgDir} "lib" "libsqlite3.a")
join_path(sqlite3_INCLUDE_DIRECTORIES ${_sqlitePkgDir} "include")

add_library(sqlite3 STATIC IMPORTED)
set_target_properties(sqlite3 PROPERTIES
    IMPORTED_LOCATION ${sqlite3_LINK_LIBRARIES}
    INTERFACE_INCLUDE_DIRECTORIES ${sqlite3_INCLUDE_DIRECTORIES}
)
