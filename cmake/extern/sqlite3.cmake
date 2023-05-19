#sqlite
join_path(_sqlitePkgDir ${EXTERNAL-DEPS-DIR} "sqlite" "build")
add_library(sqlite3 STATIC IMPORTED)
set_target_properties(sqlite3 PROPERTIES
    IMPORTED_LOCATION ${_sqlitePkgDir}/lib/libsqlite3.a
    INTERFACE_INCLUDE_DIRECTORIES ${_sqlitePkgDir}/include
)
