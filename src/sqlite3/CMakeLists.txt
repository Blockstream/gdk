add_library(sqlite3 OBJECT sqlite3.c)
target_include_directories(sqlite3 
    PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
)
# set_target_properties(sqlite3
#     PROPERTIES 
#         C_VISIBILITY_PRESET default
#         CXX_VISIBILITY_PRESET default
#         VISIBILITY_INLINES_HIDDEN FALSE
# )
target_compile_definitions(sqlite3 PRIVATE _HAVE_SQLITE_CONFIG_H)
