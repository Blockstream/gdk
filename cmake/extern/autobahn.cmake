
join_path(AUTOBAHN-CPP_INCLUDE_DIRS ${EXTERNAL-DEPS-DIR} "autobahn-cpp" "include")

add_library(autobahn-cpp INTERFACE IMPORTED)
set_target_properties(autobahn-cpp PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${AUTOBAHN-CPP_INCLUDE_DIRS}
)
