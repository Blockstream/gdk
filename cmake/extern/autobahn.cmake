
find_path(AUTOBAHN-CPP_INCLUDE_DIRS NAMES "autobahn/autobahn.hpp")

add_library(extern::autobahn-cpp INTERFACE IMPORTED)
set_target_properties(extern::autobahn-cpp PROPERTIES
    INTERFACE_INCLUDE_DIRECTORIES ${AUTOBAHN-CPP_INCLUDE_DIRS}
)
