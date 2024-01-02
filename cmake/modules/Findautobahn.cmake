# * Try to find the autobahn library
#
# optional hint: autobahn_ROOT_DIR
#
# once done this will define
# - autobahn_FOUND
# - autobahn_INCLUDE_DIRS
# - autobahn_LINK_LIBRARIES
#
# and the imported target
# - extern::autobahn-cpp

include(FindPackageHandleStandardArgs)

set(autobahn_ROOT_DIR
    ""
    CACHE PATH "Folder contains autobahn install dir"
)
find_path(autobahn_INCLUDE_DIR autobahn/autobahn.hpp PATHS ${autobahn_ROOT_DIR})

find_package_handle_standard_args(autobahn DEFAULT_MSG autobahn_INCLUDE_DIR)
if(autobahn_FOUND)
    set(autobahn_INCLUDE_DIRS ${autobahn_INCLUDE_DIR})
    add_library(extern::autobahn-cpp INTERFACE IMPORTED)
    set_target_properties(extern::autobahn-cpp PROPERTIES INTERFACE_INCLUDE_DIRECTORIES ${autobahn_INCLUDE_DIRS})
endif()
