
if(ENABLE_BCUR)
    find_path(BCUR_INCLUDE_DIRS NAMES "bc-ur/bc-ur.hpp")
    find_library(BCUR_LINK_LIBRARIES bc-ur)
    add_library(extern::bc-ur STATIC IMPORTED)
    set_target_properties(extern::bc-ur
        PROPERTIES 
            IMPORTED_LOCATION ${BCUR_LINK_LIBRARIES}
            INTERFACE_INCLUDE_DIRECTORIES ${BCUR_INCLUDE_DIRS}
    )
    add_compile_definitions(USE_REAL_BCUR)
else()
    set(BCUR_INCLUDE_DIRS "")
    set(BCUR_LINK_LIBRARIES "")
endif()
