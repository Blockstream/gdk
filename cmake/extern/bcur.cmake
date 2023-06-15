if(ENABLE_BCUR)
    join_path(_bcurRootDir ${EXTERNAL-DEPS-DIR} "bc-ur" "build")
    join_path(_bcURLibDir ${_bcurRootDir} "lib")
    join_path(BCUR_INCLUDE_DIRS ${_bcurRootDir} "include")
    find_library(BCUR_LINK_LIBRARIES bc-ur PATHS ${_bcURLibDir})
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
