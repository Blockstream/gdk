if(ENABLE_BCUR)
    join_path(_bcurRootDir ${EXTERNAL-DEPS-DIR} "bc-ur" "build")
    join_path(_bcURLibDir ${_bcurRootDir} "lib")
    join_path(BCUR_INCLUDE_DIR ${_bcurRootDir} "include")
    find_library(BCUR_LIBRARIES bc-ur PATHS ${_bcURLibDir})
    add_library(bc-ur STATIC IMPORTED)
    set_target_properties(bc-ur
        PROPERTIES 
            IMPORTED_LOCATION ${BCUR_LIBRARIES}
            INTERFACE_INCLUDE_DIRECTORIES ${BCUR_INCLUDE_DIR}
    )
    add_compile_definitions(USE_REAL_BCUR)
else()
    set(BCUR_INCLUDE_DIR "")
    set(BCUR_LIBRARIES "")
endif()
