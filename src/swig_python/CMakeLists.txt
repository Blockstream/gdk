
if (CMAKE_CROSSCOMPILING)
    message("cross-compiling: skipping python bindings")
    return()
endif()
if(NOT SWIG_FOUND)
    message("swig not found: skipping swig python binding")
    return()
endif()
if(NOT Python_FOUND)
    message("python not found: skipping swig python binding")
    return()
endif()

string(TOUPPER ${CMAKE_BUILD_TYPE} _upper_build_type)
set(_python_C_FLAGS ${CMAKE_C_FLAGS} ${CMAKE_F_FLAGS_${_upper_build_type}})
set(_python_L_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
if(APPLE)
    set(_python_L_FLAGS "${_python_L_FLAGS} -framework Security")
endif()

configure_file(__init__.py ${CMAKE_CURRENT_BINARY_DIR}/green_gdk/green_gdk/__init__.py COPYONLY)
configure_file(swig_green_gdk.i ${CMAKE_CURRENT_BINARY_DIR}/green_gdk/swig_green_gdk.i COPYONLY)
configure_file(README.md ${CMAKE_CURRENT_BINARY_DIR}/green_gdk/README.md COPYONLY)
configure_file(pyproject.toml.in ${CMAKE_CURRENT_BINARY_DIR}/green_gdk/pyproject.toml)

get_target_property(_gdk_rust_LINK_LIBRARIES gdk-rust IMPORTED_LOCATION)
get_target_property(_libevent_core_LINK_LIBRARIES libevent::core IMPORTED_LOCATION_${_upper_build_type})
get_target_property(_libevent_extra_LINK_LIBRARIES libevent::extra IMPORTED_LOCATION_${_upper_build_type})
set(_libevent_pthreads_LINK_LIBRARIES "")
if(TARGET libevent::pthreads)
    get_target_property(_libevent_pthreads_LINK_LIBRARIES libevent::pthreads IMPORTED_LOCATION_${_upper_build_type})
endif()

if(DEV_MODE)
    configure_file(dev-mode-setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/green_gdk/setup.py)
elseif(APPLE)
    find_package(Python ${PYTHON_REQUIRED_VERSION} EXACT COMPONENTS Interpreter Development)
    configure_file(mac-setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/green_gdk/setup.py)
else()
    configure_file(setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/green_gdk/setup.py)
endif()

add_custom_command(OUTPUT python-wheel-canary-file
    COMMAND cmake -E env
        LDSHARED=${CMAKE_C_COMPILER} LDFLAGS=${_pythonLFlags}
        CPP=${CMAKE_CXX_COMPILER} CPPFLAGS=${_pythonCFlags}
        CXX=${CMAKE_CXX_COMPILER} CXXFLAGS=${_pythonCFlags}
        CC=${CMAKE_C_COMPILER} CFLAGS=${_pythonCFlags}
        ${Python_EXECUTABLE} -m build
    COMMAND touch python-wheel-canary-file
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/green_gdk
    DEPENDS
        green_gdk
        ${CMAKE_CURRENT_BINARY_DIR}/green_gdk/swig_green_gdk.i
        ${CMAKE_CURRENT_BINARY_DIR}/green_gdk/green_gdk/__init__.py
        ${CMAKE_CURRENT_BINARY_DIR}/green_gdk/README.md
        ${CMAKE_CURRENT_BINARY_DIR}/green_gdk/pyproject.toml
        ${CMAKE_CURRENT_BINARY_DIR}/green_gdk/setup.py
    COMMENT "building python-wheel"
)
add_custom_target(python-wheel
    DEPENDS python-wheel-canary-file
)
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/green_gdk/dist/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/python
    COMPONENT gdk-python
    FILES_MATCHING PATTERN *.whl
)
