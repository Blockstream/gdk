
if (CMAKE_CROSSCOMPILING)
    message("cross-compiling: skipping python bindings")
    return()
endif()
if(NOT SWIG_FOUND)
    message("skipping swig python, couldn't find swig")
    return()
endif()
if(NOT Python_FOUND)
    message("skipping swig python, couldn't find python")
    return()
endif()

string(TOUPPER ${CMAKE_BUILD_TYPE} _upper_build_type)
set(_python_C_FLAGS ${CMAKE_C_FLAGS} ${CMAKE_F_FLAGS_${_upper_build_type}})
set(_python_L_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")
if(APPLE)
    set(_python_L_FLAGS "${_python_L_FLAGS} -framework Security")
endif()

configure_file(__init__.py ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/greenaddress/__init__.py COPYONLY)
configure_file(swig_gasdk.i ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/swig_gasdk.i COPYONLY)
configure_file(README.md ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/README.md COPYONLY)
configure_file(pyproject.toml.in ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/pyproject.toml)

get_target_property(_gdk_rust_LINK_LIBRARIES gdk-rust IMPORTED_LOCATION)
get_target_property(_libevent_LINK_LIBRARIES event_static IMPORTED_LOCATION_${_upper_build_type})
set(_libevent_pthreads_LINK_LIBRARIES "")
if(TARGET event_pthreads_static)
    get_target_property(_libevent_pthreads_LINK_LIBRARIES event_pthreads_static IMPORTED_LOCATION_${_upper_build_type})
endif()

set(_gdk_library "")
if(DEV_MODE)
    configure_file(dev-mode-setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/setup.py)
    set(_gdk_library "greenaddress")
elseif(APPLE)
    find_package(Python ${PYTHON_REQUIRED_VERSION} EXACT COMPONENTS Development)
    configure_file(mac-setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/setup.py)
    set(_gdk_library "greenaddress-static")
else()
    configure_file(setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/setup.py)
    set(_gdk_library "greenaddress-static")
endif()

add_custom_command(OUTPUT python-wheel-canary-file
    COMMAND cmake -E env
        LDSHARED=${CMAKE_C_COMPILER} LDFLAGS=${_pythonLFlags}
        CPP=${CMAKE_CXX_COMPILER} CPPFLAGS=${_pythonCFlags}
        CXX=${CMAKE_CXX_COMPILER} CXXFLAGS=${_pythonCFlags}
        CC=${CMAKE_C_COMPILER} CFLAGS=${_pythonCFlags}
        ${Python_EXECUTABLE} -m build
    COMMAND touch python-wheel-canary-file
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/greenaddress
    DEPENDS
        ${_gdk_library}
        ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/swig_gasdk.i
        ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/greenaddress/__init__.py
        ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/README.md
        ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/pyproject.toml
        ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/setup.py
    COMMENT "building python-wheel"
)
add_custom_target(python-wheel
    DEPENDS python-wheel-canary-file
)
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/dist/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/python
    FILES_MATCHING PATTERN *.whl
)
