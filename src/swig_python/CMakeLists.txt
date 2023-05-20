macro(create_python_wheel_target)
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
            greenaddress-full
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
endmacro()



macro(prepare_manylinux_build_environment)
    install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/greenaddress
        DESTINATION ${CMAKE_INSTALL_DATADIR}/wheel-build-environment
        EXCLUDE_FROM_ALL
        COMPONENT gdk-cibuildwheel
        PATTERN dist EXCLUDE
        PATTERN greenaddress.egg-info EXCLUDE
        PATTERN python-wheel-canary-file EXCLUDE
    )
    install(FILES
            ${CMAKE_SOURCE_DIR}/include/gdk.h
            ${CMAKE_BINARY_DIR}/src/gdk_export.h
        DESTINATION ${CMAKE_INSTALL_DATADIR}/wheel-build-environment/greenaddress
        COMPONENT gdk-cibuildwheel
        EXCLUDE_FROM_ALL
        )
    install(TARGETS greenaddress-full
        ARCHIVE DESTINATION ${CMAKE_INSTALL_DATADIR}/wheel-build-environment/greenaddress
        COMPONENT gdk-cibuildwheel
        EXCLUDE_FROM_ALL
    )
endmacro()



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

string(TOUPPER ${CMAKE_BUILD_TYPE} _upperBuildType)
set(_pythonCFlags ${CMAKE_C_FLAGS} ${CMAKE_C_FLAGS_${_upperBuildType}})
string(STRIP ${_pythonCFlags} _pythonCFlags)
set(_pythonLFlags "${CMAKE_SHARED_LINKER_FLAGS}")

if(CMAKE_BUILD_TYPE STREQUAL Debug)
    set(_pythonCFlags "${_pythonCFlags} -O0")
    set(_pythonLFlags "${_pythonLFlags} -O0")
endif()
if(APPLE)
    set(_pythonLFlags "${_pythonLFlags} -framework Security")
endif()

configure_file(__init__.py ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/greenaddress/__init__.py COPYONLY)
configure_file(swig_gasdk.i ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/swig_gasdk.i COPYONLY)
configure_file(README.md ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/README.md COPYONLY)
configure_file(pyproject.toml.in ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/pyproject.toml)

if(DEV_MODE)
    configure_file(dev-mode-setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/setup.py)
elseif(APPLE)
    find_package(Python ${PYTHON_REQUIRED_VERSION} EXACT COMPONENTS Development)
    configure_file(mac-setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/setup.py)
else()
    configure_file(setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/setup.py)
endif()
create_python_wheel_target()

if(DEV_MODE)
    return()
endif()

if(NOT APPLE)
    prepare_manylinux_build_environment()
endif()
