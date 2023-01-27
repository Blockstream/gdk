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

set(_pythonCFlags ${CMAKE_C_FLAGS})
set(_pythonLFlags "${CMAKE_SHARED_LINKER_FLAGS}")
if(CMAKE_BUILD_TYPE STREQUAL Debug)
    set(_pythonCFlags "${_pythonCFlags} ${CMAKE_C_FLAGS_DEBUG} -O0")
    string(STRIP ${_pythonCFlags} _pythonCFlags)
    set(_pythonLFlags "${_pythonLFlags} -O0")
else()
    set(_pythonCFlags "${_pythonCFlags} ${CMAKE_C_FLAGS_RELEASE}")
    string(STRIP ${_pythonCFlags} _pythonCFlags)
endif()
if(APPLE)
    set(_pythonLFlags "${_pythonLFlags} -framework Security")
endif()
file(COPY __init__.py DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/greenaddress/)
file(COPY swig_gasdk.i DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/greenaddress)
file(COPY README.md DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/greenaddress)
configure_file(pyproject.toml.in ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/pyproject.toml)
configure_file(setup.py.in ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/setup.py)

add_custom_command(OUTPUT python-wheel-canary-file
    COMMAND cmake -E env
        LDSHARED=${CMAKE_C_COMPILER} LDFLAGS=${_pythonLFlags}
        CPP=${CMAKE_CXX_COMPILER} CPPFLAGS=${_pythonCFlags}
        CXX=${CMAKE_CXX_COMPILER} CXXFLAGS=${_pythonCFlags}
        CC=${CMAKE_C_COMPILER} CFLAGS=${_pythonCFlags}
        python -m build
    COMMAND touch python-wheel-canary-file
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/greenaddress
    DEPENDS greenaddress-full
    COMMENT "building python-wheel"
)
add_custom_target(python-wheel
    DEPENDS python-wheel-canary-file
)

install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/greenaddress/dist/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/python
    FILES_MATCHING PATTERN *.whl
)

if(APPLE)
    return()
endif()

add_custom_command(OUTPUT python-wheel-manylinux-canary-file
    COMMAND python -m auditwheel repair `find greenaddress -name *.whl` --plat manylinux_2_31_x86_64
    COMMAND touch python-wheel-manylinux-canary-file
    WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    DEPENDS python-wheel
    COMMENT "rebranding python-wheel for manylinux platform"
)
add_custom_target(python-wheel-manylinux
    DEPENDS python-wheel-manylinux-canary-file
)
install(DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/wheelhouse/
    DESTINATION ${CMAKE_INSTALL_DATADIR}/python
    FILES_MATCHING PATTERN *.whl
)
