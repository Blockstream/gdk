join_path(_torSrcDir ${EXTERNAL-DEPS-DIR} "tor")
join_path(_libDirCore ${_torSrcDir} "src" "core")
join_path(_libDirLib ${_torSrcDir} "src" "lib")
join_path(_libDirTrunnel ${_torSrcDir} "src" "trunnel")
join_path(_libDirDonna ${_torSrcDir} "src" "ext" "ed25519" "donna")
join_path(_libDirRef10 ${_torSrcDir} "src" "ext" "ed25519" "ref10")
join_path(_libDirKeccak ${_torSrcDir} "src" "ext" "keccak-tiny")
set(_torLibs
    ${_libDirCore}/libtor-app.a
    ${_libDirLib}/libtor-buf.a
    ${_libDirLib}/libtor-compress.a
    ${_libDirLib}/libtor-confmgt.a
    ${_libDirLib}/libtor-crypt-ops.a
    ${_libDirKeccak}/libkeccak-tiny.a
    ${_libDirDonna}/libed25519_donna.a
    ${_libDirRef10}/libed25519_ref10.a
    ${_libDirLib}/libcurve25519_donna.a
    ${_libDirLib}/libtor-ctime.a
    ${_libDirLib}/libtor-pubsub.a
    ${_libDirLib}/libtor-dispatch.a
    ${_libDirLib}/libtor-container.a
    ${_libDirLib}/libtor-encoding.a
    ${_libDirLib}/libtor-err.a
    ${_libDirLib}/libtor-evloop.a
    ${_libDirLib}/libtor-fdio.a
    ${_libDirLib}/libtor-fs.a
    ${_libDirLib}/libtor-geoip.a
    ${_libDirLib}/libtor-intmath.a
    ${_libDirLib}/libtor-lock.a
    ${_libDirLib}/libtor-log.a
    ${_libDirLib}/libtor-malloc.a
    ${_libDirLib}/libtor-math.a
    ${_libDirLib}/libtor-memarea.a
    ${_libDirLib}/libtor-meminfo.a
    ${_libDirLib}/libtor-net.a
    ${_libDirLib}/libtor-osinfo.a
    ${_libDirLib}/libtor-process.a
    ${_libDirLib}/libtor-sandbox.a
    ${_libDirLib}/libtor-smartlist-core.a
    ${_libDirLib}/libtor-string.a
    ${_libDirLib}/libtor-term.a
    ${_libDirLib}/libtor-thread.a
    ${_libDirLib}/libtor-time.a
    ${_libDirLib}/libtor-tls.a
    ${_libDirLib}/libtor-trace.a
    ${_libDirLib}/libtor-version.a
    ${_libDirLib}/libtor-wallclock.a
    ${_libDirTrunnel}/libor-trunnel.a
)

add_library(tor INTERFACE IMPORTED)
set(TOR_LIB_DIRS ${_libDirCore} ${_libDirLib} ${_libDirTrunnel} ${_libDirDonna} ${_libDirRef10} ${_libDirKeccak}) 
join_path(TOR_INCLUDE_DIRS ${_torSrcDir} "src" "feature" "api")
if (CMAKE_VERSION VERSION_LESS "3.12")
    set_target_properties(tor PROPERTIES 
        INTERFACE_INCLUDE_DIRECTORIES ${TOR_INCLUDE_DIRS}
        INTERFACE_LINK_LIBRARIES "${_torLibs}"
    )
else()
    target_include_directories(tor INTERFACE ${TOR_INCLUDE_DIRS})
    target_link_libraries(tor
        INTERFACE
            ${_torLibs}
            $<$<PLATFORM_ID:Windows>:ssp>
            $<$<PLATFORM_ID:Windows>:iphlpapi>
    )
endif()
