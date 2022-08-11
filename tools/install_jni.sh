#!/usr/bin/env bash
set -e

JAVA_DESTDIR="${DESTDIR}/${MESON_INSTALL_PREFIX}/java"
mkdir -p ${JAVA_DESTDIR}/com/blockstream/{libwally,libgreenaddress}
cp ${MESON_BUILD_ROOT}/external_deps/libwally-core/src/swig_java/src/com/blockstream/libwally/Wally.java $JAVA_DESTDIR/com/blockstream/libwally
cp ${MESON_BUILD_ROOT}/src/swig_java/com/blockstream/libgreenaddress/GDK.java $JAVA_DESTDIR/com/blockstream/libgreenaddress
