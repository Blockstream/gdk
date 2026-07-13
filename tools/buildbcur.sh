#! /usr/bin/env bash
set -e

cp tools/bc-ur.patch ${PRJ_SUBDIR}
cd "${PRJ_SUBDIR}"

# fixes to the src files
patch -p1 < bc-ur.patch

AUTOCONF_HOST="${target_triple}"
if [ "${AUTOCONF_HOST}" = "arm64-apple-darwin" ]; then
	AUTOCONF_HOST="aarch64-apple-darwin"
fi

CONFIGURE_ARGS="--prefix=${GDK_BUILD_ROOT} --host=${AUTOCONF_HOST}"
if [ "${target_triple}" != "${host_triple}" ]; then
	CONFIGURE_ARGS+=" --build=${host_triple}"
fi

export CFLAGS="$CFLAGS $EXTRA_CFLAGS"
export CXXFLAGS="$CXXFLAGS $EXTRA_CXXFLAGS"
export LDFLAGS="$LDFLAGS $EXTRA_LDFLAGS"
./configure ${CONFIGURE_ARGS} ${CONFIGURE_LIBDIR_ARG}

make lib
make install
