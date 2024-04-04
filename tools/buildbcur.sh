#! /usr/bin/env bash
set -e

cp tools/bc-ur.patch ${PRJ_SUBDIR}
cd "${PRJ_SUBDIR}"

# fixes to the src files
patch -p1 < bc-ur.patch

CONFIGURE_ARGS="--prefix=${GDK_BUILD_ROOT} --host=${target_triple}"

export CFLAGS="$CFLAGS $EXTRA_CFLAGS"
export CXXFLAGS="$CXXFLAGS $EXTRA_CXXFLAGS"
export LDFLAGS="$LDFLAGS $EXTRA_LDFLAGS"
./configure ${CONFIGURE_ARGS}

make lib
make install
