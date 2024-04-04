#! /usr/bin/env bash
set -e

cd "${PRJ_SUBDIR}"

CONFIGURE_ARGS="--prefix=${GDK_BUILD_ROOT} \
    --enable-static --disable-shared --disable-static-shell \
    --enable-threadsafe --disable-dynamic-extensions \
    --disable-editline --disable-readline --with-pic \
    --disable-fts3 --disable-fts4 --disable-fts5 \
    --disable-rtree"
EXTRA_FLAGS="-DSQLITE_OMIT_DEPRECATED=1 \
    -DSQLITE_DQS=0 \
    -DSQLITE_DEFAULT_MEMSTATUS=0 \
    -DSQLITE_DEFAULT_AUTOVACUUM=0 \
    -DSQLITE_OMIT_AUTOVACUUM=1 \
    -DSQLITE_DEFAULT_SYNCHRONOUS=0 \
    -DSQLITE_DEFAULT_WAL_SYNCHRONOUS=1 \
    -DSQLITE_LIKE_DOESNT_MATCH_BLOBS=1 \
    -DSQLITE_MAX_EXPR_DEPTH=0 \
    -DSQLITE_OMIT_DECLTYPE=1 \
    -DSQLITE_OMIT_PROGRESS_CALLBACK=1 \
    -DSQLITE_OMIT_SHARED_CACHE=1 \
    -DSQLITE_DEFAULT_AUTOMATIC_INDEX=0 \
    -DSQLITE_OMIT_BLOB_LITERAL=1 \
    -DSQLITE_OMIT_COMPLETE=1 \
    -DSQLITE_OMIT_GET_TABLE=1 \
    -DSQLITE_OMIT_INCRBLOB=1 \
    -DSQLITE_OMIT_LIKE_OPTIMIZATION=1 \
    -DSQLITE_OMIT_LOAD_EXTENSION=1 \
    -DSQLITE_OMIT_OR_OPTIMIZATION=1 \
    -DSQLITE_OMIT_TCL_VARIABLE=1 \
    -DSQLITE_OMIT_TEMPDB=1 \
    -DSQLITE_OMIT_TRACE=1 \
    -DSQLITE_OMIT_UTF16=1 \
    -DSQLITE_OMIT_WAL=1 \
    -DSQLITE_TEMP_STORE=3 \
    -DSQLITE_ENABLE_API_ARMOR=1 \
    -DSQLITE_OMIT_AUTHORIZATION=1 \
    -DSQLITE_OMIT_AUTOINCREMENT=1 \
    -DSQLITE_OMIT_JSON=1 \
    -DSQLITE_OMIT_DATETIME_FUNCS=1 \
    -DSQLITE_OMIT_DECLTYPE=1 \
    -DSQLITE_OMIT_CAST=1 \
    -DSQLITE_OMIT_CASE_SENSITIVE_LIKE_PRAGMA=1 \
    -DSQLITE_OMIT_BETWEEN_OPTIMIZATION=1"

if [[ ${BUILDTYPE} == "debug" ]]; then
    CONFIGURE_ARGS="${CONFIGURE_ARGS} --enable-debug"
else
    CONFIGURE_ARGS="${CONFIGURE_ARGS} --disable-debug"
fi

case $target_triple in
    *-linux-android)
        CONFIGURE_ARGS+=" --host=${target_triple} --build=${host_triple}"
        ;;

    *-apple-ios | *-apple-iossimulator)
        CONFIGURE_ARGS+=" --host=${target_triple} --build=${host_triple}"
        ;;

    *-w64-mingw32)
        CONFIGURE_ARGS+=" --host=${target_triple} --build=${host_triple}"
        ;;

esac


CFLAGS+=" ${EXTRA_FLAGS}"
LDFLAGS+=" ${EXTRA_FLAGS}"

./configure ${CONFIGURE_ARGS}
make libsqlite3.la -j${NUM_JOBS}
make install-data
make install-libLTLIBRARIES
