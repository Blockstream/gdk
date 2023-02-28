#! /usr/bin/env bash
set -e

cd "${PRJ_SUBDIR}"

CONFIGURE_ARGS="--prefix=${GDK_BUILD_ROOT}/sqlite/build 
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

if [[ "$1" == "--ndk" ]]; then

    source ${GDK_SOURCE_ROOT}/tools/env.sh
    export CFLAGS="$CFLAGS $EXTRA_FLAGS"
    export LDFLAGS="$LDFLAGS $EXTRA_FLAGS"
    ./configure --host=${NDK_TARGET_HOST} ${CONFIGURE_ARGS}

elif [[ "$1" == "--windows" ]]; then

    export CC=x86_64-w64-mingw32-gcc-posix
    export CXX=x86_64-w64-mingw32-g++-posix
    ./configure --host=x86_64-w64-mingw32 --build=${HOST_OS} ${CONFIGURE_ARGS}

elif [[ "$1" == "--iphone" ]] || [[ "$1" == "--iphonesim" ]]; then

    source ${GDK_SOURCE_ROOT}/tools/ios_env.sh $1
    export CFLAGS="$IOS_CFLAGS $EXTRA_FLAGS"
    export LDFLAGS="$IOS_LDFLAGS $EXTRA_FLAGS"
    export CC=${XCODE_DEFAULT_PATH}/clang
    export CXX=${XCODE_DEFAULT_PATH}/clang++
    ./configure --host=arm-apple-darwin --with-sysroot=${IOS_SDK_PATH} ${CONFIGURE_ARGS}

elif [[ "$1" == "--clang" ]]; then

    export CFLAGS="$SDK_CFLAGS $EXTRA_FLAGS -DSQLITE_USE_ALLOCA=1"
    export LDFLAGS="$SDK_LDFLAGS $EXTRA_FLAGS"
    ./configure ${CONFIGURE_ARGS}

else
    export CFLAGS="$SDK_CFLAGS $EXTRA_FLAGS"
    export LDFLAGS="$SDK_LDFLAGS $EXTRA_FLAGS"
    ./configure ${CONFIGURE_ARGS}

fi

make libsqlite3.la -j${NUM_JOBS}
make install-data
make install-libLTLIBRARIES
