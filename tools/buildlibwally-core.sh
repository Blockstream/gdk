#! /usr/bin/env bash
set -e

cd ${WALLYCORE_SRCDIR}
rm -rf src/secp256k1
git clone ${SECP_URL} src/secp256k1
cd src/secp256k1
git checkout ${SECP_COMMIT}
cd ${WALLYCORE_SRCDIR}
touch .${SECP_COMMIT}

./tools/cleanup.sh
./tools/autogen.sh

${SED} -i 's/\"wallycore\"/\"green_gdk\"/' src/swig_java/swig.i

CONFIGURE_ARGS="--prefix=${GDK_BUILD_ROOT} --enable-static --disable-shared --disable-tests --disable-swig-python"

if [ "${BUILDTYPE}" = "debug" ]; then
    CONFIGURE_ARGS+=" --enable-debug"
fi

case ${target_triple} in
    *-apple-ios | *-apple-iossimulator)
        CONFIGURE_ARGS+=" --disable-swig-java --with-sysroot=${SDK_SYSROOT} --host=${target_triple} --build=${host_triple}"
        ;;

    *-linux-android)
        CONFIGURE_ARGS+=" --with-sysroot=${SDK_SYSROOT} --enable-swig-java --host=${target_triple} --build=${host_triple}"
        ;;

    *-w64-mingw32)
        CONFIGURE_ARGS+=" --disable-swig-java --host=${target_triple} --build=${host_triple}"
        ;;
    *-apple-darwin)
        CFLAGS+=" -I${JAVA_HOME}/include -I${JAVA_HOME}/include/darwin"
        ;&
    *)
        if [ -n "${JAVA_HOME}" ]; then
            CONFIGURE_ARGS+=" --enable-swig-java"
        else
            CONFIGURE_ARGS+=" --disable-swig-java"
        fi
        ;;
esac


./configure ${CONFIGURE_ARGS}
make clean -k || echo >/dev/null
make -j${NUM_JOBS}
make -o configure install -j${NUM_JOBS}


# FIXME: work around wally not installing its Java wrapper
java_wally="src/swig_java/src/com/blockstream/libwally/Wally.java"
if [[ -f ${java_wally} ]]; then
    dest_dir="${GDK_BUILD_ROOT}/share/java/com/blockstream/libwally"
    mkdir -p ${dest_dir}
    cp ${java_wally} ${dest_dir}
fi
