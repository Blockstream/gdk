#!/usr/bin/env bash
set -e

DEP_NAME=""
SHA_SUM=""
UNTAR_NAME=""
WRAP_NAME=""
URL=""

GETOPT='getopt'
if [ "$(uname)" == "Darwin" ]; then
    GETOPT='/usr/local/opt/gnu-getopt/bin/getopt'
fi

TEMPOPT=`"$GETOPT" -n "'upgrade_deps.sh" -o l:,s:,u: -- "$@"`
eval set -- "$TEMPOPT"
while true; do
    case "$1" in
        -l ) DEP_NAME="$2-meson"; UNTAR_NAME="$2"; WRAP_NAME="$2"; shift 2 ;;
        -s ) SHA_SUM="$2"; shift 2 ;;
        -u ) URL="$2"; shift 2 ;;
        -- ) shift; break ;;
    esac
done

TOOLS_DIR=${PWD}/tools
WRAP_DIR=${PWD}/subprojects
DEP_DIR=${WRAP_DIR}/${DEP_NAME}
TMP=$(mktemp -d)

pushd . >& /dev/null

cd ${TMP}

echo "Updating wrap definitions..."
echo "  Downloading dependency..."
curl -Lo tmp.tar.gz ${URL} >& /dev/null
SOURCE_SHA256=$(sha256sum tmp.tar.gz | cut -f 1 -d ' ')
UNTAR_DIR=$(tar ztf tmp.tar.gz | head -1 | cut -f 1 -d '/')

echo "  Generating meson build patch..."
mkdir -p ${UNTAR_DIR}
cp ${DEP_DIR}/meson.build ${UNTAR_DIR}
tar --mode=go=rX,u+rw,a-s --sort=name --owner=0 --group=0 --numeric-owner --mtime="2018-08-01 00:00Z" -cf ${DEP_NAME}.tar ${UNTAR_DIR}
PATCH_SHA256=$(sha256sum ${DEP_NAME}.tar | cut -f 1 -d ' ')

sed -i -e "s!\(source_url.*=\).*!\1 ${URL}!" ${WRAP_DIR}/${WRAP_NAME}.wrap
sed -i -e "s!\(source_hash.*=\).*!\1 ${SOURCE_SHA256}!" ${WRAP_DIR}/${WRAP_NAME}.wrap
sed -i -e "s!\(directory.*=\).*!\1 ${UNTAR_DIR}!" ${WRAP_DIR}/${WRAP_NAME}.wrap
sed -i -e "s!\(source_filename.*=\).*!\1 ${UNTAR_NAME}-${SHA_SUM}.tar.gz!" ${WRAP_DIR}/${WRAP_NAME}.wrap
sed -i -e "s!\(source_url.*archive/\).*!\1${SHA_SUM}.tar.gz!" ${WRAP_DIR}/${WRAP_NAME}.wrap
sed -i -e "s!\(patch_url.*=\).*!\1 file:./subprojects/${UNTAR_NAME}-meson/${UNTAR_NAME}-meson-${SOURCE_SHA256}.tar!" ${WRAP_DIR}/${WRAP_NAME}.wrap
sed -i -e "s!\(patch_filename.*=\).*!\1 ${UNTAR_NAME}-meson-${SOURCE_SHA256}.tar!" ${WRAP_DIR}/${WRAP_NAME}.wrap
sed -i -e "s!\(patch_hash.*=\).*!\1 ${PATCH_SHA256}!" ${WRAP_DIR}/${WRAP_NAME}.wrap

if [ "${UNTAR_NAME}" == "libwally-core" -o "${UNTAR_NAME}" == "boost" ]; then
    sed -i -e "s!\(.*_NAME=\"\).*!\1${UNTAR_DIR}\"!" ${TOOLS_DIR}/build${WRAP_NAME}.sh
fi

popd >& /dev/null
rm -rf ${TMP}

echo "Finished updating wrap definitions..."

echo "Cleaning old dependencies..."
. ./tools/clean.sh
