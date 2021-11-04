#!/usr/bin/env bash
set -e

export GDK_VERSION=$1
export PYTHON_EXE=$2

export PYTHON_DESTDIR="${DESTDIR}/${MESON_INSTALL_PREFIX}"

mkdir -p $PYTHON_DESTDIR

VENV_DIR=${MESON_BUILD_ROOT}/venv
virtualenv --clear -p ${PYTHON_EXE} ${VENV_DIR}

source $VENV_DIR/bin/activate

cd $PYTHON_DESTDIR

cp -r ${MESON_BUILD_ROOT}/src/swig_python/greenaddress .

cp ${MESON_SOURCE_ROOT}/src/swig_python/setup.py .

# TODO: remove setuptools pinning once the following bug is fixed
# https://github.com/pypa/setuptools/issues/2849
pip install -U pip 'setuptools==58.4.0' wheel

pip wheel --wheel-dir=$PYTHON_DESTDIR .
virtualenv --clear -p ${PYTHON_EXE} ${MESON_BUILD_ROOT}/smoketestvenv
deactivate

source ${MESON_BUILD_ROOT}/smoketestvenv/bin/activate

pip install --find-links=. greenaddress
python -c "import greenaddress; assert len(greenaddress.get_networks()) > 0"

deactivate

rm -fr ${MESON_BUILD_ROOT}/smoketestvenv
