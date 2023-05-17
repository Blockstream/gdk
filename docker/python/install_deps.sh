#! /usr/bin/env bash
set -e

yum update -yqq
# cargo openssl-devel and libffi-devel needed for python's ``cryptography`` package
yum install swig perl-core autoconf libstdc++-static -yqq

python_versions=(cp38-cp38 cp39-cp39 pp39-pypy39_pp73 cp310-cp310 cp311-cp311)


/opt/python/${python_versions[0]}/bin/python -m venv /root/tmp-python-env
source /root/tmp-python-env/bin/activate
pip install virtualenv
for python_version in "${python_versions[@]}";
do
    echo "building python environment for ${python_version}"
    virtualenv -p /opt/python/$python_version/bin/python /root/python-${python_version}-venv
done
deactivate
rm -rf /root/tmp-python-env

for python_version in "${python_versions[@]}";
do
    source /root/python-${python_version}-venv/bin/activate
    pip install -r tools/requirements.txt
    deactivate
done

ln -s /root/python-${python_versions[0]}-venv /opt/python/default

yum autoremove -yqq
