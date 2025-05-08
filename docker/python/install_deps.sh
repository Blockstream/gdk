#! /usr/bin/env bash
set -e

dnf upgrade almalinux-release -y
yum update -yqq
yum install -yqq swig perl-core autoconf libstdc++-static clang

python_versions=(cp39-cp39 cp310-cp310 cp311-cp311)


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
