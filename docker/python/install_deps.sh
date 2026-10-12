#! /usr/bin/env bash
set -e

dnf upgrade almalinux-release -y
yum update -yqq
yum install -yqq swig perl-core autoconf libstdc++-static clang

python_versions=(cp39-cp39 cp310-cp310 cp311-cp311 cp312-cp312 cp313-cp313 cp314-cp314)


./tools/install_uv.sh /opt/python/${python_versions[0]}/bin/python
for python_version in "${python_versions[@]}";
do
    echo "building python environment for ${python_version}"
    uv venv --python /opt/python/$python_version/bin/python /root/python-${python_version}-venv
done

for python_version in "${python_versions[@]}";
do
    source /root/python-${python_version}-venv/bin/activate
    uv pip install --require-hashes -r tools/requirements.txt
    deactivate
done

ln -s /root/python-${python_versions[0]}-venv /opt/python/default

yum autoremove -yqq
