#! /usr/bin/env bash
set -e

yum update -y -q
yum install -y -q @development-tools autoconf pkgconfig libtool clang which python python3-pip libatomic curl perl-core libstdc++-static xz gzip git make patch swig

# We need a more recent cmake than the one in the distro repos
curl -sL --retry 3 https://github.com/Kitware/CMake/releases/download/v3.18.5/cmake-3.18.5-Linux-x86_64.sh --output cmake.sh
chmod +x cmake.sh
./cmake.sh --skip-license --exclude-subdir --prefix=/usr/local/

pip install --require-hashes -r tools/requirements.txt

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.85.0
source /root/.cargo/env
