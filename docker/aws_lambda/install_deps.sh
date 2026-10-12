#! /usr/bin/env bash
set -e

yum update -y -q
yum install -y -q @development-tools autoconf pkgconfig libtool clang which python python3-pip libatomic curl perl-core libstdc++-static xz gzip git make patch swig

# We need a more recent cmake than the one in the distro repos
curl -sL --retry 3 https://github.com/Kitware/CMake/releases/download/v3.18.5/cmake-3.18.5-Linux-x86_64.sh --output cmake.sh
echo "722d0e64209b8011a60571d94a6fabf59266a8fcd7f8ded98a89dc20eead15f6  cmake.sh" | sha256sum -c
chmod +x cmake.sh
./cmake.sh --skip-license --exclude-subdir --prefix=/usr/local/

./tools/install_uv.sh
uv venv --python python3 /root/venv
uv pip install --python /root/venv --require-hashes -r tools/requirements.txt

./tools/install_rustup.sh
source /root/.cargo/env
