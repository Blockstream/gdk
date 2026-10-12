#! /usr/bin/env bash
set -e

dnf update -yq
dnf install -yq @development-tools autoconf pkg-config libtool clang which python python39 libatomic curl perl-core cmake libstdc++-static xz

./tools/install_uv.sh python3.9
uv venv --python python3.9 /root/venv
uv pip install --python /root/venv --require-hashes -r tools/requirements.txt

./tools/install_rustup.sh
source /root/.cargo/env


dnf clean all
rm -fr /var/cache/dnf /tmp/*
