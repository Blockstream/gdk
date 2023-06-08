#! /usr/bin/env bash
set -e

dnf update -yq
dnf install -yq @development-tools autoconf pkg-config libtool ninja-build clang which python python3-pip libatomic curl perl-core cmake libstdc++-static

pip install --require-hashes -r tools/requirements.txt

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.68.0
source /root/.cargo/env


dnf clean all
rm -fr /var/cache/dnf /tmp/*
