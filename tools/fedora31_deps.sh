#! /usr/bin/env bash
set -e

dnf update -yq
dnf install -yq @development-tools autoconf pkg-config libtool ninja-build clang which python python3-pip libatomic curl perl-core
pip install --require-hashes -r /requirements.txt

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.56.0
source /root/.cargo/env
rustup component add rustfmt clippy

dnf clean all
rm -fr /var/cache/dnf /tmp/*
