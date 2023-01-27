#! /usr/bin/env bash
set -e

dnf update -yq
dnf install -yq @development-tools autoconf pkg-config libtool ninja-build clang which python python3-pip libatomic curl perl-core cmake libstdc++-static
pip install --require-hashes -r /requirements.txt

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.64.0
source /root/.cargo/env
rustup component add rustfmt clippy

mkdir /tmp/protoc && \
    cd /tmp/protoc && \
    curl -Ls https://github.com/protocolbuffers/protobuf/releases/download/v3.19.3/protoc-3.19.3-linux-x86_64.zip > protoc.zip && \
    unzip protoc.zip && \
    mv /tmp/protoc/bin/protoc /usr/local/bin && \
    rm -rf /tmp/protoc

dnf clean all
rm -fr /var/cache/dnf /tmp/*
