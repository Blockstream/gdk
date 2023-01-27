#! /usr/bin/env bash
set -e

apt update -qq
apt upgrade -yqq

apt install curl autoconf pkg-config build-essential libtool libtool-bin virtualenv python3-{pip,yaml,-venv} ninja-build clang llvm-dev git swig unzip cmake patchelf -yqq
pip3 install --require-hashes -r /requirements.txt
rm /requirements.txt

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.64.0
source /root/.cargo/env
rustup component add rustfmt clippy

mkdir /tmp/protoc && \
    cd /tmp/protoc && \
    curl -Ls https://github.com/protocolbuffers/protobuf/releases/download/v3.19.3/protoc-3.19.3-linux-x86_64.zip > protoc.zip && \
    unzip protoc.zip && \
    mv /tmp/protoc/bin/protoc /usr/local/bin && \
    rm -rf /tmp/protoc

if [ -f /.dockerenv ]; then
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
