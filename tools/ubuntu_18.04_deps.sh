#! /usr/bin/env bash
set -e

apt update -qq
apt upgrade -yqq

apt install curl autoconf pkg-config build-essential libtool virtualenv python3-{pip,yaml} ninja-build clang llvm-dev git swig -yqq
pip3 install --require-hashes -r /requirements.txt
rm /requirements.txt

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.56.0
source /root/.cargo/env
rustup component add rustfmt clippy

if [ -f /.dockerenv ]; then
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
