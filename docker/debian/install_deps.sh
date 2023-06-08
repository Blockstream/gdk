#! /usr/bin/env bash
set -e

apt update -qq
apt upgrade -yqq

apt install --no-install-recommends autoconf automake autotools-dev pkg-config build-essential libtool python3{,-dev,-pip,-virtualenv} python{,-dev}-is-python3 ninja-build clang{,-format,-tidy} git swig g++-mingw-w64-x86-64 curl cmake libssl-dev libtool-bin patchelf -yqq
pip3 install --require-hashes -r tools/requirements.txt


if [ -f /.dockerenv ]; then
    apt remove --purge unzip -yqq
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
