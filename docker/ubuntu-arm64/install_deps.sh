#! /usr/bin/env bash
set -e

apt update -qq
DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata

apt install --no-install-recommends unzip autoconf automake autotools-dev pkg-config build-essential libtool python3{,-dev,-pip,-virtualenv,-venv} python{,-dev}-is-python3 git swig openjdk-11-jdk cmake libssl-dev libtool-bin curl -yqq
pip3 install --require-hashes -r ./tools/requirements.txt
pip3 install build

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.81.0
source /root/.cargo/env


if [ -f /.dockerenv ]; then
    apt remove --purge unzip -yqq
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
