#! /usr/bin/env bash
set -e

apt update -qq
DEBIAN_FRONTEND=noninteractive TZ=Etc/UTC apt-get -y install tzdata

apt install --no-install-recommends unzip autoconf automake autotools-dev pkg-config build-essential libtool python3.9{,-dev,-venv} python{,-dev}-is-python3 git swig openjdk-21-jdk cmake libssl-dev libtool-bin curl ca-certificates -yqq
./tools/install_uv.sh python3.9
uv venv --python python3.9 /root/venv
uv pip install --python /root/venv --require-hashes -r tools/requirements.txt

./tools/install_rustup.sh
source /root/.cargo/env


if [ -f /.dockerenv ]; then
    apt remove --purge unzip -yqq
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
