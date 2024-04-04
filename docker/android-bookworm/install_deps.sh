#! /usr/bin/env bash
set -e

apt update -qq
apt upgrade -yqq

apt install --no-install-recommends unzip autoconf automake autotools-dev pkg-config build-essential libtool python3{,-dev} python{,-dev}-is-python3 clang git swig openjdk-17-jdk curl cmake libssl-dev libtool-bin -yqq
update-java-alternatives -s java-1.17.0-openjdk-amd64

curl -L -o ndk.zip https://dl.google.com/android/repository/android-ndk-r26b-linux.zip
echo "ad73c0370f0b0a87d1671ed2fd5a9ac9acfd1eb5c43a7fbfbd330f85d19dd632  ndk.zip" | shasum -a 256 -c
unzip ndk.zip
rm ndk.zip


if [ -f /.dockerenv ]; then
    apt remove --purge unzip -yqq
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
