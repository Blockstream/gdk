#! /usr/bin/env bash
set -e

apt update -qq
apt upgrade -yqq

apt install --no-install-recommends unzip autoconf automake autotools-dev pkg-config build-essential libtool python3{,-dev,-pip,-virtualenv} python{,-dev}-is-python3 ninja-build clang{,-format,-tidy} git swig openjdk-11-jdk g++-mingw-w64-x86-64 curl -yqq
update-java-alternatives -s java-1.11.0-openjdk-amd64
pip3 install --require-hashes -r /requirements.txt
rm /requirements.txt

curl -L -o ndk.zip https://dl.google.com/android/repository/android-ndk-r23b-linux.zip
echo "c6e97f9c8cfe5b7be0a9e6c15af8e7a179475b7ded23e2d1c1fa0945d6fb4382 ndk.zip" | sha256sum --check
unzip ndk.zip
rm ndk.zip

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.56.0

source /root/.cargo/env
rustup component add rustfmt clippy
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android x86_64-pc-windows-gnu

if [ -f /.dockerenv ]; then
    apt remove --purge unzip -yqq
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
