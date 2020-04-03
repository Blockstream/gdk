#! /usr/bin/env bash
set -e

apt update -qq
apt upgrade -yqq

apt install wget unzip autoconf automake autotools-dev pkg-config build-essential libtool virtualenv python3-{pip,yaml} ninja-build clang{,-format,-tidy} llvm-dev git swig openjdk-11-jdk g++-mingw-w64-x86-64 curl bsdmainutils -yqq
update-java-alternatives -s java-1.11.0-openjdk-amd64
pip3 install --require-hashes -r /requirements.txt
rm /requirements.txt

wget -q -O ndk.zip https://dl.google.com/android/repository/android-ndk-r21-linux-x86_64.zip
echo "b65ea2d5c5b68fb603626adcbcea6e4d12c68eb8a73e373bbb9d23c252fc647b ndk.zip" | sha256sum --check
unzip ndk.zip
rm ndk.zip

curl https://sh.rustup.rs -sSf | sh -s -- -y --default-toolchain 1.42.0

source /root/.cargo/env
rustup component add rustfmt clippy
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android x86_64-pc-windows-gnu

if [ -f /.dockerenv ]; then
    apt remove --purge unzip -yqq
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
