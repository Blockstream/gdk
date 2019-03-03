#! /usr/bin/env bash
set -e

apt update -qq
apt upgrade -yqq

apt install wget unzip autoconf pkg-config build-essential libtool virtualenv python3-pip ninja-build clang clang-tidy llvm-dev git swig openjdk-8-jdk g++-mingw-w64-x86-64 -yqq
update-java-alternatives -s java-1.8.0-openjdk-amd64
pip3 install --require-hashes -r /requirements.txt
rm /requirements.txt

wget -q -O ndk.zip https://dl.google.com/android/repository/android-ndk-r19b-linux-x86_64.zip
echo "0fbb1645d0f1de4dde90a4ff79ca5ec4899c835e729d692f433fda501623257a ndk.zip" | sha256sum --check
unzip ndk.zip
rm ndk.zip

CLANG_FORMAT_VERSION=6.0.0
CLANG_PACKAGE_NAME=clang+llvm-${CLANG_FORMAT_VERSION}-x86_64-linux-gnu-debian8
wget -q -O clang.tar.xz http://releases.llvm.org/${CLANG_FORMAT_VERSION}/${CLANG_PACKAGE_NAME}.tar.xz
echo "ff55cd0bdd0b67e22d1feee2e4c84dedc3bb053401330b64c7f6ac18e88a71f1 clang.tar.xz" | sha256sum --check
tar -xf clang.tar.xz
rm clang.tar.xz
cp ${CLANG_PACKAGE_NAME}/bin/clang-{tidy,format} /usr/local/bin

if [ -f /.dockerenv ]; then
    apt remove --purge unzip -yqq
    apt -yqq autoremove
    apt -yqq clean
    rm -rf /var/lib/apt/lists/* /var/cache/* /tmp/* /usr/share/locale/* /usr/share/man /usr/share/doc /lib/xtables/libip6* /root/.cache
fi
