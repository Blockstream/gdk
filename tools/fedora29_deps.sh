#! /usr/bin/env bash
set -e

dnf update -yq
dnf install -yq @development-tools wget autoconf pkg-config libtool ninja-build clang which python2 libatomic python3-{devel,virtualenv,wheel} swig
pip3 install --require-hashes -r /requirements.txt

dnf clean all
rm -fr /var/cache/dnf /tmp/*
