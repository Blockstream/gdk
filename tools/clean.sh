#!/usr/bin/env bash
set -e

clean_meson() {
  find subprojects/ -mindepth 2 -maxdepth 2 -not -path '*-meson*' -name '*meson*' -not -path '*gdk_rust*' | xargs rm -rf --
}

SHARED_CLEAN=(-mindepth 1 -maxdepth 1 -not -name '*gdk_rust*' -not -path '*-meson*' -not -name '*wrap*')

if [ "$1" = "meson" ]; then
  clean_meson
elif [ "$1" = "dirs" ]; then
  find subprojects/ "${SHARED_CLEAN[@]}" -not -name '*packagecache*'  | xargs rm -rf --
  find subprojects/packagecache/ -name '*meson*.tar' | xargs rm -rf --
elif [ "$1" = "all" ]; then
  # Clean everything, including the downloaded package tars
  rm -fr build-*
  clean_meson
  find subprojects/ -maxdepth 1 -mindepth 1 -not -name '*meson*' -not -name '*wrap*' | xargs rm -rf --
else
  # By default clean everything except the downloaded package tars
  rm -fr build-*
  clean_meson
  find subprojects/ -mindepth 1 -maxdepth 1 -not -path '*-meson*' -not -name '*wrap*' -not -name '*packagecache*' | xargs rm -rf --
  find subprojects/packagecache/ -name '*meson*.tar' | xargs rm -rf --
fi

rm -rf docs/build docs/source/session.rst
rm -rf .venv
