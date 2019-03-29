#!/usr/bin/env bash
set -e

clean_meson() {
  find subprojects/ -mindepth 2 -maxdepth 2 -not -path '*-meson*' -name '*meson*' | xargs rm -rf --
}

if [ "$1" = "meson" ]; then
  clean_meson
elif [ "$1" = "dirs" ]; then
  find subprojects/ -mindepth 1 -maxdepth 1 -not -path '*-meson*' -not -name '*wrap*' -not -name '*packagecache*' | xargs rm -rf --
  find subprojects/packagecache/ -name '*meson*.tar' | xargs rm -rf --
else
  rm -fr build-*
  clean_meson
  find subprojects/ -maxdepth 1 -mindepth 1 -not -name '*meson*' -not -name '*wrap*' | xargs rm -rf --
fi

rm -rf docs/build docs/source/session.rst
rm -rf .venv
