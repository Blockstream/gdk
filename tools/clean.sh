#!/usr/bin/env bash
set -e

clean_meson() {
  find subprojects/ -mindepth 2 -maxdepth 2 -name '*meson*' -not -name '*build*' | xargs rm -rf --
}

if [ "$1" == "meson" ]; then
  clean_meson
else
  rm -fr build-*
  clean_meson
  find subprojects/ -maxdepth 1 -mindepth 1 -not -name '*meson*' -not -name '*wrap*' | xargs rm -rf --
fi

rm -rf docs/build docs/source/session.rst
rm -rf .venv
