#!/usr/bin/env bash
set -e

clean_meson() {
  find subprojects/ -mindepth 2 -maxdepth 2 -not -path '*-meson*' -name '*meson*' -not -path '*gdk_rpc*' | xargs rm -rf --
}

SHARED_CLEAN=(-mindepth 1 -maxdepth 1 -not -name '*gdk_rpc*' -not -path '*-meson*' -not -name '*wrap*')

if [ "$1" = "meson" ]; then
  clean_meson
elif [ "$1" = "dirs" ]; then
  find subprojects/ "${SHARED_CLEAN[@]}" -not -name '*packagecache*'  | xargs rm -rf --
  find subprojects/packagecache/ -name '*meson*.tar' | xargs rm -rf --
else
  rm -fr build-*
  clean_meson
  find subprojects/ "${SHARED_CLEAN[@]}" | xargs rm -rf --
fi

rm -rf docs/build docs/source/session.rst
rm -rf .venv
