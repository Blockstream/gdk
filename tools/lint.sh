#!/usr/bin/env bash
set -e

if [ $(command -v cargo) ]; then
    pushd subprojects/gdk_rpc
	  cargo clippy --all
    popd
fi
