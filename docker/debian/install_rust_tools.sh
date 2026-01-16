#! /usr/bin/env bash
set -e

rustup component add rustfmt clippy llvm-tools-preview
rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android x86_64-pc-windows-gnu
cargo install --locked --version 0.22.0 cargo-audit
cargo install --locked --version 0.8.24 grcov
cargo install --locked --version 0.9.55 cargo-nextest
