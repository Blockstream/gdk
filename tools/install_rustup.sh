#! /usr/bin/env bash
# Install a pinned rustup + toolchain with the rustup-init binary verified
# against its published sha256, instead of `curl https://sh.rustup.rs | sh`.
# Hashes: https://static.rust-lang.org/rustup/archive/<version>/<triple>/rustup-init.sha256
set -e

RUSTUP_VERSION=1.29.1
RUST_TOOLCHAIN=1.85.0

case "$(uname -m)" in
    x86_64)  triple=x86_64-unknown-linux-gnu;  sha256=dda7234360b7f578ca8b0ddcb80145646fa61a67c1720a5abc7051b35c9fcb71 ;;
    aarch64) triple=aarch64-unknown-linux-gnu; sha256=15f6e4ce9f583b929c996c91562bad6d4454f3281de858b02cdfdef615fac433 ;;
    *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -sSL --retry 3 "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/${triple}/rustup-init" --output "$tmp/rustup-init"
echo "${sha256}  $tmp/rustup-init" | sha256sum -c
chmod +x "$tmp/rustup-init"
"$tmp/rustup-init" -y --default-toolchain "${RUST_TOOLCHAIN}"
