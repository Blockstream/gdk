#!/bin/bash
set -eo pipefail

(command -v gpg && command -v wget && command -v jq) > /dev/null \
  || { echo >&2 "This script requires gpg, wget and jq"; exit 1; }

# ThomasV's release signing key
PGPID=6694D8DE7BE8EE5631BED9502BD5824B7F9470E6
gpg --list-keys $PGPID > /dev/null || gpg --keyserver keyserver.ubuntu.com --recv-keys $PGPID

# Grab the latest release and verify it
version=`curl -s 'https://download.electrum.org/?C=M;O=D' | grep -o -E 'alt="\[DIR\]"></td><td><a href="([0-9a-z.]+)' | cut -d'"' -f4 | head -n 1`
filename=Electrum-$version.tar.gz
dir=`mktemp -d`
wget -q -P $dir https://download.electrum.org/$version/$filename{,.asc}
gpg --verify $dir/$filename.asc $dir/$filename

# Read servers.json out of the tar, filter for non-onion servers only
# and format as a newline-separated list of `host:port:proto` strings.
# Note this sets the "noverify" flag to disable SSL certificate validation.
serverlist() {
  tar -axf $dir/$filename Electrum-$version/electrum/$1 -O | jq -r 'to_entries[]
    | select(.key | endswith(".onion") | not)
    | .key + ":" + if .value.s != null then .value.s + ":s:noverify" else .value.t + ":t" end' \
  | sort
}

target=$(dirname "${BASH_SOURCE[0]}")/../src
serverlist servers.json > $target/servers-mainnet.txt
serverlist servers_testnet.json > $target/servers-testnet.txt

rm -r $dir
