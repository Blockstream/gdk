#!/bin/bash

# launch with DEBUG env equal something when debugging to see outputs

# use externally defined env vars or the following defaults
export ELECTRS_EXEC=${ELECTRS_EXEC:=$HOME/git/electrs/target/release/electrs}
export ELECTRS_LIQUID_EXEC=${ELECTRS_LIQUID_EXEC:=$HOME/git/electrs-blockstream/target/release/electrs}
export ELEMENTSD_EXEC=${ELEMENTSD_EXEC:=$HOME/git/elements/src/elementsd}
export BITCOIND_EXEC=${BITCOIND_EXEC:=$HOME/git/bitcoind/src/bitcoind}
export WALLY_DIR=${WALLY_DIR:=$HOME/git/gdk/build-clang/libwally-core/build/lib/}

if [[ -z "${DEBUG}" ]]; then
  NOCAPTURE=""
else
  NOCAPTURE="-- --nocapture"
fi

# delete any previoulsy launched integation test process
ps -eaf | grep -v grep | grep electrum_integration_test | awk '{print $2}' | xargs -r kill -9

# launch tests, use liquid or bitcoin as parameter to launch only the respective
RUST_BACKTRACE=1 cargo test $1 $NOCAPTURE
