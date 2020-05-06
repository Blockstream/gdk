#!/bin/bash

# launch with DEBUG env equal something when debugging to see outputs

# adapt the following vars to your environment
export ELECTRS_EXEC=$HOME/git/electrs/target/release/electrs
export ELECTRS_LIQUID_EXEC=$HOME/git/electrs-blockstream/target/release/electrs 
export ELEMENTSD_EXEC=$HOME/git/elements/src/elementsd 
export BITCOIND_EXEC=bitcoind
export WALLY_DIR=$HOME/git/gdk/build-clang/libwally-core/build/lib/ 

if [[ -z "${DEBUG}" ]]; then
  NOCAPTURE=""
else
  NOCAPTURE="-- --nocapture"
fi

# delete any previoulsy launched integation test process
ps -eaf | grep -v grep | grep electrum_integration_test | awk '{print $2}' | xargs -r kill -9

# launch tests, use liquid or bitcoin as parameter to launch only the respective
cargo test $1 $NOCAPTURE
