//! Contains the bindings to the various environment variables needed to run
//! the integration tests.

use gdk_common::once_cell::sync::Lazy;
use std::env;

/// Environment variable pointing to the directory containing the compiled
/// static libraries of [libwally] and [secp].
///
/// [libwally]: https://github.com/ElementsProject/libwally-core
/// [secp]: https://github.com/ElementsProject/secp256k1-zkp
#[allow(unused)]
pub(crate) const WALLY_DIR: Lazy<String> = Lazy::new(|| env::var("WALLY_DIR").unwrap());

/// Environment variable pointing to the `bitcoind` executable.
pub(crate) const BITCOIND_EXEC: Lazy<String> = Lazy::new(|| env::var("BITCOIND_EXEC").unwrap());

/// Environment variable pointing to the `elementsd` executable.
pub(crate) const ELEMENTSD_EXEC: Lazy<String> = Lazy::new(|| env::var("ELEMENTSD_EXEC").unwrap());

/// Environment variable pointing to the `electrs` executable.
pub(crate) const ELECTRS_EXEC: Lazy<String> = Lazy::new(|| env::var("ELECTRS_EXEC").unwrap());

/// Environment variable pointing to the `electrs` executable (for Liquid).
pub(crate) const ELECTRS_LIQUID_EXEC: Lazy<String> =
    Lazy::new(|| env::var("ELECTRS_LIQUID_EXEC").unwrap());
