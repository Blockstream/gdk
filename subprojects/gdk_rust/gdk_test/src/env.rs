//! Contains the bindings to the various environment variables needed to run
//! the integration tests.

use gdk_common::once_cell::sync::Lazy;
use std::env;

/// Environment variable pointing to the `bitcoind` executable.
pub(crate) const BITCOIND_EXEC: Lazy<String> = Lazy::new(|| env::var("BITCOIND_EXEC").unwrap());

/// Environment variable pointing to the `electrs` executable.
pub(crate) const ELECTRS_EXEC: Lazy<String> = Lazy::new(|| env::var("ELECTRS_EXEC").unwrap());
