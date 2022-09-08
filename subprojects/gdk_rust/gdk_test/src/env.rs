//! Contains the bindings to the various environment variables needed to run
//! the integration tests.

/// Environment variable pointing to the directory containing the compiled
/// static libraries of [libwally] and [secp].
///
/// [libwally]: https://github.com/ElementsProject/libwally-core
/// [secp]: https://github.com/ElementsProject/secp256k1-zkp
#[allow(unused)]
pub(crate) const WALLY_DIR: &str = env!("WALLY_DIR");

/// Environment variable pointing to the `bitcoind` executable.
pub(crate) const BITCOIND_EXEC: &str = env!("BITCOIND_EXEC");

/// Environment variable pointing to the `elementsd` executable.
pub(crate) const ELEMENTSD_EXEC: &str = env!("ELEMENTSD_EXEC");

/// Environment variable pointing to the `electrs` executable.
pub(crate) const ELECTRS_EXEC: &str = env!("ELECTRS_EXEC");

/// Environment variable pointing to the `electrs` executable (for Liquid).
pub(crate) const ELECTRS_LIQUID_EXEC: &str = env!("ELECTRS_LIQUID_EXEC");
