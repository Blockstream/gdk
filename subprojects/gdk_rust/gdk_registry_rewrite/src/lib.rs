#![warn(missing_docs)]

//! # GDK registry
//
//! This library provides Liquid assets metadata ensuring data is verified and
//! preserving privacy. It also provides asset icons.
//!
//! A small number of assets information are hard-coded within this library,
//! others are fetched from a default "asset registry" or a user-defined one.
//!
//! The main methods are [`get_assets`] and [`refresh_assets`], but the library
//! must first be initialized by calling [`init`].
//!
//! Assets metadata are informations like the name of an asset, the ticker, and
//! the precision (decimal places of amounts) which define how wallets show
//! informations to users. It's important that these informations are presented
//! correctly so that users can make an informed decision. To ensure these
//! properties, assets metadata are committed in the assets id and verified on
//! the client, so that if the fetched informations are incorrect this library
//! will filter them out.
//!
//! Another important consideration is that access to registries is made in a
//! way that user interest in a particular asset is not revealed to preserve
//! users' privacy.

mod asset_entry;
mod error;
mod params;
mod registry_infos;

use std::path::Path;

pub use error::{Error, Result};
pub use params::{GetAssetsParams, RefreshAssetsParams};
use registry_infos::RegistryInfos;

/// Initialize the library by specifying the root directory where the cached
/// data is persisted across sessions.
pub fn init(_dir: impl AsRef<Path>) -> Result<()> {
    todo!()
}

/// Returns informations about a set of assets and related icons.
///
/// Unlike [`refresh_assets`], this function will cache the queried assets to
/// avoid performing a full registry read on evey call. The cache file stored
/// on disk is encrypted via the wallet's xpub key.
pub fn get_assets(_params: GetAssetsParams) -> Result<RegistryInfos> {
    todo!()
}

/// Returns informations about a set of assets and related icons.
///
/// Results could come from the persisted cached value when `params.refresh`
/// is `false`, or could be fetched from an asset registry when it's `true`. By
/// default, the Liquid mainnet network is used and the asset registry used is
/// managed by Blockstream and no proxy is used to access it. This default
/// configuration could be overridden by providing the `params.config`
/// parameter.
pub fn refresh_assets(_params: RefreshAssetsParams) -> Result<RegistryInfos> {
    todo!()
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
