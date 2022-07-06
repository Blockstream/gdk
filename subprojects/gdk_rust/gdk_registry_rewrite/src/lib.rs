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
mod assets_or_icons;
mod cache;
mod error;
mod file;
mod hard_coded;
mod http;
mod params;
mod registry;
mod registry_infos;
mod value_modified;

use std::path::Path;

use cache::Cache;
use registry_infos::{RegistryAssets, RegistryInfos};

pub use error::{Error, Result};
pub use params::{GetAssetsParams, RefreshAssetsParams};

/// Initialize the library by specifying the root directory where the cached
/// data is persisted across sessions.
pub fn init(dir: impl AsRef<Path>) -> Result<()> {
    registry::init(&dir)?;
    cache::init(&dir)
}

/// Returns informations about a set of assets and related icons.
///
/// Unlike [`refresh_assets`], this function will cache the queried assets to
/// avoid performing a full registry read on evey call. The cache file stored
/// on disk is encrypted via the wallet's xpub key.
pub fn get_assets(params: GetAssetsParams) -> Result<RegistryInfos> {
    let (assets_id, xpub, config) = params.explode();

    let mut cache = Cache::from_xpub(xpub)?;

    log::debug!("`get_assets` using cache {:?}", cache);

    let (mut cached, mut not_cached): (Vec<_>, Vec<_>) =
        assets_id.into_iter().partition(|id| cache.is_cached(id));

    // Remove all the ids known not to be in the registry to avoid retriggering
    // a registry read.
    not_cached.retain(|id| !cache.is_missing(id));

    if not_cached.is_empty() {
        cache.filter(&cached);
        return Ok(cache.into());
    }

    log::debug!("{:?} are not already cached", not_cached);

    let params = RefreshAssetsParams::new(true, true, false, config);
    let registry = self::refresh_assets(params)?;

    let (in_registry, not_on_disk): (Vec<_>, Vec<_>) = not_cached
        .into_iter()
        .partition(|id| registry.contains(&id));

    if !in_registry.is_empty() {
        log::debug!("{:?} found in the local asset registry", in_registry);
        cache.extend_from_registry(registry, &in_registry);
        cache.update()?;
        cached.extend(in_registry);
    }

    if !not_on_disk.is_empty() {
        log::debug!("{:?} are not in the local asset registry", not_on_disk);
        cache.register_missing(not_on_disk);
        cache.update()?;
    }

    cache.filter(&cached);
    Ok(cache.into())
}

/// Returns informations about a set of assets and related icons.
///
/// Results could come from the persisted cached value when `params.refresh`
/// is `false`, or could be fetched from an asset registry when it's `true`. By
/// default, the Liquid mainnet network is used and the asset registry used is
/// managed by Blockstream and no proxy is used to access it. This default
/// configuration could be overridden by providing the `params.config`
/// parameter.
pub fn refresh_assets(params: RefreshAssetsParams) -> Result<RegistryInfos> {
    if !params.wants_something() {
        return Err(Error::BothAssetsIconsFalse);
    }

    let assets = params
        .wants_assets()
        .then(|| {
            let assets = registry::get_assets(&params)?;

            let (ok, wrong): (RegistryAssets, _) = assets
                .into_iter()
                .partition(|(_, entry)| entry.verifies().unwrap_or(false));

            if !wrong.is_empty() {
                log::warn!("{} assets didn't verify!", wrong.len());
            }

            if params.should_refresh() {
                // TODO: update cache misses
            }

            Ok::<_, Error>(ok)
        })
        .transpose()?
        .unwrap_or_default();

    let icons = params
        .wants_icons()
        .then(|| registry::get_icons(&params))
        .transpose()?
        .unwrap_or_default();

    Ok(RegistryInfos::new(assets, icons))
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
