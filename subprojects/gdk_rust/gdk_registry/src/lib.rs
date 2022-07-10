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
use std::sync::Arc;
use std::thread;

use cache::Cache;
use registry_infos::RegistrySource;

pub use asset_entry::AssetEntry;
pub use error::{Error, Result};
pub use hard_coded::policy_asset_id;
pub use params::{Config, ElementsNetwork, GetAssetsParams, RefreshAssetsParams};
pub use registry_infos::RegistryInfos;

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
    let GetAssetsParams {
        assets_id,
        xpub,
        config,
    } = params;

    let mut cache = Cache::from_xpub(xpub)?;

    log::debug!("`get_assets` using cache {:?}", cache);

    let (mut cached, mut not_cached): (Vec<_>, Vec<_>) =
        assets_id.into_iter().partition(|id| cache.is_cached(id));

    // Remove all the ids known not to be in the registry to avoid retriggering
    // a registry read.
    not_cached.retain(|id| !cache.is_missing(id));

    if not_cached.is_empty() {
        cache.filter(&cached);
        return Ok(cache.to_registry(true));
    }

    log::debug!("{:?} are not already cached", not_cached);

    let params = RefreshAssetsParams::new(true, true, false, config);
    let registry = self::refresh_assets(params)?;

    // The returned infos are marked as being from the registry if at least one
    // of the returned assets is from the full asset registry.
    let mut from_cache = true;

    let (in_registry, not_on_disk): (Vec<_>, Vec<_>) =
        not_cached.into_iter().partition(|id| registry.contains(&id));

    if !in_registry.is_empty() {
        log::debug!("{:?} found in the local asset registry", in_registry);
        cache.extend_from_registry(registry, &in_registry);
        cache.update()?;
        cached.extend(in_registry);
        from_cache = false;
    }

    if !not_on_disk.is_empty() {
        log::debug!("{:?} are not in the local asset registry", not_on_disk);
        cache.register_missing(not_on_disk);
        cache.update()?;
    }

    cache.filter(&cached);
    Ok(cache.to_registry(from_cache))
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

    let params = Arc::new(params);

    let assets_handle = {
        let params = Arc::clone(&params);
        thread::spawn(move || {
            params
                .wants_assets()
                .then(|| registry::get_assets(&params))
                .transpose()
                .map(Option::unwrap_or_default)
        })
    };

    let (icons, icons_source) = params
        .wants_icons()
        // forces multiline formatting
        .then(|| registry::get_icons(&params))
        .transpose()?
        .unwrap_or_default();

    let (assets, assets_source) = assets_handle.join().unwrap()?;

    let source = assets_source.merge(icons_source);

    Ok(RegistryInfos::new_with_source(assets, icons, source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets_or_icons::AssetsOrIcons;
    use crate::hard_coded;
    use crate::params::ElementsNetwork;
    use bitcoin::util::bip32::ExtendedPubKey;
    use log::info;
    use serde_json::Value;
    use std::path::Path;
    use std::str::FromStr;
    use tempfile::TempDir;

    /// Shadows `crate::inner::init`, mapping `Error::AlreadyInitialized` to
    /// `Ok(())` to avoid having a test fail only because some other test has
    /// already called the init function.
    fn init(dir: impl AsRef<Path>) -> Result<()> {
        match super::init(dir) {
            Err(Error::AlreadyInitialized) => Ok(()),
            other => other,
        }
    }

    #[test]
    // TODO: use httptest
    fn test_registry_prod() {
        let _ = env_logger::try_init();

        let policy_asset = policy_asset_id(ElementsNetwork::Liquid);
        let temp_dir = TempDir::new().unwrap();
        info!("{:?}", temp_dir);
        init(&temp_dir).unwrap();

        let r = |refresh, assets, icons| {
            refresh_assets(RefreshAssetsParams::new(assets, icons, refresh, Default::default()))
        };

        let hard_coded_values =
            match hard_coded::value(ElementsNetwork::Liquid, AssetsOrIcons::Assets) {
                Value::Object(h) => h,
                _ => panic!("must be value object"),
            };

        // Either assets or icons must be requested
        assert!(r(true, false, false).is_err());

        // refresh false, asset true (no cache), icons true (no cache)
        let value = r(false, true, true).unwrap();
        assert_eq!(value.assets.len(), hard_coded_values.len());
        assert_eq!(value.icons.len(), 1);
        assert_eq!(value.source, Some(RegistrySource::LocalRegistry));

        // refresh false, asset true (no cache), icons false (no cache)
        let value = r(false, true, false).unwrap();
        assert_eq!(value.assets.len(), hard_coded_values.len());
        assert!(value.icons.is_empty());
        assert_eq!(value.source, Some(RegistrySource::LocalRegistry));

        // refresh false, asset false (no cache), icons true (no cache)
        let value = r(false, false, true).unwrap();
        assert!(value.assets.is_empty());
        assert_eq!(value.icons.len(), 1);
        assert_eq!(value.source, Some(RegistrySource::LocalRegistry));

        // refresh true, asset true, icons false (no cache)
        let value = r(true, true, false).unwrap();
        assert!(value.assets.get(&policy_asset).is_some());
        assert!(value.icons.is_empty());
        assert!(matches!(
            value.source,
            Some(RegistrySource::NotModified | RegistrySource::Downloaded)
        ));

        // refresh false, asset false, icons true (no cache)
        let value = r(false, false, true).unwrap();
        assert!(value.assets.is_empty());
        assert_eq!(value.icons.len(), 1);
        assert_eq!(value.source, Some(RegistrySource::LocalRegistry));

        // refresh true, asset true, icons true (no cache)
        // {"asset": data, "icons": data}
        let value = r(true, true, true).unwrap();
        assert!(value.assets.get(&policy_asset).is_some());
        assert!(!value.icons.is_empty());
        assert!(matches!(
            value.source,
            Some(RegistrySource::NotModified | RegistrySource::Downloaded)
        ));

        let now = std::time::Instant::now();
        // check 304
        let value = r(true, true, true).unwrap();
        assert!(value.assets.get(&policy_asset).is_some());
        assert!(!value.icons.is_empty());
        assert_eq!(value.source, Some(RegistrySource::NotModified));
        println!("not modified took {:?}", now.elapsed());

        let now = std::time::Instant::now();
        // cache read
        let value = r(false, true, true).unwrap();
        assert!(value.assets.get(&policy_asset).is_some());
        assert!(!value.icons.is_empty());
        assert_eq!(value.source, Some(RegistrySource::LocalRegistry));
        println!("cache read {:?}", now.elapsed());

        // concurrent access
        // TODO: interleaved write
        let mut handles = vec![];
        for _ in 0..5 {
            let handle = std::thread::spawn(move || r(false, true, true).unwrap());
            handles.push(handle);
        }
        while let Some(handle) = handles.pop() {
            assert_eq!(handle.join().unwrap(), value);
        }
    }

    #[test]
    fn test_get_assets() {
        use elements::AssetId;

        const DFLT_ASSETS: [&str; 2] = [
            "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
            "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
        ];

        const DFLT_XPUB: &str = "tpubD97UxEEcrMpkE8yG3NQveraWveHzTAJx3KwPsUycx9ABfxRjMtiwfm6BtrY5yhF9yF2eyMg2hyDtGDYXx6gVLBox1m2Mq4u8zB2NXFhUZmm";

        let _ = env_logger::try_init();

        let registry_dir = TempDir::new().unwrap();
        info!("creating registry dir at {:?}", registry_dir);
        init(&registry_dir).unwrap();

        fn get(assets: Option<Vec<&str>>, xpub: Option<&str>) -> Result<RegistryInfos> {
            let assets_id = assets
                .unwrap_or(DFLT_ASSETS.to_vec())
                .into_iter()
                .flat_map(AssetId::from_str)
                .collect::<Vec<_>>();

            let xpub = ExtendedPubKey::from_str(xpub.unwrap_or(DFLT_XPUB))?;

            get_assets(GetAssetsParams {
                assets_id,
                xpub,
                config: crate::params::Config::default(),
            })
        }

        // empty query
        let res = get(Some(vec![]), None).unwrap();
        assert!(res.assets.is_empty());
        assert!(res.icons.is_empty());
        assert_eq!(res.source, Some(RegistrySource::Cache));

        // invalid query
        let res = get(Some(vec!["foo"]), None).unwrap();
        assert!(res.assets.is_empty());
        assert!(res.icons.is_empty());
        assert_eq!(res.source, Some(RegistrySource::Cache));

        // invalid xpub
        let res = get(None, Some("foo"));
        assert!(res.is_err(), "{:?}", res);

        // asset id not present in registry
        let res = get(
            Some(vec!["144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49"]),
            None,
        )
        .unwrap();
        assert!(res.assets.is_empty());
        assert!(res.icons.is_empty());
        assert_eq!(res.source, Some(RegistrySource::Cache));

        // default query, 2 assets queried, only 1 is present in registry
        let now = std::time::Instant::now();
        let res = get(None, None).unwrap();
        assert_eq!(1, res.assets.len());
        assert_eq!(1, res.icons.len());
        assert_eq!(res.source, Some(RegistrySource::LocalRegistry));
        println!("cache read took {:?}", now.elapsed());

        // same query, now infos should come from cache.
        let res = get(None, None).unwrap();
        assert_eq!(1, res.assets.len());
        assert_eq!(1, res.icons.len());
        assert_eq!(res.source, Some(RegistrySource::Cache));
    }
}
