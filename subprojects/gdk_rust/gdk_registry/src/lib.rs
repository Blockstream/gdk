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
mod last_modified;
mod params;
mod registry;
mod registry_infos;

use std::path::Path;
use std::sync::Arc;
use std::thread;

use assets_or_icons::AssetsOrIcons;
use cache::Cache;
use gdk_common::log;
use last_modified::LastModified;
use params::GetAssetsQuery;
use registry_infos::RegistrySource;

pub use asset_entry::AssetEntry;
pub use error::{Error, Result};
pub use hard_coded::policy_asset_id;
pub use params::{
    AssetCategory, Config, ElementsNetwork, GetAssetsBuilder, GetAssetsParams, RefreshAssetsParams,
};
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
/// avoid performing a full registry read on every call. The cache file stored
/// on disk is encrypted via the wallet's xpub key.
pub fn get_assets(params: GetAssetsParams) -> Result<RegistryInfos> {
    let network = params.config.network;

    let (assets_id, xpub) = match params.into_query()? {
        GetAssetsQuery::FromCache(assets_id, xpub) => (assets_id, xpub),
        GetAssetsQuery::FromRegistry(matcher) => return registry::filter_full(network, &*matcher),
        GetAssetsQuery::FromHardCoded(matcher) => {
            return registry::filter_hard_coded(network, &*matcher)
        }
        GetAssetsQuery::WholeRegistry => return registry::get_full(network),
    };

    let mut cache_files = cache::CACHE_FILES.lock()?;
    let mut cache = Cache::from_xpub(xpub, &mut *cache_files);

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

    let registry = registry::get_full(network)?;

    // The returned infos are marked as being from the registry if at least one
    // of the returned assets is from the full asset registry.
    let mut from_cache = true;

    let mut in_registry = Vec::new();
    let mut assets_not_in_disk = Vec::new();
    let mut icons_not_in_disk = Vec::new();

    for id in not_cached {
        match (registry.contains_asset(&id), registry.contains_icon(&id)) {
            (true, true) => in_registry.push(id),

            (true, false) => {
                in_registry.push(id.clone());
                icons_not_in_disk.push(id);
            }

            (false, true) => {
                assets_not_in_disk.push(id.clone());
            }

            (false, false) => {
                assets_not_in_disk.push(id.clone());
                icons_not_in_disk.push(id);
            }
        }
    }

    if !in_registry.is_empty() {
        log::debug!("{:?} found in the local asset registry", in_registry);
        cache.extend_from_registry(registry, &in_registry);
        cache.update(&mut *cache_files)?;
        cached.extend(in_registry);
        from_cache = false;
    }

    if !assets_not_in_disk.is_empty() {
        log::debug!("{:?} are not in the local asset registry", assets_not_in_disk);
        cache.register_missing_assets(assets_not_in_disk);
        cache.update(&mut *cache_files)?;
    }

    if !icons_not_in_disk.is_empty() {
        log::debug!("{:?} are not in the local icons registry", icons_not_in_disk);
        cache.register_missing_icons(icons_not_in_disk);
        cache.update(&mut *cache_files)?;
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
/// configuration can be overridden by providing the `params.config` parameter.
pub fn refresh_assets(params: RefreshAssetsParams) -> Result<RegistrySource> {
    if !params.wants_something() {
        return Err(Error::BothAssetsIconsFalse);
    }

    let params = Arc::new(params);

    let assets_handle = {
        let params = Arc::clone(&params);
        thread::spawn(move || {
            params
                .wants_assets()
                .then(|| registry::refresh_assets(&params))
                .transpose()
                .map(Option::unwrap_or_default)
        })
    };

    let icons_source = params
        .wants_icons()
        // forces multiline formatting
        .then(|| registry::refresh_icons(&params))
        .transpose()?
        .unwrap_or_default();

    let assets_source = assets_handle.join().unwrap()?;

    Ok(RegistrySource::merge(assets_source, icons_source))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assets_or_icons::AssetsOrIcons;
    use crate::hard_coded;
    use crate::params::GetAssetsBuilder;
    use crate::params::{AssetCategory, ElementsNetwork};
    use gdk_common::bitcoin::hashes::hex::FromHex;
    use gdk_common::bitcoin::util::bip32::ExtendedPubKey;
    use gdk_common::elements::AssetId;
    use gdk_common::log::info;
    use httptest::{matchers::*, responders::*, Expectation, Server};
    use rusty_fork::rusty_fork_test;
    use serde_json::Value;
    use std::collections::{HashMap, HashSet};
    use std::path::Path;
    use std::str::FromStr;

    use tempfile::TempDir;

    /// Shadows `crate::init`, mapping `Error::AlreadyInitialized` to
    /// `Ok(())` to avoid having a test fail only because some other test has
    /// already initialized.
    fn init(dir: impl AsRef<Path>) -> Result<()> {
        match super::init(dir) {
            Err(Error::AlreadyInitialized) => Ok(()),
            other => other,
        }
    }

    fn local_server_config(server: &Server, assets: bool, icons: bool) -> Config {
        let test_endpoint = |what: AssetsOrIcons| {
            let (body, last_modified) = what.liquid_data();

            server.expect(
                Expectation::matching(all_of![
                    request::method_path("GET", what.endpoint()),
                    request::headers(contains(("if-modified-since", last_modified.clone()))),
                    request::headers(not(contains(("emptify_icons", "true")))),
                ])
                .times(0..=1)
                .respond_with({
                    status_code(304)
                        .body(body.clone())
                        .append_header("last-modified", last_modified.clone())
                }),
            );

            server.expect(
                Expectation::matching(all_of![
                    request::method_path("GET", what.endpoint()),
                    request::headers(not(contains(("if-modified-since", last_modified.clone())))),
                    request::headers(not(contains(("emptify_icons", "true")))),
                ])
                .times(0..=1)
                .respond_with({
                    status_code(200).body(body).append_header("last-modified", last_modified)
                }),
            );

            let (body, last_modified) = what.emptify_icons();
            server.expect(
                Expectation::matching(all_of![
                    request::method_path("GET", what.endpoint()),
                    request::headers(contains(("emptify_icons", "true"))),
                ])
                .times(0..=1)
                .respond_with({
                    status_code(200)
                        .body(body.clone())
                        .append_header("last-modified", last_modified.clone())
                }),
            );
        };

        if assets {
            test_endpoint(AssetsOrIcons::Assets);
        }

        if icons {
            test_endpoint(AssetsOrIcons::Icons);
        }

        Config {
            url: format!("http://localhost:{}", server.addr().port()),
            ..Default::default()
        }
    }

    fn test_refresh_assets(
        assets: bool,
        icons: bool,
        emptify_icons: bool,
    ) -> Result<RegistrySource> {
        let server = Server::run();

        let mut config = local_server_config(&server, assets, icons);
        if emptify_icons {
            config.custom_headers.insert("emptify_icons".to_string(), "true".to_string());
        }
        let xpub = ExtendedPubKey::from_str(DEFAULT_XPUB)?;
        let params = RefreshAssetsParams::new(assets, icons, config, Some(xpub));

        super::refresh_assets(params)
    }

    fn get_full_registry() -> RegistryInfos {
        registry::get_full(ElementsNetwork::Liquid).unwrap()
    }

    const DEFAULT_ASSETS: [&str; 2] = [
        "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
        "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49",
    ];

    const DEFAULT_XPUB: &str = "tpubD97UxEEcrMpkE8yG3NQveraWveHzTAJx3KwPsUycx9ABfxRjMtiwfm6BtrY5yhF9yF2eyMg2hyDtGDYXx6gVLBox1m2Mq4u8zB2NXFhUZmm";

    fn get_assets(assets: Option<&[&str]>, xpub: Option<&str>) -> Result<RegistryInfos> {
        let assets_id =
            assets.unwrap_or(&DEFAULT_ASSETS).into_iter().flat_map(|s| AssetId::from_str(*s));

        let xpub = ExtendedPubKey::from_str(xpub.unwrap_or(DEFAULT_XPUB))?;

        let params = GetAssetsBuilder::new().assets_id(assets_id, xpub).build();

        super::get_assets(params)
    }

    rusty_fork_test! {
        #[test]
        fn test_registry_prod() {
            let _ = env_logger::try_init();

            let temp_dir = TempDir::new().unwrap();
            info!("{:?}", temp_dir);
            init(&temp_dir).unwrap();

            let policy_asset = policy_asset_id(ElementsNetwork::Liquid);

            let hard_coded_values =
                match hard_coded::value(ElementsNetwork::Liquid, AssetsOrIcons::Assets) {
                    Value::Object(h) => h,
                    _ => panic!("must be value object"),
                };

            let hard_coded_icons =
                match hard_coded::value(ElementsNetwork::Liquid, AssetsOrIcons::Icons) {
                    Value::Object(h) => h,
                    _ => panic!("must be value object"),
                };

            // Either assets or icons must be requested
            assert!(test_refresh_assets(false, false, false).is_err());

            // asset true (no cache), icons true (no cache)
            let value = get_full_registry();
            assert_eq!(value.assets.len(), hard_coded_values.len());
            assert_eq!(value.icons.len(), hard_coded_icons.len());

            // refresh assets but not icons
            let source = test_refresh_assets(true, false, false).unwrap();
            assert_eq!(source, RegistrySource::Downloaded);

            // refresh icons but not assets
            let source = test_refresh_assets(false, true, false).unwrap();
            assert_eq!(source, RegistrySource::Downloaded);

            let value = get_full_registry();
            assert!(value.assets.get(&policy_asset).is_some());

            // check 304
            let now = std::time::Instant::now();
            let source = test_refresh_assets(true, true, false).unwrap();
            assert_eq!(source, RegistrySource::NotModified);
            println!("not modified took {:?}", now.elapsed());

            let value = get_full_registry();

            // concurrent access
            // TODO: interleaved write
            let mut handles = vec![];
            for _ in 0..5 {
                let handle = std::thread::spawn(move || get_full_registry());
                handles.push(handle);
            }
            while let Some(handle) = handles.pop() {
                assert_eq!(handle.join().unwrap(), value);
            }
        }

        #[test]
        fn test_get_assets() {
            let _ = env_logger::try_init();

            let temp_dir = TempDir::new().unwrap();
            info!("{:?}", temp_dir);
            init(&temp_dir).unwrap();

            // empty query
            let res = get_assets(Some(&[]), None).unwrap();
            assert!(res.assets.is_empty());
            assert!(res.icons.is_empty());
            assert_eq!(res.source, Some(RegistrySource::Cache));

            // invalid query
            let res = get_assets(Some(&["foo"]), None).unwrap();
            assert!(res.assets.is_empty());
            assert!(res.icons.is_empty());
            assert_eq!(res.source, Some(RegistrySource::Cache));

            // invalid xpub
            let res = get_assets(None, Some("foo"));
            assert!(res.is_err(), "{:?}", res);

            // asset id not present in registry
            let res = get_assets(
                Some(&["144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49"]),
                None,
                )
                .unwrap();
            assert!(res.assets.is_empty());
            assert!(res.icons.is_empty());
            assert_eq!(res.source, Some(RegistrySource::Cache));

            // default query, 2 assets queried, only 1 is present in registry
            let now = std::time::Instant::now();
            let res = get_assets(None, None).unwrap();
            assert_eq!(1, res.assets.len());
            assert_eq!(1, res.icons.len());
            assert_eq!(res.source, Some(RegistrySource::LocalRegistry));
            println!("cache read took {:?}", now.elapsed());

            // same query, now infos should come from cache.
            let res = get_assets(None, None).unwrap();
            assert_eq!(1, res.assets.len());
            assert_eq!(1, res.icons.len());
            assert_eq!(res.source, Some(RegistrySource::Cache));
        }

        #[test]
        fn test_corrupted_registry() {
            let _ = env_logger::try_init();

            let temp_dir = TempDir::new().unwrap();
            info!("{:?}", temp_dir);
            init(&temp_dir).unwrap();

            let hard_coded_assets = hard_coded::assets(ElementsNetwork::Liquid);
            let hard_coded_icons = hard_coded::icons(ElementsNetwork::Liquid);

            let source = test_refresh_assets(true, true, false).unwrap();
            assert_eq!(source, RegistrySource::Downloaded);

            // Corrupt local assets and icons files after downloading updated
            // registry infos. With `refresh` set to `false` they should both get
            // reset to the hard coded values.
            registry::tests::corrupt_file(ElementsNetwork::Liquid, AssetsOrIcons::Assets).unwrap();
            registry::tests::corrupt_file(ElementsNetwork::Liquid, AssetsOrIcons::Icons).unwrap();

            let res = get_full_registry();
            assert_eq!(res.assets.len(), hard_coded_assets.len());
            assert_eq!(res.icons.len(), hard_coded_icons.len());

            registry::tests::corrupt_file(ElementsNetwork::Liquid, AssetsOrIcons::Assets).unwrap();
            registry::tests::corrupt_file(ElementsNetwork::Liquid, AssetsOrIcons::Icons).unwrap();

            let source = test_refresh_assets(true, true, false).unwrap();
            assert_eq!(source, RegistrySource::Downloaded);

            let res = test_refresh_assets(true, true, false).unwrap();
            assert_eq!(res, RegistrySource::NotModified);
        }

        #[test]
        fn test_update_missing_and_updated() {
            let _ = env_logger::try_init();

            let temp_dir = TempDir::new().unwrap();
            info!("{:?}", temp_dir);
            init(&temp_dir).unwrap();

            // both assets not present in the hard coded values
            let res = get_assets(Some(&["123465c803ae336c62180e52d94ee80d80828db54df9bedbb9860060f49de2eb", "4d4354944366ea1e33f27c37fec97504025d6062c551208f68597d1ed40ec53e"]), None).unwrap();
            assert_eq!(res.assets.len(), 0);

            // updating the local registry, now those assets should be added to
            // the cache.
             test_refresh_assets(true, true, false).unwrap();

            let res = get_assets(Some(&["123465c803ae336c62180e52d94ee80d80828db54df9bedbb9860060f49de2eb", "4d4354944366ea1e33f27c37fec97504025d6062c551208f68597d1ed40ec53e"]), None).unwrap();
            assert_eq!(res.assets.len(), 2);
            assert_eq!(res.source, Some(RegistrySource::Cache));

            // now we make the server response to return updated icons (all become empty) and
            // verify the local cache it's different
            let asset_id_hex = "11f91cb5edd5d0822997ad81f068ed35002daec33986da173461a8427ac857e1";
            let asset_id = AssetId::from_hex(asset_id_hex).unwrap();
            let before = get_assets(Some(&[asset_id_hex]), None).unwrap();
            let before = before.icons.get(&asset_id).unwrap();
            test_refresh_assets(true, true, true).unwrap();
            let after = get_assets(Some(&[asset_id_hex]), None).unwrap();
            let after = after.icons.get(&asset_id).unwrap();
            assert_ne!(before, after);
        }

        #[test]
        fn update_icons_server_side() {
            let _ = env_logger::try_init();

            let temp_dir = TempDir::new().unwrap();
            info!("{:?}", temp_dir);
            init(&temp_dir).unwrap();

            test_refresh_assets(true, true, false).unwrap();
            let icons = get_full_registry().icons;

            assets_or_icons::test::update_liquid_data();

            test_refresh_assets(true, true, false).unwrap();
            let new_icons = get_full_registry().icons;

            assert!(new_icons.len() > icons.len(), "{} vs {}", new_icons.len(), icons.len());

            let asset_id = AssetId::from_hex("6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d").unwrap();
            assert_eq!(icons.get(&asset_id), new_icons.get(&asset_id), "hard coded icon should not get updated");

            let asset_id = AssetId::from_hex("de091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2").unwrap();
            assert_ne!(icons.get(&asset_id), new_icons.get(&asset_id), "non hard coded icon should get updated");
        }

        #[test]
        fn update_missing_icons() {
            let _ = env_logger::try_init();

            let temp_dir = TempDir::new().unwrap();
            info!("{:?}", temp_dir);
            init(&temp_dir).unwrap();

            /// The first asset id in `data/test/extra_icons.json`.
            const ID: &str = "223465c803ae336c62180e52d94ee80d80828db54df9bedbb9860060f49de2eb";

            // ID icon is not present in the hard coded icons
            let res = get_assets(Some(&[ID]), None).unwrap();
            assert_eq!(res.icons.len(), 0);

            assets_or_icons::test::update_liquid_data();

            // Not updating the icons.
            test_refresh_assets(true, false, false).unwrap();
            let res = get_assets(Some(&[ID]), None).unwrap();
            assert_eq!(res.icons.len(), 0);

            // Now updating the icons.
            test_refresh_assets(false, true, false).unwrap();
            let res = get_assets(Some(&[ID]), None).unwrap();
            assert_eq!(res.icons.len(), 1);
        }

        #[test]
        fn get_assets_extended() {
            let _ = env_logger::try_init();

            let temp_dir = TempDir::new().unwrap();
            info!("{:?}", temp_dir);
            init(&temp_dir).unwrap();

            let xpub = ExtendedPubKey::from_str(DEFAULT_XPUB).unwrap();

            let hard_coded_values =
                match hard_coded::value(ElementsNetwork::Liquid, AssetsOrIcons::Assets) {
                    Value::Object(h) => h,
                    _ => panic!("must be value object"),
                };

            let hard_coded_icons =
                match hard_coded::value(ElementsNetwork::Liquid, AssetsOrIcons::Icons) {
                    Value::Object(h) => h,
                    _ => panic!("must be value object"),
                };

            // Not setting any field -> should error.
            let params = GetAssetsBuilder::new().build();
            assert!(matches!(super::get_assets(params), Err(Error::GetAssetsNoFields)));

            // Setting both `assets_id` and another field -> should error.
            let params = GetAssetsBuilder::new().assets_id([], xpub).names(Vec::<String>::new()).build();
            assert!(matches!(super::get_assets(params), Err(Error::GetAssetsIdNotAlone)));

            // Fetching the whole registry before doing any updates.
            let params = GetAssetsBuilder::new().category(AssetCategory::All).build();
            let res = super::get_assets(params.clone()).unwrap();
            assert_eq!(res.assets.len(), hard_coded_values.len());
            assert_eq!(res.icons.len(), hard_coded_icons.len());

            // Update assets and redo same query -> we should get new assets.
            test_refresh_assets(true, false, false).unwrap();
            let new = super::get_assets(params.clone()).unwrap();
            assert!(new.assets.len() > res.assets.len());

            // Update icons and redo same query -> we should get new icons.
            test_refresh_assets(false, true, false).unwrap();
            let new = super::get_assets(params).unwrap();
            assert!(new.assets.len() > res.assets.len());

            let params = GetAssetsBuilder::new().category(AssetCategory::WithIcons).build();
            let with_icons = super::get_assets(params).unwrap();
            assert!(with_icons.assets.len() > 0);
            // We should get the same number of assets and icons..
            assert_eq!(with_icons.assets.len(), with_icons.icons.len());
            // ..and the asset ids should match.
            assert_eq!(with_icons.assets.keys().collect::<HashSet<_>>(), with_icons.icons.keys().collect::<HashSet<_>>());

            // Manually filter all the assets with icons with ticker `LCAD`.
            let icons_and_lcad = with_icons.assets
                .iter()
                .filter_map(|(id, asset)| {
                    matches!(asset.ticker.as_deref(), Some("LCAD"))
                        .then(|| (id.clone(), asset.clone()))
                })
                .collect::<HashMap<_, _>>();

            // This should be the same as the following query.
            let params = GetAssetsBuilder::new().category(AssetCategory::WithIcons).tickers(["LCAD"]).build();
            let also_icons_and_lcad = super::get_assets(params).unwrap().assets;

            assert_eq!(icons_and_lcad, also_icons_and_lcad);

            // Get hard coded assets
            let params = GetAssetsBuilder::new().category(AssetCategory::HardCoded).build();
            let res = super::get_assets(params).unwrap();
            assert_eq!(res.assets, hard_coded::assets(ElementsNetwork::Liquid));
            assert_eq!(res.icons, hard_coded::icons(ElementsNetwork::Liquid));
        }
    }
}
