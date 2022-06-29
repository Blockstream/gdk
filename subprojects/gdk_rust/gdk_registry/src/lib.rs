#![warn(missing_docs)]

//!
//! # GDK registry
//!
//! This library provides Liquid assets metadata ensuring data is verified and preserving privacy.
//! It also provides asset icons.
//!
//! A small number of assets information are hard-coded within this library, others are fetched from
//! a default "asset registry" or a user-defined one.
//!
//! The main method is [`refresh_assets`] but the library must be initialized with a call to [`init`].
//!
//! Assets metadata are piece of information like the name of the assets, the ticker, and the
//! precision (decimal places of amounts) which define how wallets show information to users.
//! It's important these informations are presented correctly so that the user could make an
//! informed decision. To ensure these property assets metadata are committed in the assets id and
//! verification made on the client so that if fetched information is incorrect this library will
//! filter them out.
//!
//! Another important consideration is that access to registries is made in a way that user interest
//! in a particular asset is not revealed to preserve users' privacy. At the moment the solution is
//! to fetch the whole registry.
//!

use hard::{hard_coded_assets, hard_coded_icons};
use log::{debug, warn};

pub use error::{Error, Result};
pub use file::ValueModified;
pub use hard::policy_asset_id;
pub use inner::init;
pub use param::{AssetsOrIcons, ElementsNetwork, GetAssetsParams, RefreshAssetsParam};
use registry_cache as cache;
pub use result::{AssetEntry, RegistryResult};

mod cache_result;
mod error;
mod file;
mod hard;
mod http;
mod inner;
mod param;
mod registry_cache;
mod result;

use cache_result::CacheResult;

///
/// Returns information about assets and related icons.
///
/// Results could come from the persisted cached value when `details.refresh` is `false` or could be
/// fetched from an asset registry when it's `true`.
/// By default, Liquid mainnet network is used and the asset registry used is managed by Blockstream
/// and no proxy is used to access it. This default configuration could be overridden by providing
/// the `details.config` parameter.
///
pub fn refresh_assets(details: RefreshAssetsParam) -> Result<RegistryResult> {
    let network = details.network();
    let mut return_value = RegistryResult::default();
    let agent = details.agent()?;
    for what in details.asked()? {
        let mut file = inner::get_full_registry(network, what)?;
        let file_value = file::read::<ValueModified>(&mut file)?;
        let value = match agent.as_ref() {
            Some(agent) => {
                let response_value =
                    http::call(&details.url(what), agent, &file_value.last_modified)?;
                debug!("response for {} modified: {}", what, response_value.last_modified);
                if file_value.last_modified != response_value.last_modified {
                    let last_modified = response_value.last_modified.clone();
                    let value = match what {
                        AssetsOrIcons::Assets => {
                            let hard = hard_coded_assets(network);
                            let mut downloaded = response_value.assets()?;
                            let len = downloaded.len();
                            debug!("downloaded {} assets metadata", len);
                            downloaded.retain(|_k, v| v.verify().unwrap_or(false));
                            if downloaded.len() != len {
                                warn!("Some assets didn't verify!");
                            }
                            downloaded.extend(hard);
                            serde_json::to_value(downloaded)?
                        }
                        AssetsOrIcons::Icons => {
                            let hard = hard_coded_icons(network);
                            let mut downloaded = response_value.icons()?;
                            debug!("downloaded {} assets icons", downloaded.len());
                            downloaded.extend(hard);
                            serde_json::to_value(downloaded)?
                        }
                    };

                    let new = ValueModified {
                        last_modified,
                        value,
                    };
                    file::write(&new, &mut file)?;
                    new
                } else {
                    file_value
                }
            }
            None => file_value,
        };
        match what {
            AssetsOrIcons::Assets => return_value.assets = serde_json::from_value(value.value)?,
            AssetsOrIcons::Icons => return_value.icons = serde_json::from_value(value.value)?,
        }
    }
    Ok(return_value)
}

///
/// Returns informations about a specific set of assets and related icons.
///
/// Unlike `refresh_assets`, this function caches the queried assets to avoid
/// performing a full registry read on every call. The cache is stored on disk
/// and it's encrypted with the wallet's xpub key.
///
pub fn get_assets(params: GetAssetsParams) -> Result<RegistryResult> {
    let xpub = &params.xpub;
    let mut cache = match cache::read(xpub) {
        Ok(cache) => cache,
        Err(err) => match err {
            Error::RegistryCacheNotCreated => CacheResult::default(),
            _ => return Err(err),
        },
    };

    debug!("`get_assets` received cache {:?}", cache);

    let GetAssetsParams {
        assets_id,
        xpub: _,
        config,
    } = params;

    let (mut found, mut not_found) = cache.split_present(assets_id);

    // Remove all the previous cache misses from `not_found` to possibly avoid
    // retriggering a registry read.
    not_found.retain(|id| !cache.missing_assets().contains(id));

    if not_found.is_empty() {
        cache.filter(&found);
        return Ok(cache.into());
    }

    debug!("the following assets were not found in the cache: {:?}", not_found);

    let params = RefreshAssetsParam {
        assets: true,
        icons: true,
        refresh: false,
        config,
    };

    let mut registry = refresh_assets(params)?;
    let (found_in_registry, still_not_found) = registry.split_present(not_found);

    if !still_not_found.is_empty() {
        debug!("the following assets were not found in the registry: {:?}", still_not_found);

        cache.register_missing(still_not_found);
        cache::write(&xpub, &cache)?;
    }

    if !found_in_registry.is_empty() {
        registry.filter(&found_in_registry);
        let filtered_registry = registry;

        debug!("adding these new entries to the cache: {:?}", filtered_registry);

        let RegistryResult {
            assets,
            icons,
        } = filtered_registry;

        cache.extend_assets(assets);
        cache.extend_icons(icons);

        cache::write(&xpub, &cache)?;

        // Add the asset ids that were found in the registry to the ones
        // already present in the cache.
        found.extend(found_in_registry);
    }

    cache.filter(&found);

    Ok(cache.into())
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::hard::hard_coded_values;
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
    fn test_registry_prod() {
        let _ = env_logger::try_init();

        let policy_asset = policy_asset_id(ElementsNetwork::Liquid);
        let temp_dir = TempDir::new().unwrap();
        info!("{:?}", temp_dir);
        init(&temp_dir).unwrap();

        let r = |refresh, assets, icons| {
            refresh_assets(RefreshAssetsParam {
                assets,
                icons,
                refresh,
                ..Default::default()
            })
        };

        let hard_coded_values =
            match hard_coded_values(ElementsNetwork::Liquid, AssetsOrIcons::Assets) {
                Value::Object(h) => h,
                _ => panic!("must be value object"),
            };

        // Either assets or icons must be requested
        assert!(r(true, false, false).is_err());

        // refresh false, asset true (no cache), icons true (no cache)
        let value = r(false, true, true).unwrap();
        assert_eq!(value.assets.len(), hard_coded_values.len());
        assert_eq!(value.icons.len(), 1);

        // refresh false, asset true (no cache), icons false (no cache)
        let value = r(false, true, false).unwrap();
        assert_eq!(value.assets.len(), hard_coded_values.len());
        assert!(value.icons.is_empty());

        // refresh false, asset false (no cache), icons true (no cache)
        let value = r(false, false, true).unwrap();
        assert!(value.assets.is_empty());
        assert_eq!(value.icons.len(), 1);

        // refresh true, asset true, icons false (no cache)
        let value = r(true, true, false).unwrap();
        assert!(value.assets.get(&policy_asset).is_some());
        assert!(value.icons.is_empty());

        // refresh false, asset false, icons true (no cache)
        let value = r(false, false, true).unwrap();
        assert!(value.assets.is_empty());
        assert_eq!(value.icons.len(), 1);

        // refresh true, asset true, icons true (no cache)
        // {"asset": data, "icons": data}
        let value = r(true, true, true).unwrap();
        assert!(value.assets.get(&policy_asset).is_some());
        assert!(!value.icons.is_empty());

        let now = std::time::Instant::now();
        // check 304
        let value = r(true, true, true).unwrap();
        assert!(value.assets.get(&policy_asset).is_some());
        assert!(!value.icons.is_empty());
        println!("not modified took {:?}", now.elapsed());

        let now = std::time::Instant::now();
        // cache read
        let value = r(false, true, true).unwrap();
        assert!(value.assets.get(&policy_asset).is_some());
        assert!(!value.icons.is_empty());
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

        fn get(assets: Option<Vec<&str>>, xpub: Option<&str>) -> Result<RegistryResult> {
            let assets_id = assets
                .unwrap_or(DFLT_ASSETS.to_vec())
                .into_iter()
                .flat_map(AssetId::from_str)
                .collect::<Vec<_>>();

            let xpub = ExtendedPubKey::from_str(xpub.unwrap_or(DFLT_XPUB))?;

            get_assets(GetAssetsParams {
                assets_id,
                xpub,
                config: crate::param::Config::default(),
            })
        }

        // empty query
        let res = get(Some(vec![]), None).unwrap();
        assert!(res.assets.is_empty());
        assert!(res.icons.is_empty());

        // invalid query
        let res = get(Some(vec!["foo"]), None).unwrap();
        assert!(res.assets.is_empty());
        assert!(res.icons.is_empty());

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

        // default query, 2 assets queried, only 1 is present in registry
        let now = std::time::Instant::now();
        let res = get(None, None).unwrap();
        assert_eq!(1, res.assets.len());
        assert_eq!(1, res.icons.len());
        println!("cache read took {:?}", now.elapsed());
    }
}
