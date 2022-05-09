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
use log::{debug, info, warn};

pub use error::Error;
pub use file::ValueModified;
pub use hard::policy_asset_id;
pub use inner::init;
pub use param::{AssetsOrIcons, ElementsNetwork, RefreshAssetsParam};
pub use result::{AssetEntry, RefreshAssetsResult};

mod error;
mod file;
mod hard;
mod http;
mod inner;
mod param;
mod result;

///
/// Returns information about assets and related icons.
///
/// Results could come from the persisted cached value when `details.refresh` is `false` or could be
/// fetched from an asset registry when it's `true`.
/// By default, Liquid mainnet network is used and the asset registry used is managed by Blockstream
/// and no proxy is used to access it. This default configuration could be overridden by providing
/// the `details.config` parameter.
///
pub fn refresh_assets(details: &RefreshAssetsParam) -> Result<RefreshAssetsResult, Error> {
    let now = std::time::Instant::now();
    let network = details.network();
    let mut return_value = RefreshAssetsResult::default();
    let agent = details.agent()?;
    for what in details.asked()? {
        let mut file = inner::get_file(network, what)?;
        let file_value = file::read(&mut file)?;
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
    info!("refresh_assets took: {:?}", now.elapsed());
    Ok(return_value)
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::hard::hard_coded_values;
    use log::info;
    use serde_json::Value;
    use tempfile::TempDir;

    #[test]
    fn test_registry_prod() {
        let _ = env_logger::try_init();

        let policy_asset = policy_asset_id(ElementsNetwork::Liquid);
        let temp_dir = TempDir::new().unwrap();
        info!("{:?}", temp_dir);
        init(&temp_dir).unwrap();

        let r = |refresh, assets, icons| {
            refresh_assets(&RefreshAssetsParam {
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
}
