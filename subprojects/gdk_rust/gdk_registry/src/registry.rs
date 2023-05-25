use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use gdk_common::log::{debug, warn};
use gdk_common::once_cell::sync::OnceCell;
use serde::{de::DeserializeOwned, Serialize};

use crate::params::{ElementsNetwork, RefreshAssetsParams};
use crate::registry_infos::{RegistryAssets, RegistryIcons, RegistrySource};
use crate::{cache, file, hard_coded, http};
use crate::{AssetEntry, AssetsOrIcons, Error, LastModified, RegistryInfos, Result};

type LastModifiedFiles = HashMap<ElementsNetwork, Mutex<File>>;
type RegistryFiles = HashMap<(ElementsNetwork, AssetsOrIcons), Mutex<File>>;

static LAST_MODIFIED_FILES: OnceCell<LastModifiedFiles> = OnceCell::new();
static REGISTRY_FILES: OnceCell<RegistryFiles> = OnceCell::new();

/// Returns the file at `path`, using `initializer` to initialize the file's
/// contents if it doesn't already exist.
fn get_file<T: Serialize, I: FnOnce() -> T>(path: &Path, initializer: I) -> Result<File> {
    // We check if the file path exists *before* calling `OpenOptions::open`.
    let exists = path.exists();

    let mut file = OpenOptions::new().write(true).read(true).create(true).open(&path)?;

    if !exists {
        crate::file::write(&initializer(), &mut file)?;
    }

    Ok(file)
}

pub(crate) fn init(registry_dir: impl AsRef<Path>) -> Result<()> {
    let mut last_modified_files: LastModifiedFiles = HashMap::with_capacity(ElementsNetwork::len());

    let mut registry_files: RegistryFiles =
        HashMap::with_capacity(ElementsNetwork::len() * AssetsOrIcons::len());

    let mut path = registry_dir.as_ref().to_owned();

    for network in ElementsNetwork::iter() {
        path.push(network.to_string());
        fs::create_dir_all(&path)?;

        let file = get_file(&path.join("last-modified"), LastModified::default)?;
        last_modified_files.insert(network, Mutex::new(file));

        {
            let assets = AssetsOrIcons::Assets;
            path.push(assets.to_string());
            let file = get_file(&path, || hard_coded::assets(network))?;
            registry_files.insert((network, assets), Mutex::new(file));
            path.pop();
        }

        {
            let iconss = AssetsOrIcons::Icons;
            path.push(iconss.to_string());
            let file = get_file(&path, || hard_coded::icons(network))?;
            registry_files.insert((network, iconss), Mutex::new(file));
            path.pop();
        }

        path.pop();
    }

    LAST_MODIFIED_FILES.set(last_modified_files).map_err(|_err| Error::AlreadyInitialized)?;

    REGISTRY_FILES.set(registry_files).map_err(|_err| Error::AlreadyInitialized)?;

    Ok(())
}

pub(crate) fn refresh_assets(params: &RefreshAssetsParams) -> Result<RegistrySource> {
    match refresh::<RegistryAssets>(AssetsOrIcons::Assets, params)? {
        Some(mut assets) => {
            let len = assets.len();
            debug!("downloaded {} assets", assets.len());
            assets.retain(|_, entry| entry.verifies().unwrap_or(false));
            if assets.len() != len {
                warn!("{} assets didn't verify!", len - assets.len());
            }
            if let Some(xpub) = params.xpub {
                cache::update_missing_assets(xpub, &assets)?;
            }
            Ok(RegistrySource::Downloaded)
        }

        _ => Ok(RegistrySource::NotModified),
    }
}

pub(crate) fn refresh_icons(params: &RefreshAssetsParams) -> Result<RegistrySource> {
    match refresh::<RegistryIcons>(AssetsOrIcons::Icons, params)? {
        Some(icons) => {
            debug!("downloaded {} icons", icons.len());
            if let Some(xpub) = params.xpub {
                cache::update_missing_icons(xpub, &icons)?;
            }
            Ok(RegistrySource::Downloaded)
        }

        _ => Ok(RegistrySource::NotModified),
    }
}

/// Returns all the local assets and icons.
pub(crate) fn get_full(network: ElementsNetwork) -> Result<RegistryInfos> {
    let assets = {
        let mut v = fetch::<RegistryAssets>(network, AssetsOrIcons::Assets)?;
        v.extend(hard_coded::assets(network));
        v
    };

    let icons = {
        let mut v = fetch::<RegistryIcons>(network, AssetsOrIcons::Icons)?;
        v.extend(hard_coded::icons(network));
        v
    };

    Ok(RegistryInfos::new(assets, icons))
}

pub(crate) fn filter_full(
    network: ElementsNetwork,
    matcher: &dyn Fn(&AssetEntry, Option<&str>) -> bool,
) -> Result<RegistryInfos> {
    filter(get_full(network)?, matcher)
}

pub(crate) fn filter_hard_coded(
    network: ElementsNetwork,
    matcher: &dyn Fn(&AssetEntry, Option<&str>) -> bool,
) -> Result<RegistryInfos> {
    let registry = RegistryInfos::new(hard_coded::assets(network), hard_coded::icons(network));
    filter(registry, matcher)
}

fn filter(
    mut registry: RegistryInfos,
    matcher: &dyn Fn(&AssetEntry, Option<&str>) -> bool,
) -> Result<RegistryInfos> {
    let matched_ids = registry
        .assets
        .iter()
        .filter_map(|(id, asset)| {
            let icon = registry.icons.get(id).map(|i| &**i);
            matcher(asset, icon).then_some(id.clone())
        })
        .collect::<Vec<_>>();

    registry.assets.retain(|id, _| matched_ids.contains(id));
    registry.icons.retain(|id, _| matched_ids.contains(id));

    Ok(registry)
}

fn fetch<T: Default + Serialize + DeserializeOwned>(
    network: ElementsNetwork,
    what: AssetsOrIcons,
) -> Result<T> {
    let file = &mut *get_registry_file(network, what)?;

    match file::read::<T>(file) {
        Ok(value) => Ok(value),

        Err(err) => {
            warn!("couldn't deserialize local {} due to {}", what, err);
            let hard_coded = hard_coded::value(network, what);
            file::write(&hard_coded, file)?;
            serde_json::from_value(hard_coded).map_err(Into::into)
        }
    }
}

fn refresh<T: Serialize + DeserializeOwned>(
    what: AssetsOrIcons,
    params: &RefreshAssetsParams,
) -> Result<Option<T>> {
    let file = &mut *get_registry_file(params.network(), what)?;

    let last_modified = if file::read::<T>(file).is_ok() {
        get_last_modified(params.network(), what)?
    } else {
        String::new()
    };

    match http::call(&params.url(what), &params.agent()?, &last_modified, &params.custom_headers())?
    {
        Some((value, new_modified)) => {
            debug!("fetched {} were last modified {}", what, new_modified);
            let downloaded = serde_json::from_value::<T>(value)?;
            file::write(&downloaded, file)?;
            set_last_modified(new_modified, params.network(), what)?;
            Ok(Some(downloaded))
        }

        _ => {
            debug!("local {} are up to date", what);
            Ok(None)
        }
    }
}

/// Returns either the assets or icons file corresponding to a given network,
/// behind a Mutex guard. Fails if the Mutex is poisoned.
fn get_registry_file(
    network: ElementsNetwork,
    ty: AssetsOrIcons,
) -> Result<MutexGuard<'static, File>> {
    REGISTRY_FILES
        .get()
        .ok_or(Error::RegistryUninitialized)?
        .get(&(network, ty))
        .expect("all (network, {assets|icons}) combinations are initialized")
        .lock()
        .map_err(Into::into)
}

fn get_last_modified_file(network: ElementsNetwork) -> Result<MutexGuard<'static, File>> {
    LAST_MODIFIED_FILES
        .get()
        .ok_or(Error::RegistryUninitialized)?
        .get(&network)
        .expect("all networks are initialized")
        .lock()
        .map_err(Into::into)
}

fn get_last_modified(network: ElementsNetwork, what: AssetsOrIcons) -> Result<String> {
    get_last_modified_file(network)
        //
        .and_then(|mut file| crate::file::read::<LastModified>(&mut *file))
        .map(|last_modified| last_modified[what].to_owned())
}

fn set_last_modified(new: String, network: ElementsNetwork, what: AssetsOrIcons) -> Result<()> {
    get_last_modified_file(network).and_then(|mut file| {
        let mut last_modified = crate::file::read::<LastModified>(&mut *file)?;
        let old = &mut last_modified[what];
        *old = new;
        crate::file::write(&last_modified, &mut *file)
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use gdk_common::rand::Rng;
    use std::io::{Seek, Write};

    /// Writes 16 random bytes to the beginning of the file specified by
    /// `network` and `what`.
    pub(crate) fn corrupt_file(network: ElementsNetwork, what: AssetsOrIcons) -> Result<()> {
        let mut file = get_registry_file(network, what)?;

        let mut noise = [0u8; 16];
        gdk_common::rand::thread_rng().fill(&mut noise);

        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(&noise).map_err(Into::into)
    }
}
