use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use gdk_common::log::{debug, info, warn};
use once_cell::sync::OnceCell;
use serde::{de::DeserializeOwned, Serialize};

use crate::params::{ElementsNetwork, RefreshAssetsParams};
use crate::registry_infos::{RegistryAssets, RegistryIcons, RegistrySource};
use crate::AssetsOrIcons;
use crate::LastModified;
use crate::{cache, hard_coded, http};
use crate::{Error, Result};

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

        for what in AssetsOrIcons::iter() {
            path.push(what.to_string());
            let file = get_file(&path, || hard_coded::value(network, what))?;
            registry_files.insert((network, what), Mutex::new(file));
            path.pop();
        }

        path.pop();
    }

    LAST_MODIFIED_FILES.set(last_modified_files).map_err(|_err| Error::AlreadyInitialized)?;

    REGISTRY_FILES.set(registry_files).map_err(|_err| Error::AlreadyInitialized)?;

    Ok(())
}

pub(crate) fn get_assets(params: &RefreshAssetsParams) -> Result<(RegistryAssets, RegistrySource)> {
    let (mut assets, source) = fetch::<RegistryAssets>(AssetsOrIcons::Assets, params)?;

    if matches!(source, RegistrySource::Downloaded) {
        let len = assets.len();
        debug!("downloaded {} assets", assets.len());
        assets.retain(|_, entry| entry.verifies().unwrap_or(false));
        if assets.len() != len {
            warn!("{} assets didn't verify!", len - assets.len());
        }
        if let Some(xpub) = params.xpub {
            cache::update_missing_assets(xpub, &assets)?;
        }
    }

    assets.extend(hard_coded::assets(params.network()));

    Ok((assets, source))
}

pub(crate) fn get_icons(params: &RefreshAssetsParams) -> Result<(RegistryIcons, RegistrySource)> {
    let (mut icons, source) = fetch::<RegistryIcons>(AssetsOrIcons::Icons, params)?;

    if matches!(source, RegistrySource::Downloaded) {
        debug!("downloaded {} icons", icons.len());
        if let Some(xpub) = params.xpub {
            cache::update_missing_icons(xpub, &icons)?;
        }
    }

    icons.extend(hard_coded::icons(params.network()));

    Ok((icons, source))
}

/// TODO: docs
fn fetch<T: Default + Serialize + DeserializeOwned>(
    what: AssetsOrIcons,
    params: &RefreshAssetsParams,
) -> Result<(T, RegistrySource)> {
    let file = &mut *get_registry_file(params.network(), what)?;

    if !params.should_refresh() {
        info!("returning local {}", what);
        let value = match crate::file::read::<T>(file) {
            Ok(v) => v,

            Err(err) => {
                warn!("couldn't deserialize local {} due to {}", what, err);
                crate::file::write(&T::default(), file)?;
                T::default()
            }
        };
        Ok((value, RegistrySource::LocalRegistry))
    } else {
        let (value, last_modified) = match crate::file::read::<T>(file) {
            Ok(value) => (value, get_last_modified(params.network(), what)?),

            Err(err) => {
                warn!("couldn't deserialize local {} due to {}", what, err);
                (T::default(), String::new())
            }
        };

        match http::call(&params.url(what), &params.agent()?, &last_modified)? {
            Some((value, new_modified)) => {
                debug!("fetched {} were last modified {}", what, new_modified);
                let downloaded = serde_json::from_value::<T>(value)?;
                crate::file::write(&downloaded, file)?;
                set_last_modified(new_modified, params.network(), what)?;
                Ok((downloaded, RegistrySource::Downloaded))
            }

            None => {
                debug!("local {} are up to date", what);
                Ok((value, RegistrySource::NotModified))
            }
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
    use rand::Rng;
    use std::io::{Seek, Write};

    /// Writes 16 random bytes to the beginning of the file specified by
    /// `network` and `what`.
    pub(crate) fn corrupt_file(network: ElementsNetwork, what: AssetsOrIcons) -> Result<()> {
        let mut file = get_registry_file(network, what)?;

        let mut noise = [0u8; 16];
        rand::thread_rng().fill(&mut noise);

        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(&noise).map_err(Into::into)
    }
}
