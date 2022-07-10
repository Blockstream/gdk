use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use log::debug;
use once_cell::sync::OnceCell;
use serde::de::DeserializeOwned;

use crate::assets_or_icons::AssetsOrIcons;
use crate::cache;
use crate::hard_coded;
use crate::params::{ElementsNetwork, RefreshAssetsParams};
use crate::registry_infos::{RegistryAssets, RegistryIcons, RegistrySource};
use crate::value_modified::ValueModified;
use crate::{Error, Result};

type RegistryFiles = HashMap<(ElementsNetwork, AssetsOrIcons), Mutex<File>>;

static REGISTRY_FILES: OnceCell<RegistryFiles> = OnceCell::new();

pub(crate) fn init(registry_dir: impl AsRef<Path>) -> Result<()> {
    let mut registry_files: RegistryFiles =
        HashMap::with_capacity(ElementsNetwork::len() * AssetsOrIcons::len());

    let mut path = registry_dir.as_ref().to_owned();

    for network in ElementsNetwork::iter() {
        path.push(network.to_string());
        fs::create_dir_all(&path)?;

        for what in AssetsOrIcons::iter() {
            path.push(what.to_string());

            // We check if the file path exists *before* calling
            // `OpenOptions::open`.
            let exists = path.exists();

            let mut file = OpenOptions::new().write(true).read(true).create(true).open(&path)?;

            if !exists {
                let hard = ValueModified::from_hard_coded(network, what);
                crate::file::write(&hard, &mut file)?;
            }

            registry_files.insert((network, what), Mutex::new(file));
            path.pop();
        }
        path.pop();
    }

    REGISTRY_FILES.set(registry_files).map_err(|_err| Error::AlreadyInitialized)
}

pub(crate) fn get_assets(params: &RefreshAssetsParams) -> Result<(RegistryAssets, RegistrySource)> {
    let (mut assets, source) = fetch::<RegistryAssets>(AssetsOrIcons::Assets, params)?;

    if matches!(source, RegistrySource::Downloaded) {
        let len = assets.len();
        debug!("downloaded {} assets", assets.len());
        assets.retain(|_, entry| entry.verifies().unwrap_or(false));
        if assets.len() != len {
            log::warn!("{} assets didn't verify!", len - assets.len());
        }
        cache::update_missing(&params.xpubs, &assets)?;
    }

    assets.extend(hard_coded::assets(params.network()));

    Ok((assets, source))
}

pub(crate) fn get_icons(params: &RefreshAssetsParams) -> Result<(RegistryIcons, RegistrySource)> {
    let (mut icons, source) = fetch::<RegistryIcons>(AssetsOrIcons::Icons, params)?;

    if matches!(source, RegistrySource::Downloaded) {
        debug!("downloaded {} icons", icons.len());
    }

    icons.extend(hard_coded::icons(params.network()));

    Ok((icons, source))
}

/// TODO: docs
fn fetch<T: DeserializeOwned>(
    what: AssetsOrIcons,
    params: &RefreshAssetsParams,
) -> Result<(T, RegistrySource)> {
    let mut file = get_file(params.network(), what)?;

    let current = crate::file::read::<ValueModified>(&mut file)?;

    if !params.should_refresh() {
        return Ok((current.deserialize_into()?, RegistrySource::LocalRegistry));
    }

    let response = crate::http::call(&params.url(what), &params.agent()?, current.last_modified())?;

    if response.last_modified() == current.last_modified() {
        debug!("local {} are up to date", what);
        return Ok((current.deserialize_into()?, RegistrySource::NotModified));
    }

    debug!("fetched {} were last modified {}", what, response.last_modified());

    crate::file::write(&response, &mut file)?;

    let downloaded = response.deserialize_into()?;

    Ok((downloaded, RegistrySource::Downloaded))
}

/// Returns either the assets or icons file corresponding to a given network,
/// behind a Mutex guard. Fails if the Mutex is poisoned.
fn get_file(network: ElementsNetwork, ty: AssetsOrIcons) -> Result<MutexGuard<'static, File>> {
    REGISTRY_FILES
        .get()
        .ok_or(Error::RegistryUninitialized)?
        .get(&(network, ty))
        .expect("all (network, {assets|icons}) combinations are initialized")
        .lock()
        .map_err(Into::into)
}
