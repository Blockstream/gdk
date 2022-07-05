use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use once_cell::sync::OnceCell;

use crate::assets_or_icons::AssetsOrIcons;
use crate::params::ElementsNetwork;
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

            let mut file = OpenOptions::new()
                .write(true)
                .read(true)
                .create(true)
                .open(&path)?;

            if !exists {
                let hard = ValueModified::from_hard_coded(network, what);
                crate::file::write(&hard, &mut file)?;
            }

            registry_files.insert((network, what), Mutex::new(file));
            path.pop();
        }
        path.pop();
    }

    REGISTRY_FILES
        .set(registry_files)
        .map_err(|_err| Error::AlreadyInitialized)
}

/// Returns either the assets or icons file corresponding to a given network,
/// behind a Mutex guard. Fails if the Mutex is poisoned or if another thread
/// is currently holding the lock.
pub(crate) fn _get_file(
    network: ElementsNetwork,
    ty: AssetsOrIcons,
) -> Result<MutexGuard<'static, File>> {
    REGISTRY_FILES
        .get()
        .ok_or(Error::RegistryUninitialized)?
        .get(&(network, ty))
        .expect("all (network, {assets|icons}) combinations are initialized")
        .try_lock()
        .map_err(Into::into)
}
