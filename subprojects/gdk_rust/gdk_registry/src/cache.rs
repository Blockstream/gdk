use std::cmp;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use gdk_common::bitcoin::bip32::ExtendedPubKey;
use gdk_common::bitcoin::hashes::{sha256, Hash};
use gdk_common::elements::AssetId;
use gdk_common::log::{debug, warn};
use gdk_common::once_cell::sync::{Lazy, OnceCell};
use gdk_common::store::{Decryptable, Encryptable, ToCipher};
use gdk_common::util::ciborium_to_vec;
use serde::{Deserialize, Serialize};

use crate::registry_infos::{RegistryAssets, RegistryIcons};
use crate::{Error, Result};
use crate::{RegistryInfos, RegistrySource};

/// The name of the toplevel cache directory *inside* the registry directory.
const CACHE_DIRNAME: &str = "cached";

/// The cache directory where the wallets' registry cache files are stored.
/// It's written to once at initialization.
static CACHE_DIR: OnceCell<PathBuf> = OnceCell::new();

/// Mapping from sha256(xpub) to the corresponding cache file.
type CacheFiles = HashMap<String, File>;

pub(crate) static CACHE_FILES: Lazy<Mutex<CacheFiles>> = Lazy::new(|| {
    // The cache files are initialized by listing all the files inside
    // `CACHE_DIR`.

    let cache_dir = CACHE_DIR.get().expect("the cache directory has already been initialized");

    let cache_files = fs::read_dir(cache_dir)
        .expect("couldn't read the cache directory")
        .filter_map(|entry| {
            let filename =
                entry.ok()?.file_name().into_string().expect("all cache filenames are valid UTF-8");

            let file = OpenOptions::new()
                .write(true)
                .read(true)
                .create(true)
                .open(cache_dir.join(&filename))
                .ok()?;

            Some((filename, file))
        })
        .collect::<CacheFiles>();

    debug!("populated the cache with {} files", cache_files.len());

    Mutex::new(cache_files)
});

pub(crate) fn init(registry_dir: impl AsRef<Path>) -> Result<()> {
    let cache_dir = registry_dir.as_ref().join(CACHE_DIRNAME);

    if !cache_dir.exists() {
        debug!("creating registry cache directory as {:?}", cache_dir);
        fs::create_dir(&cache_dir)?;
    }

    CACHE_DIR.set(cache_dir).map_err(|_err| Error::AlreadyInitialized)?;

    if let Ok(files) = CACHE_FILES.lock() {
        debug!("loading {} cache files", files.len());
    }

    Ok(())
}

#[derive(Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Cache {
    assets: RegistryAssets,
    icons: RegistryIcons,

    /// Ids of queried assets missing from the local asset registry.
    missing_assets: Vec<AssetId>,

    /// Ids of queried assets whose icons are missing from the local icon
    /// registry.
    missing_icons: Vec<AssetId>,

    #[serde(default, skip_serializing)]
    xpub: Option<ExtendedPubKey>,
}

// Custom impl of `Debug` to avoid leaking `xpub` in log messages.
impl fmt::Debug for Cache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Cache")
            .field("assets", &self.assets)
            .field("icons", &self.icons)
            .field("missing_assets", &self.missing_assets)
            .field("missing_icons", &self.missing_icons)
            .finish()
    }
}

impl Cache {
    /// Filters the registry agains the ids in `choose`, then extends `self`
    /// with the values from the filtered registry.
    pub(crate) fn extend_from_registry(&mut self, registry: RegistryInfos, choose: &[AssetId]) {
        let RegistryInfos {
            mut assets,
            mut icons,
            ..
        } = registry;

        assets.retain(|id, _| choose.contains(id));
        icons.retain(|id, _| choose.contains(id));

        self.assets.extend(assets);
        self.icons.extend(icons);
    }

    pub(crate) fn filter(&mut self, ids: &[AssetId]) {
        self.assets.retain(|id, _| ids.contains(id));
        self.icons.retain(|id, _| ids.contains(id));
    }

    pub(crate) fn from_xpub(xpub: ExtendedPubKey, cache_files: &mut CacheFiles) -> Self {
        let get_cache = |file: &mut File| -> Result<Self> {
            let cipher = xpub.to_cipher()?;
            let decrypted = file.decrypt(&cipher)?;
            gdk_common::ciborium::from_reader(&decrypted[..]).map_err(Into::into)
        };

        let mut cache = match cache_files.get_mut(&hash_xpub(xpub)) {
            Some(file) => match get_cache(file) {
                Ok(cache) => cache,

                Err(err) => {
                    warn!("couldn't deserialize cached file due to {}", err);
                    Self::default()
                }
            },

            _ => Self::default(),
        };

        cache.xpub = Some(xpub);

        cache
    }

    pub(crate) fn is_cached(&self, id: &AssetId) -> bool {
        self.assets.contains_key(id)
    }

    pub(crate) fn is_missing(&self, id: &AssetId) -> bool {
        self.missing_assets.contains(id)
    }

    pub(crate) fn register_missing_assets(&mut self, ids: Vec<AssetId>) {
        self.missing_assets.extend(ids);
    }

    pub(crate) fn register_missing_icons(&mut self, ids: Vec<AssetId>) {
        self.missing_icons.extend(ids);
    }

    pub(crate) fn to_registry(self, from_cache: bool) -> RegistryInfos {
        let source = if from_cache {
            RegistrySource::Cache
        } else {
            RegistrySource::LocalRegistry
        };

        RegistryInfos::new_with_source(self.assets, self.icons, source)
    }

    pub(crate) fn update(&self, cache_files: &mut CacheFiles) -> Result<()> {
        let xpub = self.xpub.unwrap();

        let plain_text = ciborium_to_vec(self)?;
        let cipher = xpub.to_cipher()?;
        let (nonce, rest) = plain_text.encrypt(&cipher)?;

        let file = cache_files.entry(hash_xpub(xpub)).or_insert_with_key(|hash| {
            let cache_path =
                CACHE_DIR.get().expect("cache directory has been initialized ").join(hash);

            OpenOptions::new()
                .write(true)
                .read(true)
                .create(true)
                .open(cache_path)
                .expect("couldn't create new cache file")
        });

        // Write the file to disk.
        file.set_len(0)?;
        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(&nonce)?;
        file.write_all(&rest)?;

        Ok(())
    }

    pub(crate) fn update_missing_or_updated_assets(&mut self, present: &RegistryAssets) {
        let mut to_remove: Vec<&AssetId> =
            Vec::with_capacity(cmp::min(self.missing_assets.len(), present.len()));

        for (id, entry) in present {
            if self.missing_assets.contains(&id) {
                self.assets.insert(id.clone(), entry.clone());
                to_remove.push(id);
            }
            if let Some(asset) = self.assets.get(id) {
                if asset != entry {
                    self.assets.insert(id.clone(), entry.clone());
                }
            }
        }

        self.missing_assets.retain(|id| !to_remove.contains(&id));
    }

    pub(crate) fn update_missing_or_updated_icons(&mut self, present: &RegistryIcons) {
        let mut to_remove: Vec<&AssetId> =
            Vec::with_capacity(cmp::min(self.missing_icons.len(), present.len()));

        for (id, entry) in present {
            if self.missing_icons.contains(&id) {
                self.icons.insert(id.clone(), entry.clone());
                to_remove.push(id);
            }
            if let Some(icon) = self.icons.get(id) {
                if icon != entry {
                    self.icons.insert(id.clone(), entry.clone());
                }
            }
        }

        self.missing_icons.retain(|id| !to_remove.contains(&id));
    }
}

impl From<Cache> for RegistryInfos {
    fn from(cache: Cache) -> Self {
        Self::new(cache.assets, cache.icons)
    }
}

/// Removes `assets` from the [`Cache::missing_assets`] section of the
/// cache file associated to `xpub`.
pub(crate) fn update_missing_assets(xpub: ExtendedPubKey, assets: &RegistryAssets) -> Result<()> {
    let mut cache_files = CACHE_FILES.lock()?;
    let mut cache = Cache::from_xpub(xpub, &mut *cache_files);
    cache.update_missing_or_updated_assets(assets);
    cache.update(&mut *cache_files)
}

/// Removes `icons` from the [`Cache::missing_icons`] section of the
/// cache file associated to `xpub`.
pub(crate) fn update_missing_icons(xpub: ExtendedPubKey, icons: &RegistryIcons) -> Result<()> {
    let mut cache_files = CACHE_FILES.lock()?;
    let mut cache = Cache::from_xpub(xpub, &mut *cache_files);
    cache.update_missing_or_updated_icons(icons);
    cache.update(&mut *cache_files)
}

/// Returns the string representation of sha256(xpub).
fn hash_xpub(xpub: ExtendedPubKey) -> String {
    sha256::Hash::hash(xpub.to_string().as_bytes()).to_string()
}
