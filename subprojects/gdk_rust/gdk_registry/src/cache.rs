use std::cmp;
use std::collections::HashMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aes_gcm_siv::aead::{AeadInPlace, NewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::util::bip32::ExtendedPubKey;
use elements::AssetId;
use log::debug;
use once_cell::sync::{Lazy, OnceCell};
use rand::Rng;
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

static CACHE_FILES: Lazy<Mutex<CacheFiles>> = Lazy::new(|| {
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

    /// Ids of queried assets missing from the registry.
    missing: Vec<AssetId>,

    #[serde(default, skip_serializing)]
    xpub: Option<ExtendedPubKey>,
}

// Custom impl of `Debug` to avoid leaking `xpub` in log messages.
impl fmt::Debug for Cache {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Cache")
            .field("assets", &self.assets)
            .field("icons", &self.icons)
            .field("missing", &self.missing)
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

    pub(crate) fn from_xpub(xpub: ExtendedPubKey) -> Result<Self> {
        let mut cache_files = CACHE_FILES.lock()?;

        let mut cache = match cache_files.get_mut(&hash_xpub(xpub)) {
            Some(file) => {
                let decrypted = self::decrypt(file, xpub)?;
                serde_cbor::from_slice::<Self>(&decrypted)
            }

            _ => Ok(Self::default()),
        }?;

        cache.xpub = Some(xpub);
        Ok(cache)
    }

    pub(crate) fn is_cached(&self, id: &AssetId) -> bool {
        self.assets.contains_key(id)
    }

    pub(crate) fn is_missing(&self, id: &AssetId) -> bool {
        self.missing.contains(id)
    }

    pub(crate) fn register_missing(&mut self, ids: Vec<AssetId>) {
        self.missing.extend(ids);
    }

    pub(crate) fn to_registry(self, from_cache: bool) -> RegistryInfos {
        let source = if from_cache {
            RegistrySource::Cache
        } else {
            RegistrySource::LocalRegistry
        };

        RegistryInfos::new_with_source(self.assets, self.icons, source)
    }

    pub(crate) fn update(&self) -> Result<()> {
        let xpub = self.xpub.unwrap();

        let plain_text = serde_cbor::to_vec(self)?;
        let (nonce, rest) = encrypt(plain_text, xpub)?;

        let mut cache_files = CACHE_FILES.lock()?;

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
        file.seek(std::io::SeekFrom::Start(0))?;
        file.write_all(&nonce)?;
        file.write_all(&rest)?;

        Ok(())
    }

    pub(crate) fn update_missing(&mut self, present: &RegistryAssets) {
        let mut to_remove: Vec<&AssetId> =
            Vec::with_capacity(cmp::min(self.missing.len(), present.len()));

        for (id, entry) in present {
            if self.missing.contains(&id) {
                self.assets.insert(id.clone(), entry.clone());
                to_remove.push(id);
            }
        }

        self.missing.retain(|id| !to_remove.contains(&id));
    }
}

impl From<Cache> for RegistryInfos {
    fn from(cache: Cache) -> Self {
        Self::new(cache.assets, cache.icons)
    }
}

/// Removes the asset ids specified in `ids` from the [`Cache::missing`]
/// section of each cache file associated to an xpub contained in `xpubs`.
pub(crate) fn update_missing(xpubs: &[ExtendedPubKey], assets: &RegistryAssets) -> Result<()> {
    // TODO: 1.63 introduces scoped threads. Once we update the compiler
    // version we can do this in parallel w/o cloning `xpub` or `assets`.

    for xpub in xpubs {
        let mut cache = Cache::from_xpub(*xpub)?;
        cache.update_missing(assets);
        cache.update()?;
    }

    Ok(())
}

/// Decrypts the contents of a file using a cipher derived from the provided
/// xpub.
fn decrypt(file: &mut File, xpub: ExtendedPubKey) -> Result<Vec<u8>> {
    file.seek(std::io::SeekFrom::Start(0))?;

    let mut nonce_bytes = [0u8; 12];
    file.read_exact(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    let mut data = Vec::<u8>::new();
    file.read_to_end(&mut data)?;

    let cipher = to_cipher(xpub);
    cipher.decrypt_in_place(nonce, b"", &mut data)?;

    Ok(data)
}

/// Encrypts the given data using a cipher derived from the provided xpub.
fn encrypt(mut data: Vec<u8>, xpub: ExtendedPubKey) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = to_cipher(xpub);
    cipher.encrypt_in_place(nonce, b"", &mut data)?;

    Ok((nonce_bytes.to_vec(), data))
}

/// Gets a cipher from an xpub. Taken from `gdk_electrum::store::get_cipher`.
fn to_cipher(xpub: ExtendedPubKey) -> Aes256GcmSiv {
    let mut enc_key_data = vec![];
    enc_key_data.extend(&xpub.public_key.to_bytes());
    enc_key_data.extend(&xpub.chain_code.to_bytes());
    enc_key_data.extend(&xpub.network.magic().to_be_bytes());
    let key_bytes = sha256::Hash::hash(&enc_key_data).into_inner();
    let key = Key::from_slice(&key_bytes);
    Aes256GcmSiv::new(&key)
}

/// Returns the string representation of sha256(xpub).
fn hash_xpub(xpub: ExtendedPubKey) -> String {
    sha256::Hash::hash(xpub.to_string().as_bytes()).to_string()
}
