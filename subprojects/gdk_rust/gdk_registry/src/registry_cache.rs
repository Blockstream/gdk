use rand::Rng;
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use aes_gcm_siv::aead::{AeadInPlace, NewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::util::bip32::ExtendedPubKey;
use log::debug;
use once_cell::sync::{Lazy, OnceCell};

use crate::cache_result::CacheResult;
use crate::{Error, Result};

const REGISTRY_CACHE_BASENAME: &str = "cached";

/// The directory where the wallets' registry cache files are stored. It's
/// written to only once at initialization.
static REGISTRY_CACHE_DIR: OnceCell<PathBuf> = OnceCell::new();

/// Mapping from sha256(xpub) to the corresponding cache file.
type CacheFiles = HashMap<String, Mutex<File>>;

static REGISTRY_CACHE_FILES: Lazy<Mutex<CacheFiles>> = Lazy::new(|| {
    // Populate the cache by listing all the files in `REGISTRY_CACHE_DIR`.

    let cache_dir = REGISTRY_CACHE_DIR.get().expect("cache directory has already been initialized");

    let cache_files = fs::read_dir(cache_dir)
        .expect("couldn't read cache directory")
        .map(|file| {
            file.unwrap().file_name().into_string().expect("all cache filenames are valid UTF-8")
        })
        .map(|filename| {
            let file_path = cache_dir.join(&filename);
            let file =
                OpenOptions::new().write(true).read(true).create(true).open(file_path).unwrap();
            (filename, Mutex::new(file))
        })
        .collect::<CacheFiles>();

    debug!("populated the cache with {} files", cache_files.len());

    Mutex::new(cache_files)
});

/// Creates the registry cache directory if not already present.
pub fn init_dir<D>(registry_dir: D) -> Result<()>
where
    D: AsRef<Path>,
{
    let dir = registry_dir.as_ref().join(REGISTRY_CACHE_BASENAME);

    if !dir.exists() {
        debug!("creating registry cache directory at {:?}", dir);
        fs::create_dir(&dir)?;
    }

    REGISTRY_CACHE_DIR.set(dir).map_err(|_err| Error::AlreadyInitialized)?;
    debug!("loading {} cache files", REGISTRY_CACHE_FILES.lock().unwrap().len());

    Ok(())
}

/// Returns the cache file relative to a specific wallet if it exists, or
/// an error otherwise.
pub fn read(xpub: &ExtendedPubKey) -> Result<CacheResult> {
    let cache_files = REGISTRY_CACHE_FILES.lock().unwrap();

    let mut file = match cache_files.get(&hash_xpub(xpub)) {
        Some(file) => file.lock().map_err(Error::from),
        None => Err(Error::RegistryCacheNotCreated),
    }?;

    let decrypted = decrypt(&mut file, xpub)?;
    serde_cbor::from_slice(&decrypted).map_err(Error::from)
}

/// Updates the cache file corresponding to a given xpub key.
pub fn write(xpub: &ExtendedPubKey, contents: &CacheResult) -> Result<()> {
    let plain_text = serde_cbor::to_vec(contents)?;
    let (nonce, rest) = encrypt(plain_text, xpub)?;

    let cache_path = REGISTRY_CACHE_DIR
        .get()
        .expect("cache directory has been initialized ")
        .join(hash_xpub(xpub));

    let mut file = OpenOptions::new().write(true).read(true).create(true).open(cache_path)?;

    // Write the file to disk.
    file.seek(std::io::SeekFrom::Start(0))?;
    file.write_all(&nonce)?;
    file.write_all(&rest)?;

    // Update the cache files.
    let mut cache_files = REGISTRY_CACHE_FILES.lock().unwrap();
    cache_files.insert(hash_xpub(xpub), Mutex::new(file));

    Ok(())
}

/// Decrypts the contents of a file using a cipher derived from the provided
/// xpub.
fn decrypt(file: &mut File, xpub: &ExtendedPubKey) -> Result<Vec<u8>> {
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
fn encrypt(mut data: Vec<u8>, xpub: &ExtendedPubKey) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut nonce_bytes = [0u8; 12];
    rand::thread_rng().fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let cipher = to_cipher(xpub);
    cipher.encrypt_in_place(nonce, b"", &mut data)?;

    Ok((nonce_bytes.to_vec(), data))
}

/// Gets a cipher from an xpub. Taken from `gdk_electrum::store::get_cipher`.
fn to_cipher(xpub: &ExtendedPubKey) -> Aes256GcmSiv {
    let mut enc_key_data = vec![];
    enc_key_data.extend(&xpub.public_key.to_bytes());
    enc_key_data.extend(&xpub.chain_code.to_bytes());
    enc_key_data.extend(&xpub.network.magic().to_be_bytes());
    let key_bytes = sha256::Hash::hash(&enc_key_data).into_inner();
    let key = Key::from_slice(&key_bytes);
    Aes256GcmSiv::new(&key)
}

/// Returns the string representation of sha256(xpub).
fn hash_xpub(xpub: &ExtendedPubKey) -> String {
    sha256::Hash::hash(xpub.to_string().as_bytes()).to_string()
}
