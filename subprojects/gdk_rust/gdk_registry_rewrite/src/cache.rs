use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use log::debug;
use once_cell::sync::{Lazy, OnceCell};

use crate::{Error, Result};

/// The name of the toplevel cache directory *inside* the registry directory.
const CACHE_DIRNAME: &str = "cached";

/// The cache directory where the wallets' registry cache files are stored.
/// It's written to once at initialization.
static CACHE_DIR: OnceCell<PathBuf> = OnceCell::new();

/// Mapping from sha256(xpub) to the corresponding cache file.
type CacheFiles = HashMap<String, Mutex<File>>;

static CACHE_FILES: Lazy<Mutex<CacheFiles>> = Lazy::new(|| {
    // The cache files are initialized by listing all the files inside
    // `CACHE_DIR`.

    let cache_dir = CACHE_DIR
        .get()
        .expect("the cache directory has already been initialized");

    let cache_files = fs::read_dir(cache_dir)
        .expect("couldn't read the cache directory")
        .filter_map(|entry| {
            let filename = entry
                .ok()?
                .file_name()
                .into_string()
                .expect("all cache filenames are valid UTF-8");

            let file = OpenOptions::new()
                .write(true)
                .read(true)
                .create(true)
                .open(cache_dir.join(&filename))
                .ok()?;

            Some((filename, Mutex::new(file)))
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

    CACHE_DIR
        .set(cache_dir)
        .map_err(|_err| Error::AlreadyInitialized)?;

    if let Ok(files) = CACHE_FILES.lock() {
        debug!("loading {} cache files", files.len());
    }

    Ok(())
}
