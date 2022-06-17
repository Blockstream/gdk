//! The inner module contain the code needed to access the file containing the registry values
//! It contains unsafe code since we need a `static mut` variable representing the files guarded
//! by a `Mutex`

use crate::hard::hard_coded_values;
use crate::result::RefreshAssetsResult;
use crate::{file, AssetsOrIcons, ElementsNetwork, Error, Result, ValueModified};
use std::fs::OpenOptions;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::MutexGuard;
use std::{collections::HashMap, fs::File, sync::Mutex};
use std::{fs, hint};

const UNINITIALIZED: usize = 0;
const INITIALIZING: usize = 1;
const INITIALIZED: usize = 2;

macro_rules! initialize {
    ($body:expr) => {{
        /// By having the static `STATE` inside the function, it cannot be
        /// accessed out of this fn.
        static STATE: AtomicUsize = AtomicUsize::new(UNINITIALIZED);

        let old_state = match STATE.compare_exchange(
            UNINITIALIZED,
            INITIALIZING,
            Ordering::SeqCst,
            Ordering::SeqCst,
        ) {
            Ok(s) | Err(s) => s,
        };

        match old_state {
            UNINITIALIZED => {
                let res: Result<()> = $body;
                res?;
                STATE.store(INITIALIZED, Ordering::SeqCst);
                Ok(())
            }
            INITIALIZING => {
                while STATE.load(Ordering::SeqCst) == INITIALIZING {
                    // Giving time to the thread entered the UNINITIALIZED case
                    // to finish his job. When this loop finishes even this
                    // thread is sure to be INITIALIZED.
                    hint::spin_loop();
                }
                Err(Error::AlreadyInitialized)
            }
            _ => Err(Error::AlreadyInitialized),
        }
    }};
}

type RegistryFiles = Option<HashMap<(ElementsNetwork, AssetsOrIcons), Mutex<File>>>;
static mut REGISTRY_FILES: RegistryFiles = None;

/// Initialize the library by giving the root directory `dir`, where will be
/// persisted cached data.
pub fn init<P: AsRef<Path>>(dir: P) -> Result<()> {
    initialize!({
        let mut files = HashMap::new();
        for b in AssetsOrIcons::iter() {
            for n in ElementsNetwork::iter() {
                let mut file_path = dir.as_ref().to_path_buf();
                file_path.push(n.to_string());
                fs::create_dir_all(&file_path)?;
                file_path.push(b.to_string());
                let file_exists = file_path.exists();

                let mut file =
                    OpenOptions::new().write(true).read(true).create(true).open(file_path)?;

                if !file_exists {
                    let hard_coded_values = hard_coded_values(n, b);
                    let value_modified = ValueModified {
                        value: hard_coded_values,
                        last_modified: "".to_string(),
                    };
                    file::write(&value_modified, &mut file)?;
                }

                files.insert((n, b), Mutex::new(file));
            }
        }
        unsafe {
            REGISTRY_FILES = Some(files);
        }
        init_cache(dir)
    })
}

type CacheFiles = Option<HashMap<ElementsNetwork, Mutex<File>>>;
static mut CACHE_FILES: CacheFiles = None;

fn init_cache<P: AsRef<Path>>(registry_dir: P) -> Result<()> {
    initialize!({
        let files = ElementsNetwork::iter()
            .map(|network| {
                // TODO: create one cache file per wallet.
                // TODO: encrypt cache.
                let path = registry_dir.as_ref().join(network.to_string()).join("user");
                let exists = path.exists();
                let mut file =
                    OpenOptions::new().write(true).read(true).create(true).open(&path)?;

                if !exists {
                    file::write(&RefreshAssetsResult::default(), &mut file)?;
                }

                Ok((network, Mutex::new(file)))
            })
            .collect::<Result<HashMap<ElementsNetwork, Mutex<File>>>>()?;

        unsafe {
            CACHE_FILES = Some(files);
        }

        Ok(())
    })
}

/// Only way to access `File`s containing the global registry information.
pub fn get_file(network: ElementsNetwork, t: AssetsOrIcons) -> Result<MutexGuard<'static, File>> {
    unsafe {
        match REGISTRY_FILES.as_ref() {
            Some(registry_files) => Ok(registry_files
                .get(&(network, t))
                .expect("any combination is initialized")
                .lock()?),

            None => Err(Error::RegistryUninitialized),
        }
    }
}

/// Get access to the cache file relative to a specific network.
pub fn get_cache(network: ElementsNetwork) -> Result<MutexGuard<'static, File>> {
    unsafe {
        match CACHE_FILES.as_ref() {
            Some(files) => {
                Ok(files.get(&network).expect("all cache files are initialized").lock()?)
            }

            None => Err(Error::RegistryUninitialized),
        }
    }
}
