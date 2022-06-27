//! The inner module contain the code needed to access the file containing the registry values
//! It contains unsafe code since we need a `static mut` variable representing the files guarded
//! by a `Mutex`

use crate::hard::hard_coded_values;
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

type RegistryFiles = Option<HashMap<(ElementsNetwork, AssetsOrIcons), Mutex<File>>>;
static mut REGISTRY_FILES: RegistryFiles = None;

/// Initialize the library by giving the root directory `dir`, where will be
/// persisted cached data.
pub fn init<P: AsRef<Path>>(dir: P) -> Result<()> {
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
            STATE.store(INITIALIZED, Ordering::SeqCst);
            crate::registry_cache::init_dir(dir)
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
}

/// Only way to access `File`s containing the global registry information.
pub fn get_full_registry(
    network: ElementsNetwork,
    t: AssetsOrIcons,
) -> Result<MutexGuard<'static, File>> {
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
