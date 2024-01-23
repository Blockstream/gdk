use gdk_common::{bitcoin, serde_cbor, ureq};
use std::sync::{MutexGuard, PoisonError, TryLockError};

/// Result type alias of the `gdk_registry` crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Error enum of the `gdk_registry` crate.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Thrown when calling `crate::init` more than once.
    #[error("Cannot call `init` more than once")]
    AlreadyInitialized,

    /// Thrown when neither assets nor icons are requested in
    /// [`crate::RefreshAssetsParams`]
    #[error("Neither assets nor icons were requested")]
    BothAssetsIconsFalse,

    /// Returned when calling `ExtendedPubKey::from_str` with an invalid
    /// string.
    #[error(transparent)]
    BtcBip32Error(#[from] bitcoin::bip32::Error),

    /// Wraps errors coming from the `gdk_common` crate.
    #[error(transparent)]
    Common(#[from] gdk_common::Error),

    /// Returned when both `assets_id` and some other field is set when calling
    /// [`get_assets`](crate::get_assets).
    #[error("Cannot call `get_assets` with both `assets_id` and another field set")]
    GetAssetsIdNotAlone,

    /// Returned when none of the fields of
    /// [`GetAssetsParams`](crate::GetAssetsParams) are set when calling
    /// [`get_assets`](crate::get_assets).
    #[error("Specify either `assets_id` or one of more of the following fields when calling `get_assets`: `names`, `tickers`, `category`")]
    GetAssetsNoFields,

    /// An invalid network as been specified
    #[error("InvalidNetwork({0})")]
    InvalidNetwork(String),

    /// Wraps IO errors.
    #[error(transparent)]
    Io(#[from] std::io::Error),

    /// Returned when trying to lock a Mutex while another thread has the lock.
    #[error("Another thread is holding the Mutex's lock")]
    MutexBusy,

    /// Wrap a poison error as string to avoid pollute with lifetimes.
    #[error("{0}")]
    Poison(String),

    /// Returned when a registry cache file has yet to be created.
    #[error("Registry cache for this wallet has not been created")]
    CacheNotCreated,

    /// Thrown when a method requires the registry to be initialized (via the
    /// [`crate::init`] call) but it wasn't initialized.
    #[error("Registry has not been initialized")]
    RegistryUninitialized,

    /// Wraps errors happened when serializing or deserializing JSONs.
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    /// Wraps http errors.
    #[error(transparent)]
    Ureq(#[from] ureq::Error),

    /// Wraps serde error.
    #[error(transparent)]
    SerdeCbor(#[from] serde_cbor::Error),

    /// A generic error.
    #[error("{0}")]
    Generic(String),
}

impl<T> From<PoisonError<MutexGuard<'_, T>>> for Error {
    fn from(e: PoisonError<MutexGuard<'_, T>>) -> Self {
        Error::Poison(e.to_string())
    }
}

impl<T> From<TryLockError<MutexGuard<'_, T>>> for Error {
    fn from(err: TryLockError<MutexGuard<'_, T>>) -> Self {
        match err {
            TryLockError::Poisoned(p) => p.into(),
            TryLockError::WouldBlock => Self::MutexBusy,
        }
    }
}
