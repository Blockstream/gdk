use std::{
    fs::File,
    io,
    sync::{MutexGuard, PoisonError},
};

use aes_gcm_siv::aead;

/// Custom `Result`.
pub type Result<T> = std::result::Result<T, Error>;

/// Contains all the error variants possibly happening in this library
#[derive(thiserror::Error, Debug)]
pub enum Error {
    /// Thrown when neither assets nor icons are requested in [`crate::RefreshAssetsParam`]
    #[error("Neither assets nor icons were requested")]
    BothAssetsIconsFalse,

    /// Thrown when calling `crate::init` more than once
    #[error("Cannot call `init` more than once")]
    AlreadyInitialized,

    /// Returned when calling `ExtendedPubKey::from_str` with an invalid
    /// string.
    #[error(transparent)]
    BtcBip32Error(#[from] bitcoin::util::bip32::Error),

    /// Returned when a registry cache file has yet to be created.
    #[error("Registry cache for this wallet has not been created")]
    RegistryCacheNotCreated,

    /// Thrown when the method requires the registry to be initialized (via the `crate::init` call)
    /// but it wasn't initialized
    #[error("Registry has not been initialized")]
    RegistryUninitialized,

    /// An invalid network as been specified
    #[error("InvalidNetwork({0})")]
    InvalidNetwork(String),

    /// Wraps IO errors
    #[error(transparent)]
    Io(#[from] io::Error),

    /// Wraps errors happened when serializing or deserializing JSONs
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

    /// Wraps errors happened when serializing or deserializing JSONs
    #[error(transparent)]
    SerdeCbor(#[from] serde_cbor::Error),

    /// Wraps http errors
    #[error(transparent)]
    Ureq(#[from] ureq::Error),

    /// Wraps hex parsing error
    #[error(transparent)]
    Hex(#[from] elements::bitcoin::hashes::hex::Error),

    /// Wrap a poison error as string to avoid pollute with lifetimes
    #[error("{0}")]
    Poison(String),

    /// A generic error.
    #[error("{0}")]
    Generic(String),
}

// `aead::Error` doesn't implement `std::error::Error`.
impl From<aead::Error> for Error {
    fn from(err: aead::Error) -> Self {
        Error::Generic(err.to_string())
    }
}

impl From<PoisonError<MutexGuard<'_, File>>> for Error {
    fn from(e: PoisonError<MutexGuard<'_, File>>) -> Self {
        Error::Poison(e.to_string())
    }
}
