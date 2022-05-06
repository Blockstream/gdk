use std::{
    fs::File,
    io,
    sync::{MutexGuard, PoisonError},
};

/// Contains all the error variants possibly happening in this library
#[derive(Debug)]
pub enum Error {
    /// Thrown when neither assets nor icons are requested in [`crate::RefreshAssetsParam`]
    BothAssetsIconsFalse,

    /// Thrown when calling `crate::init` more than once
    AlreadyInitialized,

    /// Thrown when the method requires the registry to be initialized (via the `crate::init` call)
    /// but it wasn't initialized
    RegistryUninitialized,

    /// An invalid network as been specified
    InvalidNetwork(String),

    /// Wraps IO errors
    Io(io::Error),

    /// Wraps errors happened when serializing or deserializing JSONs
    SerdeJson(serde_json::Error),

    /// Wraps errors happened when serializing or deserializing JSONs
    SerdeCbor(serde_cbor::Error),

    /// Wraps http errors
    Ureq(ureq::Error),

    /// Wraps hex parsing error
    Hex(elements::bitcoin::hashes::hex::Error),

    /// Wrap a poison error as string to avoid pollute with lifetimes
    Poison(String),
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::SerdeJson(e)
    }
}

impl From<serde_cbor::Error> for Error {
    fn from(e: serde_cbor::Error) -> Self {
        Error::SerdeCbor(e)
    }
}

impl From<ureq::Error> for Error {
    fn from(e: ureq::Error) -> Self {
        Error::Ureq(e)
    }
}

impl From<elements::bitcoin::hashes::hex::Error> for Error {
    fn from(e: elements::bitcoin::hashes::hex::Error) -> Self {
        Error::Hex(e)
    }
}

impl From<PoisonError<MutexGuard<'_, File>>> for Error {
    fn from(e: PoisonError<MutexGuard<'_, File>>) -> Self {
        Error::Poison(e.to_string())
    }
}
