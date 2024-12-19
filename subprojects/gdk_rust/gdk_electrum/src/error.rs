use crate::BETxid;
use gdk_common::bitcoin::bip32::Xpub;
use gdk_common::error::Error as CommonError;
use gdk_common::{bitcoin, electrum_client, elements, serde_cbor, ureq};
use serde::ser::Serialize;
use std::convert::From;
use std::path::PathBuf;
use std::sync::{MutexGuard, PoisonError, RwLockReadGuard, RwLockWriteGuard};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("cannot create a new subaccount while the last one is unused")]
    AccountGapsDisallowed,

    #[error("could not parse SocketAddr `{0}`")]
    AddrParse(String),

    #[error("Expected a {expected}")]
    AvailableIndexesBadResponse {
        expected: String,
    },

    #[error(transparent)]
    Base64DecodeError(#[from] base64::DecodeError),

    #[error(transparent)]
    BitcoinAddressParseError(#[from] bitcoin::address::ParseError),

    #[error(transparent)]
    BitcoinBIP32Error(#[from] bitcoin::bip32::Error),

    #[error(transparent)]
    BitcoinConsensus(#[from] bitcoin::consensus::encode::Error),

    #[error(transparent)]
    BitcoinHexToBytesError(#[from] bitcoin::hashes::hex::HexToBytesError),

    #[error(transparent)]
    BitcoinHexToArrayError(#[from] bitcoin::hashes::hex::HexToArrayError),

    #[error(transparent)]
    BitcoinKeyError(#[from] bitcoin::key::ParsePublicKeyError),

    #[error(transparent)]
    ParseCompressed(#[from] bitcoin::key::ParseCompressedPublicKeyError),

    #[error(transparent)]
    ClientError(#[from] electrum_client::Error),

    #[error(transparent)]
    Common(#[from] CommonError),

    #[error(transparent)]
    ElementsAddressError(#[from] elements::address::AddressError),

    #[error(transparent)]
    ElementsEncode(#[from] elements::encode::Error),

    #[error(transparent)]
    ElementsMiniscriptError(#[from] gdk_common::elements_miniscript::Error),

    #[error(transparent)]
    Encryption(#[from] block_modes::BlockModeError),

    #[error(transparent)]
    JSON(#[from] serde_json::error::Error),

    #[error(transparent)]
    SerdeCbor(#[from] serde_cbor::Error),

    #[error("Invalid Electrum URL: {0}")]
    InvalidElectrumUrl(String),

    #[error("invalid headers")]
    InvalidHeaders,

    #[error(transparent)]
    InvalidKeyIvLength(#[from] block_modes::InvalidKeyIvLength),

    #[error("Sync interrupted because user doesn't want to sync")]
    UserDoesntWantToSync,

    #[error(transparent)]
    InvalidStringUtf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    InvalidStrUtf8(#[from] std::str::Utf8Error),

    #[error("invalid subaccount {0}")]
    InvalidSubaccount(u32),

    #[error(transparent)]
    MiniscriptError(#[from] gdk_common::miniscript::Error),

    #[error("Xpubs mismatch ({0} vs {1})")]
    MismatchingXpubs(Xpub, Xpub),

    #[error("Master blinding key is missing but we need it")]
    MissingMasterBlindingKey,

    #[error("Mutex is poisoned: {0}")]
    MutexPoisonError(String),

    #[error("Invalid proxy socket: {0}")]
    InvalidProxySocket(String),

    #[error("{}", match .0 {
        gdk_pin_client::Error::InvalidPin
        | gdk_pin_client::Error::Decryption(_) => "id_invalid_pin",
        _ => "id_connection_failed",
    })]
    PinClient(#[from] gdk_pin_client::Error),

    #[error("RW lock is poisoned: {0}")]
    RwLockPoisonError(String),

    #[error("Scriptpubkey not found")]
    ScriptPubkeyNotFound,

    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),

    #[error(transparent)]
    Secp256k1Zkp(#[from] elements::secp256k1_zkp::Error),

    #[error(transparent)]
    Send(#[from] std::sync::mpsc::SendError<()>),

    #[error(transparent)]
    SliceConversionError(#[from] std::array::TryFromSliceError),

    #[error(transparent)]
    StdIOError(#[from] std::io::Error),

    #[error("attempt to access the store without calling load_store first")]
    StoreNotLoaded,

    #[error("Transaction not found ({0})")]
    TxNotFound(BETxid),

    #[error(transparent)]
    UnblindError(#[from] elements::UnblindError),

    #[error(transparent)]
    UreqError(#[from] ureq::Error),

    //#[error(transparent)]
    //Sighash(#[from] sighash::Error),
    #[error(
        "{}method not found: {method:?}",
        if *.in_session { "session " } else {""}
    )]
    MethodNotFound {
        method: String,
        in_session: bool,
    },

    #[error("{0} does not exist")]
    FileNotExist(PathBuf),

    #[error("{0}")]
    Generic(String),
}

impl Serialize for Error {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&format!("{}", self))
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(_err: std::net::AddrParseError) -> Self {
        Error::AddrParse("SocketAddr parse failure with no additional info".into())
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::Generic(err)
    }
}

impl<T> From<PoisonError<RwLockReadGuard<'_, T>>> for Error {
    fn from(err: PoisonError<RwLockReadGuard<'_, T>>) -> Self {
        Error::RwLockPoisonError(err.to_string())
    }
}

impl<T> From<PoisonError<RwLockWriteGuard<'_, T>>> for Error {
    fn from(err: PoisonError<RwLockWriteGuard<'_, T>>) -> Self {
        Error::RwLockPoisonError(err.to_string())
    }
}

impl<T> From<PoisonError<MutexGuard<'_, T>>> for Error {
    fn from(err: PoisonError<MutexGuard<'_, T>>) -> Self {
        Error::MutexPoisonError(err.to_string())
    }
}

impl Error {
    /// Convert the error to a GDK-compatible code.
    pub fn to_gdk_code(&self) -> String {
        use super::Error::*;
        match *self {
            // An invalid pin attempt. Should trigger an increment to the
            // caller counter as after 3 consecutive wrong guesses the server
            // will delete the corresponding key. Other errors should leave
            // such counter unchanged.
            PinClient(gdk_pin_client::Error::InvalidPin | gdk_pin_client::Error::Decryption(_)) => {
                "id_invalid_pin"
            }
            PinClient(_) => "id_connection_failed",
            _ => "id_unknown",
        }
        .to_string()
    }
}
