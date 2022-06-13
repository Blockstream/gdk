use crate::store::StoreMeta;
use crate::{Account, BEOutPoint, BETxid, State};
use aes_gcm_siv::aead;
use bitcoin::util::bip32::ExtendedPubKey;
use elements::hash_types::Txid;
use gdk_common::error::Error as CommonError;
use serde::ser::Serialize;
use std::collections::{HashMap, HashSet};
use std::convert::From;
use std::sync::{MutexGuard, PoisonError, RwLockReadGuard, RwLockWriteGuard};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("cannot create a new subaccount while the last one is unused")]
    AccountGapsDisallowed,

    #[error("could not parse SocketAddr `{0}`")]
    AddrParse(String),

    #[error("`asset_id` cannot be empty in Liquid")]
    AssetEmpty,

    #[error(transparent)]
    Bitcoin(#[from] bitcoin::util::Error),

    #[error(transparent)]
    BitcoinBIP32Error(#[from] bitcoin::util::bip32::Error),

    #[error(transparent)]
    BitcoinConsensus(#[from] bitcoin::consensus::encode::Error),

    #[error(transparent)]
    BitcoinHashes(#[from] bitcoin::hashes::error::Error),

    #[error(transparent)]
    BitcoinHexError(#[from] bitcoin::hashes::hex::Error),

    #[error(transparent)]
    BitcoinKeyError(#[from] bitcoin::util::key::Error),

    #[error(transparent)]
    ClientError(#[from] electrum_client::Error),

    #[error(transparent)]
    Common(#[from] CommonError),

    #[error(transparent)]
    ElementsEncode(#[from] elements::encode::Error),

    #[error(transparent)]
    ElementsPset(#[from] elements::pset::Error),

    #[error("addressees cannot be empty")]
    EmptyAddressees,

    #[error(transparent)]
    Encryption(#[from] block_modes::BlockModeError),

    #[error("fee rate is below the minimum of {0}sat/kb")]
    FeeRateBelowMinimum(u64),

    #[error(transparent)]
    JSON(#[from] serde_json::error::Error),

    #[error("insufficient funds")]
    InsufficientFunds,

    #[error("invalid address")]
    InvalidAddress,

    #[error("invalid amount")]
    InvalidAmount,

    #[error("invalid asset id")]
    InvalidAssetId,

    #[error("Invalid Electrum URL: {0}")]
    InvalidElectrumUrl(String),

    #[error("invalid headers")]
    InvalidHeaders,

    #[error(transparent)]
    InvalidKeyIvLength(#[from] block_modes::InvalidKeyIvLength),

    #[error("invalid mnemonic")]
    InvalidMnemonic,

    /// An invalid pin attempt. Should trigger an increment to the caller
    /// counter as after 3 consecutive wrong guesses the server will delete the
    /// corresponding key. Other errors should leave such counter unchanged.
    #[error("id_invalid_pin")]
    InvalidPin,

    #[error("invalid replacement request fields")]
    InvalidReplacementRequest,

    #[error(transparent)]
    InvalidStringUtf8(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    InvalidStrUtf8(#[from] std::str::Utf8Error),

    #[error("invalid subaccount {0}")]
    InvalidSubaccount(u32),

    #[error("Xpubs mismatch ({0} vs {1})")]
    MismatchingXpubs(ExtendedPubKey, ExtendedPubKey),

    #[error("Master blinding key is missing but we need it")]
    MissingMasterBlindingKey,

    #[error("Mutex is poisoned: {0}")]
    MutexPoisonError(String),

    #[error("non confidential address")]
    NonConfidentialAddress,

    #[error("id_connection_failed")]
    PinError,

    #[error("PSET and Tx mismatch ({0} vs {1})")]
    PsetAndTxMismatch(Txid, Txid),

    #[error(transparent)]
    PsetBlindError(#[from] elements::pset::PsetBlindError),

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

    #[error("sendall error")]
    SendAll,

    #[error(transparent)]
    SerdeCborError(#[from] serde_cbor::error::Error),

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

    #[error("unknown call")]
    UnknownCall,

    #[error(transparent)]
    UreqError(#[from] ureq::Error),

    #[error("wallet is not initialized")]
    WalletNotInitialized,

    #[error("{0}")]
    Generic(String),
}

pub fn fn_err(str: &str) -> impl Fn() -> Error + '_ {
    move || Error::Generic(str.into())
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

// `aead::Error` doesn't implement `std::error::Error`.
impl From<aead::Error> for Error {
    fn from(err: aead::Error) -> Self {
        Error::Generic(err.to_string())
    }
}

impl From<PoisonError<RwLockReadGuard<'_, StoreMeta>>> for Error {
    fn from(err: PoisonError<RwLockReadGuard<'_, StoreMeta>>) -> Self {
        Error::RwLockPoisonError(err.to_string())
    }
}

impl From<PoisonError<RwLockWriteGuard<'_, StoreMeta>>> for Error {
    fn from(err: PoisonError<RwLockWriteGuard<'_, StoreMeta>>) -> Self {
        Error::RwLockPoisonError(err.to_string())
    }
}

impl From<PoisonError<RwLockReadGuard<'_, State>>> for Error {
    fn from(err: PoisonError<RwLockReadGuard<'_, State>>) -> Self {
        Error::RwLockPoisonError(err.to_string())
    }
}

impl From<PoisonError<RwLockWriteGuard<'_, State>>> for Error {
    fn from(err: PoisonError<RwLockWriteGuard<'_, State>>) -> Self {
        Error::RwLockPoisonError(err.to_string())
    }
}

impl From<PoisonError<RwLockReadGuard<'_, HashMap<u32, Account>>>> for Error {
    fn from(err: PoisonError<RwLockReadGuard<'_, HashMap<u32, Account>>>) -> Self {
        Error::RwLockPoisonError(err.to_string())
    }
}

impl From<PoisonError<RwLockWriteGuard<'_, HashMap<u32, Account>>>> for Error {
    fn from(err: PoisonError<RwLockWriteGuard<'_, HashMap<u32, Account>>>) -> Self {
        Error::RwLockPoisonError(err.to_string())
    }
}

impl From<PoisonError<RwLockReadGuard<'_, HashSet<BEOutPoint>>>> for Error {
    fn from(err: PoisonError<RwLockReadGuard<'_, HashSet<BEOutPoint>>>) -> Self {
        Error::RwLockPoisonError(err.to_string())
    }
}

impl From<PoisonError<RwLockWriteGuard<'_, HashSet<BEOutPoint>>>> for Error {
    fn from(err: PoisonError<RwLockWriteGuard<'_, HashSet<BEOutPoint>>>) -> Self {
        Error::RwLockPoisonError(err.to_string())
    }
}

impl From<PoisonError<MutexGuard<'_, ()>>> for Error {
    fn from(err: PoisonError<MutexGuard<'_, ()>>) -> Self {
        Error::MutexPoisonError(err.to_string())
    }
}
