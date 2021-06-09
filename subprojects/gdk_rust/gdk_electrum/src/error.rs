use crate::store::StoreMeta;
use aes_gcm_siv::aead;
use serde::ser::Serialize;
use std::convert::From;
use std::fmt::Display;
use std::sync::{PoisonError, RwLockReadGuard, RwLockWriteGuard};

#[derive(Debug)]
pub enum Error {
    Generic(String),
    UnknownCall,
    InvalidMnemonic,
    InsufficientFunds,
    InvalidAddress,
    InvalidAmount,
    EmptyAddressees,
    AssetEmpty,
    InvalidHeaders,
    InvalidSubaccount(u32),
    AccountGapsDisallowed,
    InvalidReplacementRequest,
    SendAll,
    PinError,
    /// An invalid pin attempt. Should trigger an increment to the caller counter as after 3
    /// consecutive wrong guesses the server will delete the corresponding key. Other errors should
    /// leave such counter unchanged.
    InvalidPin,
    AddrParse(String),
    InvalidElectrumUrl(String),
    Bitcoin(bitcoin::util::Error),
    BitcoinHashes(bitcoin::hashes::error::Error),
    BitcoinBIP32Error(bitcoin::util::bip32::Error),
    BitcoinConsensus(bitcoin::consensus::encode::Error),
    JSON(serde_json::error::Error),
    StdIOError(std::io::Error),
    Hex(hex::FromHexError),
    ClientError(electrum_client::Error),
    SliceConversionError(std::array::TryFromSliceError),
    ElementsEncode(elements::encode::Error),
    Common(gdk_common::error::Error),
    Send(std::sync::mpsc::SendError<()>),
    Encryption(block_modes::BlockModeError),
    Secp256k1(bitcoin::secp256k1::Error),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Error::Generic(ref strerr) => write!(f, "{}", strerr),
            Error::AddrParse(ref addr) => write!(f, "could not parse SocketAddr `{}`", addr),
            Error::InvalidMnemonic => write!(f, "invalid mnemonic"),
            Error::InsufficientFunds => write!(f, "insufficient funds"),
            Error::SendAll => write!(f, "sendall error"),
            Error::InvalidAddress => write!(f, "invalid address"),
            Error::InvalidAmount => write!(f, "invalid amount"),
            Error::InvalidHeaders => write!(f, "invalid headers"),
            Error::EmptyAddressees => write!(f, "addressees cannot be empty"),
            Error::AssetEmpty => write!(f, "asset_id cannot be empty in liquid"),
            Error::InvalidSubaccount(sub) => write!(f, "invalid subaccount {}", sub),
            Error::AccountGapsDisallowed => {
                write!(f, "cannot create a new subaccount while the last one is unused")
            }
            Error::InvalidReplacementRequest => write!(f, "invalid replacement request fields"),
            Error::UnknownCall => write!(f, "unknown call"),
            Error::Bitcoin(ref btcerr) => write!(f, "bitcoin: {}", btcerr),
            Error::BitcoinHashes(ref btcerr) => write!(f, "bitcoin_hashes: {}", btcerr),
            Error::BitcoinBIP32Error(ref bip32err) => write!(f, "bip32: {}", bip32err),
            Error::BitcoinConsensus(ref consensus_err) => write!(f, "consensus: {}", consensus_err),
            Error::JSON(ref json_err) => write!(f, "json: {}", json_err),
            Error::StdIOError(ref io_err) => write!(f, "io: {}", io_err),
            Error::Hex(ref hex_err) => write!(f, "hex: {}", hex_err),
            Error::ClientError(ref client_err) => write!(f, "client: {:?}", client_err),
            Error::SliceConversionError(ref slice_err) => write!(f, "slice: {}", slice_err),
            Error::ElementsEncode(ref el_err) => write!(f, "el_err: {}", el_err),
            Error::Common(ref cmn_err) => write!(f, "cmn_err: {:?}", cmn_err),
            Error::Send(ref send_err) => write!(f, "send_err: {:?}", send_err),
            Error::Encryption(ref send_err) => write!(f, "encryption_err: {:?}", send_err),
            Error::Secp256k1(ref err) => write!(f, "Secp256k1_err: {:?}", err),
            Error::PinError => write!(f, "PinError"),
            Error::InvalidPin => write!(f, "invalid pin"),
            Error::InvalidElectrumUrl(url) => write!(f, "Invalid Electrum URL: {}", url),
        }
    }
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

impl From<std::array::TryFromSliceError> for Error {
    fn from(err: std::array::TryFromSliceError) -> Self {
        Error::SliceConversionError(err)
    }
}

impl From<std::net::AddrParseError> for Error {
    fn from(_err: std::net::AddrParseError) -> Self {
        Error::AddrParse("SocketAddr parse failure with no additional info".into())
    }
}

impl From<serde_json::error::Error> for Error {
    fn from(err: serde_json::error::Error) -> Self {
        Error::JSON(err)
    }
}

impl From<bitcoin::util::bip32::Error> for Error {
    fn from(err: bitcoin::util::bip32::Error) -> Self {
        Error::BitcoinBIP32Error(err)
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Error::Generic(err)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::StdIOError(err)
    }
}

impl From<bitcoin::consensus::encode::Error> for Error {
    fn from(err: bitcoin::consensus::encode::Error) -> Self {
        Error::BitcoinConsensus(err)
    }
}

impl From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Self {
        Error::Hex(err)
    }
}

impl From<electrum_client::Error> for Error {
    fn from(err: electrum_client::Error) -> Self {
        Error::ClientError(err)
    }
}

impl From<bitcoin::hashes::error::Error> for Error {
    fn from(err: bitcoin::hashes::error::Error) -> Self {
        Error::BitcoinHashes(err)
    }
}
impl From<elements::encode::Error> for Error {
    fn from(err: elements::encode::Error) -> Self {
        Error::ElementsEncode(err)
    }
}

impl From<gdk_common::error::Error> for Error {
    fn from(err: gdk_common::error::Error) -> Self {
        Error::Common(err)
    }
}

impl From<std::sync::mpsc::SendError<()>> for Error {
    fn from(err: std::sync::mpsc::SendError<()>) -> Self {
        Error::Send(err)
    }
}

impl From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error::Generic(err.to_string())
    }
}

impl From<block_modes::BlockModeError> for Error {
    fn from(err: block_modes::BlockModeError) -> Self {
        Error::Generic(err.to_string())
    }
}

impl From<bitcoin::secp256k1::Error> for Error {
    fn from(err: bitcoin::secp256k1::Error) -> Self {
        Error::Secp256k1(err)
    }
}

impl From<bitcoin::util::key::Error> for Error {
    fn from(err: bitcoin::util::key::Error) -> Self {
        Error::Generic(err.to_string())
    }
}

impl From<bitcoin::hashes::hex::Error> for Error {
    fn from(err: bitcoin::hashes::hex::Error) -> Self {
        Error::Generic(err.to_string())
    }
}

impl From<serde_cbor::error::Error> for Error {
    fn from(err: serde_cbor::error::Error) -> Self {
        Error::Generic(err.to_string())
    }
}

impl From<block_modes::InvalidKeyIvLength> for Error {
    fn from(err: block_modes::InvalidKeyIvLength) -> Self {
        Error::Generic(err.to_string())
    }
}

impl From<PoisonError<RwLockReadGuard<'_, StoreMeta>>> for Error {
    fn from(err: PoisonError<RwLockReadGuard<'_, StoreMeta>>) -> Self {
        Error::Generic(err.to_string())
    }
}

impl From<PoisonError<RwLockWriteGuard<'_, StoreMeta>>> for Error {
    fn from(err: PoisonError<RwLockWriteGuard<'_, StoreMeta>>) -> Self {
        Error::Generic(err.to_string())
    }
}

impl From<aead::Error> for Error {
    fn from(err: aead::Error) -> Self {
        Error::Generic(err.to_string())
    }
}

impl From<ureq::Error> for Error {
    fn from(err: ureq::Error) -> Self {
        Error::Generic(err.to_string())
    }
}
