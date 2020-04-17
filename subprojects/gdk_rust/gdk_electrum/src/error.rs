use serde::ser::Serialize;
use std::convert::From;
use std::fmt::Display;

#[derive(Debug)]
pub enum Error {
    Generic(String),
    UnknownCall,
    InvalidMnemonic,
    InsufficientFunds,
    InvalidAddress,
    InvalidAmount,
    DB(sled::Error),
    AddrParse(String),
    Bitcoin(bitcoin::util::Error),
    BitcoinHashes(bitcoin::hashes::error::Error),
    BitcoinBIP32Error(bitcoin::util::bip32::Error),
    BitcoinConsensus(bitcoin::consensus::encode::Error),
    JSON(serde_json::error::Error),
    StdIOError(std::io::Error),
    Hex(hex::FromHexError),
    ClientError(electrum_client::types::Error),
    SliceConversionError(std::array::TryFromSliceError),
    ElementsEncode(elements::encode::Error),
    Common(gdk_common::error::Error),
    Send(std::sync::mpsc::SendError<()>),
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            Error::Generic(ref strerr) => write!(f, "{}", strerr),
            Error::AddrParse(ref addr) => write!(f, "could not parse SocketAddr `{}`", addr),
            Error::InvalidMnemonic => write!(f, "invalid mnemonic"),
            Error::InsufficientFunds => write!(f, "insufficient funds"),
            Error::InvalidAddress => write!(f, "invalid address"),
            Error::InvalidAmount => write!(f, "invalid amount"),
            Error::UnknownCall => write!(f, "unknown call"),
            Error::DB(ref dberr) => write!(f, "bitcoin: {}", dberr),
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

impl std::convert::From<bitcoin::util::bip32::Error> for Error {
    fn from(err: bitcoin::util::bip32::Error) -> Self {
        Error::BitcoinBIP32Error(err)
    }
}

impl std::convert::From<String> for Error {
    fn from(err: String) -> Self {
        Error::Generic(err)
    }
}

impl std::convert::From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::StdIOError(err)
    }
}

impl std::convert::From<sled::Error> for Error {
    fn from(err: sled::Error) -> Self {
        Error::DB(err)
    }
}

impl std::convert::From<bitcoin::consensus::encode::Error> for Error {
    fn from(err: bitcoin::consensus::encode::Error) -> Self {
        Error::BitcoinConsensus(err)
    }
}

impl std::convert::From<hex::FromHexError> for Error {
    fn from(err: hex::FromHexError) -> Self {
        Error::Hex(err)
    }
}

impl std::convert::From<electrum_client::types::Error> for Error {
    fn from(err: electrum_client::types::Error) -> Self {
        Error::ClientError(err)
    }
}

impl std::convert::From<bitcoin::hashes::error::Error> for Error {
    fn from(err: bitcoin::hashes::error::Error) -> Self {
        Error::BitcoinHashes(err)
    }
}
impl std::convert::From<elements::encode::Error> for Error {
    fn from(err: elements::encode::Error) -> Self {
        Error::ElementsEncode(err)
    }
}

impl std::convert::From<gdk_common::error::Error> for Error {
    fn from(err: gdk_common::error::Error) -> Self {
        Error::Common(err)
    }
}

impl std::convert::From<std::sync::mpsc::SendError<()>> for Error {
    fn from(err: std::sync::mpsc::SendError<()>) -> Self {
        Error::Send(err)
    }
}

impl std::convert::From<std::string::FromUtf8Error> for Error {
    fn from(err: std::string::FromUtf8Error) -> Self {
        Error::Generic(err.to_string())
    }
}
