use core::fmt;
use std::io;

use backtrace::Backtrace;
use bitcoin::consensus::encode;
use bitcoin::secp256k1;
use bitcoin::util::bip32;
use bitcoincore_rpc;
#[cfg(feature = "liquid")]
use elements;
use failure;
use hex;
use serde_json;
use url;

pub const GDK_ERROR_ID_UNKNOWN: &str = "id_unknown";

const CORE_INSUFFICIENT_FUNDS: i32 = -1;
const CORE_WALLET_GENERIC: i32 = -4;

#[derive(Debug)]
pub enum Error {
    // First we specify exact errors that map GDK errors.
    /// There were insufficient funds.
    InsufficientFunds,
    /// User is already logged in.
    AlreadyLoggedIn,
    /// User tried logging into a wallet that was not registered yet.
    WalletNotRegistered,
    /// User tried to register a wallet that was already registered.
    WalletAlreadyRegistered,
    /// Mnemonics should be phrases of 24 words.
    InvalidMnemonic,
    /// A user requested creation of a transaction with no recipients.
    NoRecipients,
    /// The wallet does not have any available UTXOs to fund a transaction.
    NoUtxosFound,
    /// Some of the data stored in the node is corrupt. The wallet will
    /// probably have to be reset.
    CorruptNodeData,

    // And then all other errors that we can't convert to GDK codes.
    Bip32(bip32::Error),
    Bip39(failure::Error),
    BitcoinEncode(encode::Error),
    BitcoinRpc(bitcoincore_rpc::Error),
    #[cfg(feature = "liquid")]
    ElementsAddress(elements::AddressError),
    Hashes(bitcoin_hashes::Error),
    Hex(hex::FromHexError),
    Io(io::Error),
    Json(serde_json::Error),
    Secp256k1(secp256k1::Error),
    Url(url::ParseError),

    /// Custom error with message.
    Other(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Into<String> for Error {
    fn into(self) -> String {
        format!("{:?}", self)
    }
}

impl From<bitcoincore_rpc::Error> for Error {
    fn from(e: bitcoincore_rpc::Error) -> Error {
        debug!("backtrace bitcoincore_rpc::Error: {} {:?}", e, Backtrace::new());
        if let bitcoincore_rpc::Error::JsonRpc(jsonrpc::Error::Rpc(ref e)) = e {
            match e.code {
                CORE_INSUFFICIENT_FUNDS => return Error::InsufficientFunds,
                CORE_WALLET_GENERIC => {
                    if e.message.contains("Duplicate -wallet filename specified.") {
                        return Error::AlreadyLoggedIn;
                    }
                }
                _ => {}
            }
        }

        Error::BitcoinRpc(e)
    }
}

macro_rules! from_error {
    ($variant:ident, $err:ty) => {
        impl From<$err> for Error {
            fn from(e: $err) -> Error {
                debug!("backtrace {}: {} {:?}", stringify!($err), e, Backtrace::new());
                Error::$variant(e)
            }
        }
    };
}

from_error!(Bip32, bip32::Error);
from_error!(BitcoinEncode, encode::Error);
#[cfg(feature = "liquid")]
from_error!(ElementsAddress, elements::AddressError);
from_error!(Hashes, bitcoin_hashes::Error);
from_error!(Hex, hex::FromHexError);
from_error!(Io, io::Error);
from_error!(Json, serde_json::Error);
from_error!(Secp256k1, secp256k1::Error);
from_error!(Url, url::ParseError);
from_error!(Other, String);

#[macro_export]
macro_rules! throw {
    ($e:expr) => {
        return Err(Error::Other($e.into()));
    };
    ($fmt:expr, $($arg:tt)*) => {
        return Err(Error::Other(format!($fmt, $($arg)*).into()));
    };
}

// nuclear option, if we need to convert an error without From or Display
pub fn into_err<E>(err: E) -> Error
where
    E: std::fmt::Debug,
{
    Error::Other(From::from(format!("{:?}", err)))
}
