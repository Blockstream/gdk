use std::string::ToString;

use bitcoin::sighash::NonStandardSighashTypeError;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    BtcAddressError(#[from] bitcoin::address::Error),

    #[error(transparent)]
    BtcBase58DecodingError(#[from] bitcoin::base58::Error),

    #[error(transparent)]
    BtcBip32Error(#[from] bitcoin::bip32::Error),

    #[error(transparent)]
    BtcEncodingError(#[from] bitcoin::consensus::encode::Error),

    #[error(transparent)]
    BtcHashesError(#[from] bitcoin::hashes::FromSliceError),

    #[error(transparent)]
    BtcHexToArrayError(#[from] bitcoin::hashes::hex::HexToArrayError),

    #[error(transparent)]
    BtcHexToBytesError(#[from] bitcoin::hashes::hex::HexToBytesError),

    #[error(transparent)]
    BtcKeyError(#[from] bitcoin::key::Error),

    #[error(transparent)]
    BtcNonStandardSigHashType(#[from] NonStandardSighashTypeError),

    #[error(transparent)]
    BtcSecp256k1Error(#[from] bitcoin::secp256k1::Error),

    #[error(transparent)]
    ElementsAddressError(#[from] elements::address::AddressError),

    #[error(transparent)]
    ElementsEncodingError(#[from] elements::encode::Error),

    #[error(transparent)]
    FromSliceError(#[from] std::array::TryFromSliceError),

    #[error("Invalid input")]
    InputValidationFailed,

    #[error("Invalid address")]
    InvalidAddress,

    #[error("Invalid address type")]
    InvalidAddressType,

    #[error("Invalid sighash")]
    InvalidSigHash,

    #[error("Invalid SLIP132 version")]
    InvalidSlip132Version,

    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error("Mismatching descriptor")]
    MismatchingDescriptor,

    #[error("Mismatching network")]
    MismatchingNetwork,

    #[error("Mismatching xpub")]
    MismatchingXpub,

    #[error("Unexpected child number")]
    UnexpectedChildNumber,

    #[error("Unsupported sighash")]
    UnsupportedSigHash,

    #[error("Unsupported descriptor")]
    UnsupportedDescriptor,

    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),

    #[error(transparent)]
    Sighash(#[from] bitcoin::sighash::Error),

    #[error("Generic({0})")]
    Generic(String),
}

impl From<aes_gcm_siv::aead::Error> for Error {
    fn from(err: aes_gcm_siv::aead::Error) -> Self {
        Self::Generic(err.to_string())
    }
}

pub fn fn_err(str: &str) -> impl Fn() -> Error + '_ {
    move || Error::Generic(str.into())
}

impl From<String> for Error {
    fn from(e: String) -> Error {
        Error::Generic(e)
    }
}

#[macro_export]
macro_rules! bail {
    ($err:expr $(,)?) => {
        return Err($err.into());
    };
}

#[macro_export]
macro_rules! ensure {
    ($cond:expr, $err:expr $(,)?) => {
        if !$cond {
            bail!($err);
        }
    };
}

#[macro_export]
macro_rules! impl_error_variant {
    ($name:ident, $enum:ident) => {
        impl_from_variant!($name, $enum, $name);
    };
    ($struct:path, $enum:ident, $variant:ident) => {
        impl From<$struct> for $enum {
            fn from(v: $struct) -> Self {
                $enum::$variant(v)
            }
        }
    };
}
