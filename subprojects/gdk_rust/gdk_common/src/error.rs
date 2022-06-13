use std::string::ToString;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    BtcAddressError(#[from] bitcoin::util::address::Error),

    #[error(transparent)]
    BtcBase58DecodingError(#[from] bitcoin::util::base58::Error),

    #[error(transparent)]
    BtcBip32Error(#[from] bitcoin::util::bip32::Error),

    #[error(transparent)]
    BtcEncodingError(#[from] bitcoin::consensus::encode::Error),

    #[error(transparent)]
    BtcHashesError(#[from] bitcoin::hashes::error::Error),

    #[error(transparent)]
    BtcHexDecodingError(#[from] bitcoin::hashes::hex::Error),

    #[error(transparent)]
    BtcKeyError(#[from] bitcoin::util::key::Error),

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

    #[error("Generic({0})")]
    Generic(String),
}

pub fn err<R>(str: &str) -> Result<R, Error> {
    Err(Error::Generic(str.into()))
}

pub fn fn_err(str: &str) -> impl Fn() -> Error + '_ {
    move || Error::Generic(str.into())
}

pub fn _io_err(str: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidInput, str.to_string())
}

impl From<String> for Error {
    fn from(e: String) -> Error {
        Error::Generic(e)
    }
}

impl From<&str> for Error {
    fn from(e: &str) -> Error {
        Error::Generic(e.to_owned())
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
