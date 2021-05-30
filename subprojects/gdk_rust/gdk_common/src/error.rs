use std::string::ToString;

#[derive(Debug)]
pub enum Error {
    Generic(String),
    InvalidAddress,
    InputValidationFailed,
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

macro_rules! impl_error {
    ( $from:ty ) => {
        impl std::convert::From<$from> for Error {
            fn from(err: $from) -> Self {
                Error::Generic(err.to_string())
            }
        }
    };
}

impl_error!(&str);
impl_error!(bitcoin::util::base58::Error);
//impl_error!(sled::Error);
impl_error!(bitcoin::hashes::error::Error);
impl_error!(bitcoin::hashes::hex::Error);
impl_error!(bitcoin::consensus::encode::Error);
impl_error!(bitcoin::util::bip32::Error);
impl_error!(std::array::TryFromSliceError);
impl_error!(elements::encode::Error);
impl_error!(elements::address::AddressError);
impl_error!(hex::FromHexError);
impl_error!(bitcoin::util::address::Error);
impl_error!(bitcoin::secp256k1::Error);

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
