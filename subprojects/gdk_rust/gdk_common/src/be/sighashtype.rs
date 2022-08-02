use bitcoin::blockdata::transaction::EcdsaSighashType as BitcoinSigHashType;
use elements::EcdsaSigHashType as ElementsSigHashType;

use crate::error::Error;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BESigHashType {
    Bitcoin(BitcoinSigHashType),
    Elements(ElementsSigHashType),
}

impl BESigHashType {
    pub fn from_u32(n: u32, is_elements: bool) -> Result<Self, Error> {
        if is_elements {
            let sighash = ElementsSigHashType::from_u32(n);
            if sighash.as_u32() == n {
                let sighash = BESigHashType::Elements(sighash);
                sighash.is_allowed()?;
                Ok(sighash)
            } else {
                Err(Error::InvalidSigHash)
            }
        } else {
            let sighash =
                BitcoinSigHashType::from_standard(n).map_err(|_| Error::InvalidSigHash)?;
            let sighash = BESigHashType::Bitcoin(sighash);
            sighash.is_allowed()?;
            Ok(sighash)
        }
    }

    pub fn into_bitcoin(&self) -> Result<BitcoinSigHashType, Error> {
        match self {
            BESigHashType::Bitcoin(sighash) => Ok(sighash.clone()),
            BESigHashType::Elements(_) => Err(Error::InvalidSigHash),
        }
    }

    pub fn into_elements(&self) -> Result<ElementsSigHashType, Error> {
        match self {
            BESigHashType::Bitcoin(_) => Err(Error::InvalidSigHash),
            BESigHashType::Elements(sighash) => Ok(sighash.clone()),
        }
    }

    fn is_allowed(&self) -> Result<(), Error> {
        match self {
            BESigHashType::Bitcoin(BitcoinSigHashType::All)
            | BESigHashType::Elements(ElementsSigHashType::All)
            | BESigHashType::Elements(ElementsSigHashType::SinglePlusAnyoneCanPay) => Ok(()),
            _ => Err(Error::UnsupportedSigHash),
        }
    }
}
