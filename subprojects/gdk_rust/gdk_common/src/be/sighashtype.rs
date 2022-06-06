use bitcoin::blockdata::transaction::SigHashType as BitcoinSigHashType;
use elements::SigHashType as ElementsSigHashType;

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
                Ok(BESigHashType::Elements(sighash))
            } else {
                Err(Error::InvalidSigHash)
            }
        } else {
            let sighash =
                BitcoinSigHashType::from_u32_standard(n).map_err(|_| Error::InvalidSigHash)?;
            Ok(BESigHashType::Bitcoin(sighash))
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
}
