use elements::hex::ToHex;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::Error;
use crate::NetworkId;

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize, PartialOrd, Ord)]
pub enum BETxid {
    Bitcoin(bitcoin::Txid),
    Elements(elements::Txid),
}

impl BETxid {
    pub fn to_hex(&self) -> String {
        match self {
            Self::Bitcoin(txid) => txid.to_hex(),
            Self::Elements(txid) => txid.to_hex(),
        }
    }
    pub fn from_hex(s: &str, network: NetworkId) -> Result<Self, Error> {
        Ok(match network {
            NetworkId::Bitcoin(_) => bitcoin::Txid::from_str(s)?.into(),
            NetworkId::Elements(_) => elements::Txid::from_str(s)?.into(),
        })
    }

    pub fn ref_bitcoin(&self) -> Option<&bitcoin::Txid> {
        match self {
            Self::Bitcoin(txid) => Some(txid),
            Self::Elements(_) => None,
        }
    }
    pub fn ref_elements(&self) -> Option<&elements::Txid> {
        match self {
            Self::Bitcoin(_) => None,
            Self::Elements(txid) => Some(txid),
        }
    }
}

pub trait BETxidConvert {
    fn into_bitcoin(self) -> bitcoin::Txid;
    fn into_elements(self) -> elements::Txid;
    fn into_be(self) -> BETxid;
    fn into_net(self, network: NetworkId) -> BETxid
    where
        Self: Sized,
    {
        match network {
            NetworkId::Bitcoin(_) => self.into_bitcoin().into(),
            NetworkId::Elements(_) => self.into_elements().into(),
        }
    }
}

impl BETxidConvert for BETxid {
    fn into_bitcoin(self) -> bitcoin::Txid {
        match self {
            Self::Bitcoin(txid) => txid,
            Self::Elements(txid) => txid.into_bitcoin(),
        }
    }
    fn into_elements(self) -> elements::Txid {
        match self {
            Self::Bitcoin(txid) => txid.into_elements(),
            Self::Elements(txid) => txid,
        }
    }
    fn into_be(self) -> Self {
        self
    }
}

impl BETxidConvert for bitcoin::Txid {
    fn into_bitcoin(self) -> bitcoin::Txid {
        self
    }
    fn into_elements(self) -> elements::Txid {
        elements::Txid::from_raw_hash(*self.as_raw_hash())
    }
    fn into_be(self) -> BETxid {
        self.into()
    }
}

impl BETxidConvert for elements::Txid {
    fn into_bitcoin(self) -> bitcoin::Txid {
        bitcoin::Txid::from_raw_hash(*self.as_raw_hash())
    }
    fn into_elements(self) -> elements::Txid {
        self
    }
    fn into_be(self) -> BETxid {
        self.into()
    }
}

impl BETxidConvert for &elements::Txid {
    fn into_bitcoin(self) -> bitcoin::Txid {
        self.clone().into_bitcoin()
    }
    fn into_elements(self) -> elements::Txid {
        self.clone().into_elements()
    }
    fn into_be(self) -> BETxid {
        self.clone().into()
    }
}

impl BETxidConvert for &bitcoin::Txid {
    fn into_bitcoin(self) -> bitcoin::Txid {
        self.clone().into_bitcoin()
    }
    fn into_elements(self) -> elements::Txid {
        self.clone().into_elements()
    }
    fn into_be(self) -> BETxid {
        self.clone().into()
    }
}

impl BETxidConvert for &BETxid {
    fn into_bitcoin(self) -> bitcoin::Txid {
        self.clone().into_bitcoin()
    }
    fn into_elements(self) -> elements::Txid {
        self.clone().into_elements()
    }
    fn into_be(self) -> BETxid {
        self.clone()
    }
}

impl fmt::Display for BETxid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bitcoin(txid) => write!(f, "{}", txid),
            Self::Elements(txid) => write!(f, "{}", txid),
        }
    }
}

impl From<bitcoin::Txid> for BETxid {
    fn from(txid: bitcoin::Txid) -> BETxid {
        BETxid::Bitcoin(txid)
    }
}

impl From<elements::Txid> for BETxid {
    fn from(txid: elements::Txid) -> BETxid {
        BETxid::Elements(txid)
    }
}
