use crate::NetworkId;
use bitcoin::Txid;

#[derive(Debug, PartialEq, Eq, Hash)]
pub enum BEOutPoint {
    Bitcoin(bitcoin::OutPoint),
    Elements(elements::OutPoint),
}

impl BEOutPoint {
    pub fn new_bitcoin(txid: Txid, vout: u32) -> Self {
        BEOutPoint::Bitcoin(bitcoin::OutPoint {
            txid,
            vout,
        })
    }

    pub fn new_elements(txid: Txid, vout: u32) -> Self {
        BEOutPoint::Elements(elements::OutPoint {
            txid,
            vout,
        })
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Bitcoin(outpoint) => bitcoin::consensus::encode::serialize(outpoint),
            Self::Elements(outpoint) => elements::encode::serialize(outpoint),
        }
    }

    pub fn deserialize(bytes: &[u8], id: NetworkId) -> Result<Self, crate::error::Error> {
        Ok(match id {
            NetworkId::Bitcoin(_) => Self::Bitcoin(bitcoin::consensus::encode::deserialize(bytes)?),
            NetworkId::Elements(_) => Self::Elements(elements::encode::deserialize(bytes)?),
        })
    }

    pub fn txid(&self) -> bitcoin::Txid {
        match self {
            Self::Bitcoin(outpoint) => outpoint.txid,
            Self::Elements(outpoint) => outpoint.txid,
        }
    }

    pub fn vout(&self) -> u32 {
        match self {
            Self::Bitcoin(outpoint) => outpoint.vout,
            Self::Elements(outpoint) => outpoint.vout,
        }
    }
}
