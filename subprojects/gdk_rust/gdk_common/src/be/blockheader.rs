use crate::NetworkId;
use bitcoin::{BitcoinHash, BlockHash};
use serde::{Deserialize, Serialize};

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BEBlockHeader {
    Bitcoin(bitcoin::BlockHeader),
    Elements(elements::BlockHeader),
}

impl BEBlockHeader {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Bitcoin(header) => bitcoin::consensus::encode::serialize(header),
            Self::Elements(header) => elements::encode::serialize(header),
        }
    }

    pub fn deserialize(bytes: &[u8], id: NetworkId) -> Result<Self, crate::error::Error> {
        Ok(match id {
            NetworkId::Bitcoin(_) => Self::Bitcoin(bitcoin::consensus::encode::deserialize(bytes)?),
            NetworkId::Elements(_) => Self::Elements(elements::encode::deserialize(bytes)?),
        })
    }

    pub fn time(&self) -> u32 {
        match self {
            Self::Bitcoin(header) => header.time,
            Self::Elements(header) => header.time,
        }
    }

    pub fn bitcoin_hash(&self) -> BlockHash {
        match self {
            Self::Bitcoin(header) => header.bitcoin_hash(),
            Self::Elements(header) => header.bitcoin_hash(),
        }
    }
}
