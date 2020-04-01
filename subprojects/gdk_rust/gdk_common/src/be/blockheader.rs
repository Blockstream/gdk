use crate::NetworkId;

#[derive(Debug, Clone)]
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
}
