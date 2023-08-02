use crate::NetworkId;
use serde::{Deserialize, Serialize};

use super::BEBlockHash;

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub enum BEBlockHeader {
    Bitcoin(bitcoin::block::Header),
    Elements(elements::BlockHeader),
}

impl BEBlockHeader {
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

    pub fn block_hash(&self) -> BEBlockHash {
        match self {
            Self::Bitcoin(header) => BEBlockHash::Bitcoin(header.block_hash()),
            Self::Elements(header) => BEBlockHash::Elements(header.block_hash()),
        }
    }

    pub fn prev_block_hash(&self) -> BEBlockHash {
        match self {
            Self::Bitcoin(header) => BEBlockHash::Bitcoin(header.prev_blockhash),
            Self::Elements(header) => BEBlockHash::Elements(header.prev_blockhash),
        }
    }
}

#[cfg(test)]
mod test {
    use bitcoin::hashes::hex::FromHex;
    use elements::encode::deserialize;
    use elements::BlockHeader;

    #[test]
    fn test_json_header() {
        let header = block_header_dynafed();
        let json = serde_json::to_value(&header).unwrap();
        let back: BlockHeader = serde_json::from_value(json).unwrap();
        assert_eq!(header, back);
    }

    #[test]
    fn test_cbor_header() {
        let header = block_header_dynafed();
        let vec = crate::util::ciborium_to_vec(&header).unwrap();
        let back: BlockHeader = ciborium::from_reader(&vec[..]).unwrap();
        assert_eq!(header, back);
    }

    fn block_header_dynafed() -> BlockHeader {
        deserialize( &Vec::<u8>::from_hex("000000a013d3fd2bf9e58616f0a283ea6f8d4674bf071f01eb7c1b5916c6168cf048dc1a5123137f8e22e2ef372734506a22adc8769e2dee5da60f5cd0b69e074c0f6dff1c7b855f67000000012200204ae81572f06e1b88fd5ced7a1a000945432e83e1551e6f721ee9c00b8cc332604a000000fbee9cea00d8efdc49cfbec328537e0d7032194de6ebf3cf42e5c05bb89a08b100010151").unwrap()).unwrap()
    }
}
