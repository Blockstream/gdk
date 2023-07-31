use bitcoin::{hashes::Hash, BlockHash};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub enum BEBlockHash {
    Bitcoin(bitcoin::BlockHash),
    Elements(elements::BlockHash),
}

impl BEBlockHash {
    pub fn into_bitcoin(&self) -> bitcoin::BlockHash {
        match self {
            Self::Bitcoin(h) => *h,
            Self::Elements(h) => bitcoin::BlockHash::from_raw_hash(h.to_raw_hash()),
        }
    }
}

impl ToString for BEBlockHash {
    fn to_string(&self) -> String {
        match self {
            Self::Bitcoin(blockhash) => blockhash.to_string(),
            Self::Elements(blockhash) => blockhash.to_string(),
        }
    }
}

// We must have a default for Store, so we use bitcoin::BlockHash which
// will be replaced with the proper type after the first sync.
impl Default for BEBlockHash {
    fn default() -> Self {
        Self::Bitcoin(BlockHash::all_zeros())
    }
}
