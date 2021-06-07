use std::convert::TryInto;

mod address;
mod blockhash;
mod blockheader;
mod outpoint;
mod script;
mod transaction;
mod txid;

pub use address::*;
use bitcoin::hashes::hex::ToHex;
use bitcoin::util::bip32::DerivationPath;
pub use blockhash::*;
pub use blockheader::*;
pub use outpoint::*;
pub use script::*;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
pub use transaction::*;
pub use txid::*;

pub type Utxos = Vec<(BEOutPoint, UTXOInfo)>;

#[derive(Debug)]
pub struct UTXOInfo {
    pub asset: String,
    pub value: u64,
    pub script: BEScript,
    pub height: Option<u32>,
    pub path: DerivationPath,
}

impl UTXOInfo {
    pub fn new_bitcoin(
        value: u64,
        script: BEScript,
        height: Option<u32>,
        path: DerivationPath,
    ) -> Self {
        UTXOInfo {
            asset: "btc".to_string(),
            value,
            script,
            height,
            path,
        }
    }

    pub fn new_elements(
        asset: elements::issuance::AssetId,
        value: u64,
        script: BEScript,
        height: Option<u32>,
        path: DerivationPath,
    ) -> Self {
        UTXOInfo {
            asset: asset.to_hex(),
            value,
            script,
            height,
            path,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Unblinded {
    pub asset: elements::issuance::AssetId,
    pub abf: [u8; 32],
    pub vbf: [u8; 32],
    pub value: u64,
}

impl Unblinded {
    pub fn asset(&self) -> elements::issuance::AssetId {
        self.asset.clone()
    }

    pub fn confidential(&self) -> bool {
        self.abf != [0u8; 32] || self.vbf != [0u8; 32]
    }
}

impl Debug for Unblinded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.asset.to_hex(), self.value)
    }
}

#[derive(Default)]
pub struct ScriptBatch {
    pub cached: bool,
    pub value: Vec<(BEScript, DerivationPath)>,
}
