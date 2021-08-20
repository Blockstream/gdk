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
    pub confidential: bool,
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
            confidential: false,
        }
    }

    pub fn new_elements(
        asset: elements::issuance::AssetId,
        value: u64,
        script: BEScript,
        height: Option<u32>,
        path: DerivationPath,
        confidential: bool,
    ) -> Self {
        UTXOInfo {
            asset: asset.to_hex(),
            value,
            script,
            height,
            path,
            confidential,
        }
    }

    pub fn asset_id(&self) -> Option<elements::issuance::AssetId> {
        if self.asset == "btc" {
            None
        } else {
            Some(self.asset.parse().expect("Invalid asset"))
        }
    }
}

#[derive(Default)]
pub struct ScriptBatch {
    pub cached: bool,
    pub value: Vec<(BEScript, DerivationPath)>,
}
