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

pub type AssetId = [u8; 32]; // TODO use elements::issuance::AssetId
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
    pub fn new(
        asset: String,
        value: u64,
        script: BEScript,
        height: Option<u32>,
        path: DerivationPath,
    ) -> Self {
        UTXOInfo {
            asset,
            value,
            script,
            height,
            path,
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct Unblinded {
    pub asset: AssetId,
    pub abf: [u8; 32],
    pub vbf: [u8; 32],
    pub value: u64,
}

impl Unblinded {
    pub fn asset(&self) -> elements::issuance::AssetId {
        elements::issuance::AssetId::from_slice(&self.asset).unwrap()
    }

    pub fn confidential(&self) -> bool {
        self.abf != [0u8; 32] || self.vbf != [0u8; 32]
    }
}

impl Debug for Unblinded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.asset().to_hex(), self.value)
    }
}

pub fn asset_to_bin(asset: &str) -> Result<AssetId, crate::error::Error> {
    let mut bytes = hex::decode(asset)?;
    bytes.reverse();
    let asset: AssetId = (&bytes[..]).try_into()?;
    Ok(asset)
}

pub fn asset_to_hex(asset: &[u8]) -> String {
    let mut asset = asset.to_vec();
    asset.reverse();
    hex::encode(asset)
}

#[derive(Default)]
pub struct ScriptBatch {
    pub cached: bool,
    pub value: Vec<(BEScript, DerivationPath)>,
}

#[cfg(test)]
mod tests {
    use crate::be::{asset_to_bin, asset_to_hex};

    #[test]
    fn test_asset_roundtrip() {
        let expected = "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225";
        let result = asset_to_hex(&asset_to_bin(expected).unwrap());
        assert_eq!(expected, &result);
    }
}
