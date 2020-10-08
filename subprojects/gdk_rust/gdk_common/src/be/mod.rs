use std::convert::TryInto;

mod address;
mod blockheader;
mod outpoint;
mod transaction;

pub use address::*;
use bitcoin::hashes::core::fmt::Formatter;
use bitcoin::util::bip32::DerivationPath;
use bitcoin::Script;
pub use blockheader::*;
pub use outpoint::*;
use serde::{Deserialize, Serialize};
use std::fmt::Debug;
pub use transaction::*;

pub type AssetId = [u8; 32]; // TODO use elements::issuance::AssetId
pub type Utxos = Vec<(BEOutPoint, UTXOInfo)>;

#[derive(Debug)]
pub struct UTXOInfo {
    pub asset: String,
    pub value: u64,
    pub script: Script,
    pub height: Option<u32>,
    pub path: DerivationPath,
}

impl UTXOInfo {
    pub fn new(
        asset: String,
        value: u64,
        script: Script,
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
    pub fn asset_hex(&self) -> String {
        asset_to_hex(&self.asset)
    }
}

impl Debug for Unblinded {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {}", self.asset_hex(), self.value)
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
    pub value: Vec<(Script, DerivationPath)>,
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
