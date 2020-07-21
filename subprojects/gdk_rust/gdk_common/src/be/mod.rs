use std::convert::{TryInto, TryFrom};

mod address;
mod blockheader;
mod outpoint;
mod transaction;

pub use address::*;
use bitcoin::Script;
pub use blockheader::*;
pub use outpoint::*;
use std::collections::{HashSet};
pub use transaction::*;
use serde::{Serialize, Deserialize};
use bitcoin::util::bip32::{DerivationPath, ChildNumber};
use std::str::FromStr;

pub type AssetId = [u8; 32];  // TODO use elements::issuance::AssetId

pub struct WalletData {
    pub utxos: Vec<(BEOutPoint, UTXOInfo)>,
    pub spent: HashSet<BEOutPoint>,
}

#[derive(Debug)]
pub struct UTXOInfo {
    pub asset: String,
    pub value: u64,
    pub script: Script,
}

impl UTXOInfo {
    pub fn new(asset: String, value: u64, script: Script) -> Self {
        UTXOInfo {
            asset,
            value,
            script,
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
    pub fn serialize(&self) -> Vec<u8> {
        let mut vec = vec![];
        vec.extend(&self.asset[..]);
        vec.extend(&self.abf[..]);
        vec.extend(&self.vbf[..]);
        vec.extend(elements::encode::serialize(&self.value));
        vec
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Self, crate::error::Error> {
        let asset: AssetId = bytes[..32].as_ref().try_into()?;
        let abf: [u8; 32] = bytes[32..64].as_ref().try_into()?;
        let vbf: [u8; 32] = bytes[64..96].as_ref().try_into()?;
        let value: u64 = elements::encode::deserialize(&bytes[96..])?;
        Ok(Unblinded {
            asset,
            value,
            abf,
            vbf,
        })
    }

    pub fn asset_hex(&self) -> String {
        asset_to_hex(&self.asset)
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


/// Other than limiting derivation to two levels, this is required because DerivationPath dosn't
/// derive Hash, so it cannot be used as HashMap key
#[derive(Debug, Hash, Serialize, Deserialize, PartialEq, Eq, Clone)]
pub struct TwoLayerPath {
    i: u32,
    j: u32,
}

impl TwoLayerPath {
    pub fn new(i:u32, j:u32) -> Self {
        TwoLayerPath{i,j}
    }
}

impl TryFrom<DerivationPath> for TwoLayerPath {
    type Error = crate::error::Error;

    fn try_from(value: DerivationPath) -> Result<Self, Self::Error> {
        let vec: Vec<ChildNumber> = value.into();
        if vec.len() != 2 {
            return Err(crate::error::Error::Generic("azz".into()));
        }
        Ok(TwoLayerPath {
            i: vec[0].into(),
            j: vec[0].into(),
        })
    }
}

impl TryInto<DerivationPath> for TwoLayerPath {
    type Error = crate::error::Error;

    fn try_into(self) -> Result<DerivationPath, Self::Error> {
        Ok(DerivationPath::from_str(&format!("m/{}/{}", self.i, self.j))?)
    }
}

#[derive(Default)]
pub struct ScriptBatch {
    pub cached: bool,
    pub value: Vec<(TwoLayerPath, Script)>,
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
