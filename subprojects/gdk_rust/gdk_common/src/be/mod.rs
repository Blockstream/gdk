use std::convert::TryInto;

mod address;
mod blockheader;
mod outpoint;
mod transaction;

pub use address::*;
pub use blockheader::*;
pub use outpoint::*;
pub use transaction::*;

pub type AssetId = [u8; 32];

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

    pub fn asset_hex(&self, policy_asset: Option<&String>) -> String {
        let mut asset = self.asset.to_vec();
        asset.reverse();
        let hex = hex::encode(asset);
        if Some(&hex) == policy_asset {
            "btc".to_string()
        } else {
            hex
        }
    }
}
