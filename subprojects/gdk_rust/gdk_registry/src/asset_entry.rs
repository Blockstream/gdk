use gdk_common::bitcoin::hashes::Hash;
use gdk_common::elements::{AssetId, ContractHash, OutPoint, Txid};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Result;

/// Contains informations about an asset, including its asset id, the contract
/// defining its property, and the transaction that issued the asset.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssetEntry {
    /// The identifier of the asset. It's a midstate of a `sha256`, thus it's
    /// 32 supposedly random bytes.
    pub asset_id: AssetId,

    /// Contains assets metadata provided by the issuer. This information is
    /// commited in the `asset_id` so it's verifiable by third parties. Some
    /// fields in the contract are repeated at this level such as `version`,
    /// `issuer_pubkey`, `name`, `ticker`, `precision` and `entity`. Other
    /// fields could be custom values created by the issuer.
    #[serde(default)]
    pub contract: serde_json::Value,

    /// Contains information regarding the internet domain of the asset issuer.
    #[serde(default)]
    pub entity: serde_json::Value,

    /// The previous output that is spent to create this issuance.
    #[serde(default)]
    pub issuance_prevout: Prevout,

    /// The transaction input containing this issuance.
    #[serde(default)]
    pub issuance_txin: Txin,

    /// A public key owned by the issuer used for authentication.
    #[serde(default)]
    pub issuer_pubkey: String,

    /// Name of the asset.
    #[serde(default)]
    pub name: String,

    /// Precision of the asset as the number of digits after the decimal
    /// separator. Eg. bitcoin use 8 as precision.
    #[serde(default)]
    pub precision: u8,

    /// Ticker of the asset.
    pub ticker: Option<String>,

    /// The version of the registry protocol.
    #[serde(default)]
    pub version: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prevout {
    txid: Txid,
    vout: u32,
}

impl Default for Prevout {
    fn default() -> Self {
        Self {
            txid: Txid::all_zeros(),
            vout: Default::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Txin {
    txid: Txid,
    vin: u32,
}

impl Default for Txin {
    fn default() -> Self {
        Self {
            txid: Txid::all_zeros(),
            vin: Default::default(),
        }
    }
}

impl AssetEntry {
    pub(crate) fn contract_string(&self) -> Result<String> {
        serde_json::to_string(&self.contract).map_err(Into::into)
    }

    pub(crate) fn issuance_prevout(&self) -> OutPoint {
        OutPoint::new(self.issuance_prevout.txid, self.issuance_prevout.vout)
    }

    /// Verify information in `self.contract` commits in `self.asset_id`
    /// ensuring the validity of the Contract data. Moreover information in the
    /// first level like `self.name` is verified to be the same of the one in
    /// the contract `self.contract.name`
    pub fn verifies(&self) -> Result<bool> {
        let contract_hash = ContractHash::from_json_contract(&self.contract_string()?)?;

        let entropy = AssetId::generate_asset_entropy(self.issuance_prevout(), contract_hash);

        let asset_id = AssetId::from_entropy(entropy);

        let ticker = match self.ticker.clone() {
            Some(val) => Value::String(val),
            None => Value::Null,
        };

        Ok(asset_id == self.asset_id
            && Some(self.version as u64) == self.contract["version"].as_u64()
            && Some(self.issuer_pubkey.as_str()) == self.contract["issuer_pubkey"].as_str()
            && Some(self.name.as_str()) == self.contract["name"].as_str()
            && ticker == self.contract["ticker"]
            && Some(self.precision as u64) == self.contract["precision"].as_u64()
            && self.entity == self.contract["entity"])
    }
}
