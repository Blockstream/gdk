use elements::{AssetId, Txid};
use serde::{Deserialize, Serialize};

/// Contains informations about an asset, including its asset id, the contract
/// defining its property, and the transaction that issued the asset.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct AssetEntry {
    /// The identifier of the asset. It's a midstate of a `sha256`, thus it's
    /// 32 supposedly random bytes.
    asset_id: AssetId,

    /// Contains assets metadata provided by the issuer. This information is
    /// commited in the `asset_id` so it's verifiable by third parties. Some
    /// fields in the contract are repeated at this level such as `version`,
    /// `issuer_pubkey`, `name`, `ticker`, `precision` and `entity`. Other
    /// fields could be custom values created by the issuer.
    #[serde(default)]
    contract: serde_json::Value,

    /// Contains information regarding the internet domain of the asset issuer.
    #[serde(default)]
    entity: serde_json::Value,

    /// The previous output that is spent to create this issuance.
    #[serde(default)]
    issuance_prevout: Prevout,

    /// The transaction input containing this issuance.
    #[serde(default)]
    issuance_txin: Txin,

    /// A public key owned by the issuer used for authentication.
    #[serde(default)]
    issuer_pubkey: String,

    /// Name of the asset.
    #[serde(default)]
    name: String,

    /// Precision of the asset as the number of digits after the decimal
    /// separator. Eg. bitcoin use 8 as precision.
    #[serde(default)]
    precision: u8,

    /// Ticker of the asset.
    ticker: Option<String>,

    /// The version of the registry protocol.
    #[serde(default)]
    version: u8,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Prevout {
    txid: Txid,
    vout: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct Txin {
    txid: Txid,
    vin: u32,
}
