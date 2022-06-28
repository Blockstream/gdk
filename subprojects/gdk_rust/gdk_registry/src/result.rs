use elements::{AssetId, ContractHash, OutPoint, Txid};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;

use crate::Error;

/// Contains the result of the [`crate::refresh_assets`] call with the `assets` or `icons` field
/// non-empty if [`crate::RefreshAssetsParam`] has respective field `asset` or `icon` equal to `true`.
/// If `refresh` field in the param is `true` this information is the most
/// up-to-date for the asset registry used.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct RegistryResult {
    /// Assets metadata
    pub(crate) assets: HashMap<AssetId, AssetEntry>,

    /// Assets icons: the hashmap value is a Base64 encoded image
    pub(crate) icons: HashMap<AssetId, String>,
}

// TODO: avoid code duplication in `CacheResult`.
impl RegistryResult {
    /// Splits the asset ids based on whether they are already contained in the
    /// cache.
    pub(crate) fn split_present<I>(&self, ids: I) -> (Vec<AssetId>, Vec<AssetId>)
    where
        I: IntoIterator<Item = AssetId>,
    {
        ids.into_iter().partition(|id| self.contains(id))
    }

    /// Returns whether the assets contain a certain `AssetId`.
    pub(crate) fn contains(&self, asset: &AssetId) -> bool {
        self.assets.contains_key(asset)
    }

    /// Filters the registry against a group of `AssetId`s, only keeping the
    /// `assets` and `icons` that match an `AssetId`.
    pub(crate) fn filter(&mut self, query: &[AssetId]) {
        self.assets.retain(|id, _| query.contains(&id));
        self.icons.retain(|id, _| query.contains(&id));
    }
}

/// Contains information about an asset, including its asset id, the contract defining its
/// property, and information about the transaction that issued the asset.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct AssetEntry {
    /// The identifier of the asset, it is a midstate of a `sha256` thus it's 32 supposedly random bytes.
    pub(crate) asset_id: AssetId,

    /// Contains assets metadata provided by the issuer. This information is commited in the
    /// `asset_id` so it's verifiable by third parties. Some fields in the contract are repeated at
    /// this level such as `version`, `issuer_pubkey`, `name`, `ticker`, `precision` and `entity`.
    /// Other fields could be custom values created by the issuer.
    #[serde(default)]
    pub(crate) contract: Value,

    /// The transaction input containing this issuance.
    #[serde(default)]
    pub(crate) issuance_txin: Txin,

    /// The previous output that is spent to create this issuance.
    #[serde(default)]
    pub(crate) issuance_prevout: Prevout,

    /// The version of the registry protocol.
    #[serde(default)]
    pub(crate) version: u8,

    /// A public key owned by the issuer used for authentication.
    #[serde(default)]
    pub(crate) issuer_pubkey: String,

    /// Name of the asset.
    #[serde(default)]
    pub(crate) name: String,

    /// Ticker of the asset.
    pub(crate) ticker: Option<String>,

    /// Precision of the asset as the number of digits after the decimal separator.
    /// Eg. bitcoin use 8 as precision.
    #[serde(default)]
    pub(crate) precision: u8,

    /// Contains information regarding the internet domain of the asset issuer.
    #[serde(default)]
    pub(crate) entity: Value,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub(crate) struct Prevout {
    txid: Txid,
    vout: u32,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub(crate) struct Txin {
    txid: Txid,
    vin: u32,
}

impl AssetEntry {
    fn contract_string(&self) -> Result<String, Error> {
        Ok(serde_json::to_string(&self.contract)?)
    }

    fn issuance_prevout(&self) -> OutPoint {
        OutPoint::new(self.issuance_prevout.txid, self.issuance_prevout.vout)
    }

    /// Verify information in `self.contract` commits in `self.asset_id` ensuring the validity of the
    /// Contract data. Moreover information in the first level like `self.name` is verified to be the
    /// same of the one in the contract `self.contract.name`
    pub(crate) fn verify(&self) -> Result<bool, Error> {
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

#[cfg(test)]
mod test {
    use elements::bitcoin::hashes::hex::FromHex;
    use elements::{AssetId, ContractHash};
    use serde_json::json;

    use super::*;

    #[test]
    fn test_policy() {
        let policy = json!({"asset_id": "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d", "name": "Liquid Bitcoin", "ticker": "L-BTC"});
        let _policy_value: AssetEntry = serde_json::from_value(policy).unwrap();
    }

    #[test]
    fn test_asset_commitment() {
        let tether_entry = r#"{"asset_id":"ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2","contract":{"entity":{"domain":"tether.to"},"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904","name":"Tether USD","precision":8,"ticker":"USDt","version":0},"issuance_txin":{"txid":"abb4080d91849e933ee2ed65da6b436f7c385cf363fb4aa08399f1e27c58ff3d","vin":0},"issuance_prevout":{"txid":"9596d259270ef5bac0020435e6d859aea633409483ba64e232b8ba04ce288668","vout":0},"name":"Tether USD","ticker":"USDt","precision":8,"entity":{"domain":"tether.to"},"version":0,"issuer_pubkey":"0337cceec0beea0232ebe14cba0197a9fbd45fcf2ec946749de920e71434c2b904"}"#;
        let tether_parsed: AssetEntry = serde_json::from_str(tether_entry).unwrap();
        let expected_contract_hash = ContractHash::from_hex(
            "3c7f0a53c2ff5b99590620d7f6604a7a3a7bfbaaa6aa61f7bfc7833ca03cde82",
        )
        .unwrap();
        let tether_contract_hash =
            ContractHash::from_json_contract(&tether_parsed.contract_string().unwrap()).unwrap();
        assert_eq!(expected_contract_hash, tether_contract_hash);

        let entropy =
            AssetId::generate_asset_entropy(tether_parsed.issuance_prevout(), tether_contract_hash);
        let asset_id = AssetId::from_entropy(entropy);

        assert_eq!(asset_id, tether_parsed.asset_id);
        assert!(tether_parsed.verify().unwrap());

        let mut tether_wrong_id = tether_parsed.clone();
        tether_wrong_id.asset_id = AssetId::default();
        assert!(!tether_wrong_id.verify().unwrap());

        let asset_entry = r#"{"asset_id":"967d5b213f94db19b0b29138042e9afb54245857aebdb00343b17e017bdead1e","contract":{"entity":{"domain":"artmirable.bfungible.network"},"file":"QmeVVZP7kKakdXkUcnG2pCvTnAkgjGaJgKkxPkkDAcdknM","icon":{"cid":"QmQKqdbpm367ZWBA9DG96rjdMYa8J9EL9sxyjfyrCnZ4v2","content_type":"image/jpeg","hash":"28c2416b6e8ec79d6014de541314be23bdb8ae88c582cf5cb4679c35ff7aed8b"},"issuer_pubkey":"032707d05b6aa5e823956b5a0d83e5d1d2acd80e8d8d5a2833f3157f3604b0ef8d","name":"The Flower Thrower 5271/10K","nft":{"cid":"QmZVAFJwMVn6cnkxBAbBEukv9N57Pfg3x7w4aBak69vy65","domain":"artmirable.bfungible.network","hash":"f448311d1f7b16ab69f1920c73e9a48b1913a463579d86703cd61f3c0c22c702"},"precision":0,"ticker":"B5271","version":0},"issuance_txin":{"txid":"4aa97ffbd885162ade3eae35c72168c7b591fae0cae2882204237f9e2c69235e","vin":0},"issuance_prevout":{"txid":"d8dd38ee8a2e1d7665e675dcddd3e223267829a66e678ceafbf727ecc8ccd654","vout":0},"version":0,"issuer_pubkey":"032707d05b6aa5e823956b5a0d83e5d1d2acd80e8d8d5a2833f3157f3604b0ef8d","name":"The Flower Thrower 5271/10K","ticker":"B5271","collection":null,"precision":0,"entity":{"domain":"artmirable.bfungible.network"}}"#;
        let parsed: AssetEntry = serde_json::from_str(asset_entry).unwrap();
        assert!(parsed.verify().unwrap());

        let mut parsed_wrong_contract = parsed.clone();
        *parsed_wrong_contract.contract.get_mut("precision").unwrap() = 5.into();
        assert!(!parsed_wrong_contract.verify().unwrap());
    }

    #[test]
    fn test_json() {
        let assets = {
            let mut assets = HashMap::new();
            assets.insert(AssetId::default(), AssetEntry::default());
            assets
        };
        let icons = {
            let mut icons = HashMap::new();
            icons.insert(AssetId::default(), "BASE64".into());
            icons
        };
        let mut r = RegistryResult {
            assets,
            icons,
        };
        let expected: Value = serde_json::from_str(include_str!("data/test/result.json")).unwrap();
        assert_eq!(serde_json::to_value(&r).unwrap(), expected);
        r.icons.clear();
        r.assets.clear();
        assert_eq!(serde_json::to_value(&r).unwrap(), json!({"assets":{}, "icons":{}}));
    }
}
