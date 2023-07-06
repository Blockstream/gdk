use std::collections::HashMap;
use std::fmt;

use gdk_common::elements::AssetId;
use serde::{ser, Deserialize, Serialize};

use crate::asset_entry::AssetEntry;

pub(crate) type RegistryAssets = HashMap<AssetId, AssetEntry>;
pub(crate) type RegistryIcons = HashMap<AssetId, String>;

/// Asset informations returned by [`get_assets`](crate::get_assets).
#[derive(Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegistryInfos {
    /// Assets metadata.
    pub assets: RegistryAssets,

    /// Assets icons: the hashmap value is a Base64 encoded image.
    pub icons: RegistryIcons,

    #[serde(default, skip_serializing)]
    pub(crate) source: Option<RegistrySource>,
}

/// Max number of assets and icons included in the debug output of
/// [`RegistryInfos`].
const REGISTRY_INFOS_DEBUG_LIMIT: usize = 64;

// Custom `Debug` impl to avoid having full base64 encoded images in debug
// logs.
impl fmt::Debug for RegistryInfos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let assets = self.assets.iter().take(REGISTRY_INFOS_DEBUG_LIMIT).collect::<HashMap<_, _>>();

        let icons = self
            .icons
            .iter()
            .map(|(id, _b64)| (id, "..."))
            .take(REGISTRY_INFOS_DEBUG_LIMIT)
            .collect::<HashMap<_, _>>();

        f.debug_struct("RegistryInfos")
            .field("assets", &assets)
            .field("icons", &icons)
            .field("source", &self.source)
            .finish()
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Deserialize)]
pub enum RegistrySource {
    Cache,
    Downloaded,
    LocalRegistry,
    NotModified,
}

impl Default for RegistrySource {
    fn default() -> Self {
        Self::LocalRegistry
    }
}

impl ser::Serialize for RegistrySource {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: ser::Serializer,
    {
        serializer.serialize_unit()
    }
}

impl RegistryInfos {
    pub(crate) fn contains_asset(&self, id: &AssetId) -> bool {
        self.assets.contains_key(id)
    }

    pub(crate) fn contains_icon(&self, id: &AssetId) -> bool {
        self.icons.contains_key(id)
    }

    pub(crate) const fn new(assets: RegistryAssets, icons: RegistryIcons) -> Self {
        Self {
            assets,
            icons,
            source: None,
        }
    }

    pub(crate) const fn new_with_source(
        assets: RegistryAssets,
        icons: RegistryIcons,
        source: RegistrySource,
    ) -> Self {
        Self {
            assets,
            icons,
            source: Some(source),
        }
    }
}

impl RegistrySource {
    pub(crate) fn merge(self, other: Self) -> Self {
        use RegistrySource::*;
        match (self, other) {
            (Cache, source) | (source, Cache) => source,
            (Downloaded, _) | (_, Downloaded) => Downloaded,
            (LocalRegistry, source) | (source, LocalRegistry) => source,
            (NotModified, NotModified) => NotModified,
        }
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use gdk_common::elements::{AssetId, ContractHash};
    use serde_json::{json, Value};

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
        let expected_contract_hash = ContractHash::from_str(
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
        assert!(tether_parsed.verifies().unwrap());

        let mut tether_wrong_id = tether_parsed.clone();
        tether_wrong_id.asset_id = AssetId::default();
        assert!(!tether_wrong_id.verifies().unwrap());

        let asset_entry = r#"{"asset_id":"967d5b213f94db19b0b29138042e9afb54245857aebdb00343b17e017bdead1e","contract":{"entity":{"domain":"artmirable.bfungible.network"},"file":"QmeVVZP7kKakdXkUcnG2pCvTnAkgjGaJgKkxPkkDAcdknM","icon":{"cid":"QmQKqdbpm367ZWBA9DG96rjdMYa8J9EL9sxyjfyrCnZ4v2","content_type":"image/jpeg","hash":"28c2416b6e8ec79d6014de541314be23bdb8ae88c582cf5cb4679c35ff7aed8b"},"issuer_pubkey":"032707d05b6aa5e823956b5a0d83e5d1d2acd80e8d8d5a2833f3157f3604b0ef8d","name":"The Flower Thrower 5271/10K","nft":{"cid":"QmZVAFJwMVn6cnkxBAbBEukv9N57Pfg3x7w4aBak69vy65","domain":"artmirable.bfungible.network","hash":"f448311d1f7b16ab69f1920c73e9a48b1913a463579d86703cd61f3c0c22c702"},"precision":0,"ticker":"B5271","version":0},"issuance_txin":{"txid":"4aa97ffbd885162ade3eae35c72168c7b591fae0cae2882204237f9e2c69235e","vin":0},"issuance_prevout":{"txid":"d8dd38ee8a2e1d7665e675dcddd3e223267829a66e678ceafbf727ecc8ccd654","vout":0},"version":0,"issuer_pubkey":"032707d05b6aa5e823956b5a0d83e5d1d2acd80e8d8d5a2833f3157f3604b0ef8d","name":"The Flower Thrower 5271/10K","ticker":"B5271","collection":null,"precision":0,"entity":{"domain":"artmirable.bfungible.network"}}"#;
        let parsed: AssetEntry = serde_json::from_str(asset_entry).unwrap();
        assert!(parsed.verifies().unwrap());

        let mut parsed_wrong_contract = parsed.clone();
        *parsed_wrong_contract.contract.get_mut("precision").unwrap() = 5.into();
        assert!(!parsed_wrong_contract.verifies().unwrap());
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
        let mut r = RegistryInfos::new(assets, icons);
        let expected: Value =
            serde_json::from_str(include_str!("../../gdk_registry/src/data/test/result.json"))
                .unwrap();
        assert_eq!(serde_json::to_value(&r).unwrap(), expected);
        r.icons.clear();
        r.assets.clear();
        assert_eq!(serde_json::to_value(&r).unwrap(), json!({"assets":{}, "icons":{}}));
    }
}
