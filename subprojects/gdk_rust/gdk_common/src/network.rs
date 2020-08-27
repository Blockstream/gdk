use crate::be::asset_to_bin;
use crate::be::AssetId;
use crate::error::Error;
use serde_derive::{Deserialize, Serialize};
use elements::confidential::Asset;
use bitcoin::hashes::{sha256d, Hash};
use elements::confidential;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Network {
    name: String,
    network: String,

    pub development: bool,
    pub liquid: bool,
    pub mainnet: bool,

    tx_explorer_url: String,
    address_explorer_url: String,

    pub tls: Option<bool>,
    pub url: Option<String>,
    pub validate_domain: Option<bool>,
    pub policy_asset: Option<String>,
    pub sync_interval: Option<u32>,
    pub ct_bits: Option<i32>,
    pub ct_exponent: Option<i32>,
    pub ct_min_value: Option<u64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElementsNetwork {
    Liquid,
    ElementsRegtest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkId {
    Elements(ElementsNetwork),
    Bitcoin(bitcoin::Network),
}

impl NetworkId {
    pub fn get_bitcoin_network(self: NetworkId) -> Option<bitcoin::Network> {
        match self {
            NetworkId::Bitcoin(net) => Some(net),
            _ => None,
        }
    }
    pub fn get_elements_network(self: NetworkId) -> Option<ElementsNetwork> {
        match self {
            NetworkId::Elements(net) => Some(net),
            _ => None,
        }
    }
}

impl Network {
    pub fn id(&self) -> NetworkId {
        match (self.liquid, self.mainnet, self.development) {
            (true, true, false) => NetworkId::Elements(ElementsNetwork::Liquid),
            (true, false, true) => NetworkId::Elements(ElementsNetwork::ElementsRegtest),
            (false, true, false) => NetworkId::Bitcoin(bitcoin::Network::Bitcoin),
            (false, false, false) => NetworkId::Bitcoin(bitcoin::Network::Testnet),
            (false, false, true) => NetworkId::Bitcoin(bitcoin::Network::Regtest),
            (l, m, d) => panic!("inconsistent network parameters: lq={}, main={}, dev={}", l, m, d),
        }
    }

    pub fn policy_asset_id(&self) -> Result<AssetId, Error> {
        if let Some(str) = self.policy_asset.as_ref() {
            Ok(asset_to_bin(str)?)
        } else {
            Err("no policy asset".into())
        }
    }

    pub fn policy_asset(&self) -> Result<Asset, Error> {
        let asset_id = self.policy_asset_id()?;
        Ok(confidential::Asset::Explicit(sha256d::Hash::from_inner(asset_id)))
    }
}
