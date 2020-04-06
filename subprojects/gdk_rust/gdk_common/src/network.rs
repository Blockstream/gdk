use crate::be::AssetId;
use serde_derive::{Deserialize, Serialize};
use std::convert::TryInto;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Network {
    name: String,
    network: String,

    bech32_prefix: String,
    p2pkh_version: u32,
    p2sh_version: u32,

    pub development: bool,
    pub liquid: bool,
    pub mainnet: bool,

    tx_explorer_url: String,
    address_explorer_url: String,

    pub tls: Option<bool>,
    pub url: Option<String>,
    pub validate_domain: Option<bool>,
    pub policy_asset: Option<String>,
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

    pub fn policy_asset(&self) -> Result<AssetId, crate::error::Error> {
        if let Some(str) = self.policy_asset.as_ref() {
            let vec = hex::decode(str)?;
            let asset: AssetId = (&vec[..]).try_into()?;
            Ok(asset)
        } else {
            Err("no policy asset".into())
        }
    }
}
