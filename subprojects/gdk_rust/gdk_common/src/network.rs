use crate::be::asset_to_bin;
use crate::be::AssetId;
use crate::error::Error;
use crate::model::WalletDerivation;
use bitcoin::util::bip32::DerivationPath;
use elements::confidential::Asset;
use elements::{confidential, issuance};
use log::info;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

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
    pub electrum_url: Option<String>,
    pub validate_domain: Option<bool>,
    pub policy_asset: Option<String>,
    pub sync_interval: Option<u32>,
    pub ct_bits: Option<i32>,
    pub ct_exponent: Option<i32>,
    pub ct_min_value: Option<u64>,
    pub spv_enabled: Option<bool>,
    pub asset_registry_url: Option<String>,
    pub asset_registry_onion_url: Option<String>,
    pub wallet_derivation: Option<String>,
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
        let asset_id = issuance::AssetId::from_slice(&asset_id)?;
        Ok(confidential::Asset::Explicit(asset_id))
    }

    pub fn registry_base_url(&self) -> Result<String, Error> {
        self.asset_registry_url
            .as_ref()
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Generic("asset regitry url not available".into()))
    }

    pub fn wallet_derivation(&self) -> WalletDerivation {
        WalletDerivation::from_str(self.wallet_derivation.as_ref().unwrap_or(&"49".to_string()))
            .unwrap_or(WalletDerivation::Bip49)
    }

    pub fn wallet_derivation_path(&self) -> Result<DerivationPath, Error> {
        // BIP44: m / purpose' / coin_type' / account' / change / address_index
        // coin_type = 0 bitcoin, 1 testnet, 1776 liquid bitcoin as defined in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        // slip44 suggest 1 for every testnet, so we are using it also for regtest
        let coin_type: u32 = match self.id() {
            NetworkId::Bitcoin(bitcoin_network) => match bitcoin_network {
                bitcoin::Network::Bitcoin => 0,
                bitcoin::Network::Testnet => 1,
                bitcoin::Network::Regtest => 1,
            },
            NetworkId::Elements(elements_network) => match elements_network {
                ElementsNetwork::Liquid => 1776,
                ElementsNetwork::ElementsRegtest => 1,
            },
        };
        // since we use P2WPKH-nested-in-P2SH it is 49 https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
        let bip = self.wallet_derivation();
        let path_string = format!("m/{}'/{}'/0'", bip, coin_type);
        info!("Using derivation path {}/0|1/*", path_string);

        Ok(DerivationPath::from_str(&path_string)?)
    }
}
