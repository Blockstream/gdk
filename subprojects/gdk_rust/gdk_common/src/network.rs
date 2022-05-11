use std::str::FromStr;

use crate::error::Error;
use bitcoin::util::bip32::{ChildNumber, ExtendedPubKey, Fingerprint};
use bitcoin::{hashes::hex::ToHex, PublicKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct NetworkParameters {
    pub name: String,
    network: String,

    pub development: bool,
    pub liquid: bool,
    pub mainnet: bool,

    tx_explorer_url: String,
    address_explorer_url: String,

    pub electrum_tls: Option<bool>,
    pub electrum_url: Option<String>,
    pub electrum_onion_url: Option<String>,
    pub validate_domain: Option<bool>,
    pub policy_asset: Option<String>,
    pub sync_interval: Option<u32>,
    pub ct_bits: Option<i32>,
    pub ct_exponent: Option<i32>,
    pub ct_min_value: Option<u64>,
    pub spv_enabled: Option<bool>,
    asset_registry_url: Option<String>,
    asset_registry_onion_url: Option<String>,

    pin_server_url: String,
    pin_server_onion_url: String,
    pin_server_public_key: String,

    pub spv_multi: Option<bool>,
    pub spv_servers: Option<Vec<String>>,

    pub proxy: Option<String>,
    pub use_tor: Option<bool>,
    pub max_reorg_blocks: Option<u32>,

    /// For electrum sessions is used as root directory for the db cache and for
    /// the headers chain files
    ///
    /// When using external SPV API is used as root directory for headers chain
    /// files
    ///
    /// Note that electrum session and external API could use the same dir and,
    /// if on the same network, share the same headers chain file but it's
    /// required to use a single process.
    pub state_dir: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElementsNetwork {
    Liquid,
    LiquidTestnet,
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

pub const LIQUID_TESTNET: elements::AddressParams = elements::AddressParams {
    p2pkh_prefix: 36,
    p2sh_prefix: 19,
    blinded_prefix: 23,
    bech_hrp: "tex",
    blech_hrp: "tlq",
};

impl ElementsNetwork {
    pub fn address_params(self: ElementsNetwork) -> &'static elements::AddressParams {
        match self {
            ElementsNetwork::Liquid => &elements::AddressParams::LIQUID,
            ElementsNetwork::LiquidTestnet => &LIQUID_TESTNET,
            ElementsNetwork::ElementsRegtest => &elements::AddressParams::ELEMENTS,
        }
    }
}

impl NetworkParameters {
    pub fn id(&self) -> NetworkId {
        match (self.liquid, self.mainnet, self.development) {
            (true, true, false) => NetworkId::Elements(ElementsNetwork::Liquid),
            (true, false, false) => NetworkId::Elements(ElementsNetwork::LiquidTestnet),
            (true, false, true) => NetworkId::Elements(ElementsNetwork::ElementsRegtest),
            (false, true, false) => NetworkId::Bitcoin(bitcoin::Network::Bitcoin),
            (false, false, false) => NetworkId::Bitcoin(bitcoin::Network::Testnet),
            (false, false, true) => NetworkId::Bitcoin(bitcoin::Network::Regtest),
            (l, m, d) => panic!("inconsistent network parameters: lq={}, main={}, dev={}", l, m, d),
        }
    }

    pub fn policy_asset_id(&self) -> Result<elements::issuance::AssetId, Error> {
        if let Some(a) = self.policy_asset.as_ref() {
            Ok(a.parse()?)
        } else {
            Err("no policy asset".into())
        }
    }

    pub fn use_tor(&self) -> bool {
        self.use_tor.unwrap_or(false)
    }

    pub fn registry_base_url(&self) -> Result<String, Error> {
        if self.use_tor() {
            if let Some(asset_registry_onion_url) = self.asset_registry_onion_url.as_ref() {
                if !asset_registry_onion_url.is_empty() {
                    return Ok(asset_registry_onion_url.into());
                }
            }
        }
        self.asset_registry_url
            .as_ref()
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Generic("asset_registry_url not available".into()))
    }

    pub fn set_asset_registry_url(&mut self, url: String) {
        self.asset_registry_url = Some(url);
    }

    pub fn set_asset_registry_onion_url(&mut self, url: String) {
        self.asset_registry_onion_url = Some(url);
    }

    pub fn pin_server_url(&self) -> &str {
        if self.use_tor() {
            if !self.pin_server_onion_url.is_empty() {
                return &self.pin_server_onion_url;
            }
        }
        &self.pin_server_url
    }

    pub fn pin_manager_public_key(&self) -> Result<PublicKey, Error> {
        Ok(PublicKey::from_str(&self.pin_server_public_key)?)
    }

    // Unique wallet identifier for the given xpub on this network. Used as part of the database
    // root path, any changes will result in the creation of a new separate database.
    pub fn wallet_hash_id(&self, master_xpub: &ExtendedPubKey) -> String {
        assert_eq!(self.bip32_network(), master_xpub.network);
        // Only network, public_key and chain_code contribute to the hash
        let mut xpub = master_xpub.clone();
        xpub.depth = 0;
        xpub.parent_fingerprint = Fingerprint::default();
        xpub.child_number = ChildNumber::from_normal_idx(0).unwrap();
        let password = xpub.encode().to_vec();
        let salt = self.network.as_bytes().to_vec();
        let cost = 2048;
        crate::wally::pbkdf2_hmac_sha512_256(password, salt, cost).to_hex()
    }

    pub fn bip32_network(&self) -> bitcoin::network::constants::Network {
        if self.mainnet {
            bitcoin::network::constants::Network::Bitcoin
        } else {
            bitcoin::network::constants::Network::Testnet
        }
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};

    #[test]
    fn test_wallet_hash_id() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let seed = crate::wally::bip39_mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        ).unwrap();
        let master_xprv = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &seed).unwrap();
        let master_xpub = ExtendedPubKey::from_private(&secp, &master_xprv);
        let mut network = crate::NetworkParameters::default();
        network.network = "mainnet".to_string();
        network.mainnet = true;
        let wallet_hash_id = network.wallet_hash_id(&master_xpub);
        // Value got logging in with the above mnemonic with network name "mainnet" (ga_session)
        assert_eq!(
            wallet_hash_id,
            "ca8f6b74e485133f441e01313682e6d5613cedbe479b2c472e017e21cc42a052"
        );
    }
}
