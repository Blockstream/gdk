use crate::error::Error;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{DerivationPath, ExtendedPubKey};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Network {
    pub name: String,
    network: String,

    pub development: bool,
    pub liquid: bool,
    pub mainnet: bool,

    tx_explorer_url: String,
    address_explorer_url: String,

    pub electrum_tls: Option<bool>,
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

    // These fields must NOT be encoded as part of the wallet identifier
    // to retain backwards compatibility.
    pub spv_multi: Option<bool>,
    pub spv_servers: Option<Vec<String>>,
    pub taproot_enabled_at: Option<u32>,
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

impl Network {
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

    pub fn registry_base_url(&self) -> Result<String, Error> {
        self.asset_registry_url
            .as_ref()
            .map(|s| s.to_string())
            .ok_or_else(|| Error::Generic("asset regitry url not available".into()))
    }

    // Unique wallet identifier for the given xpub on this network. Used as part of the database
    // root path, any changes will result in the creation of a new separate database.
    pub fn wallet_hash_id(&self, master_xpub: &ExtendedPubKey) -> String {
        assert_eq!(self.bip32_network(), master_xpub.network);
        let password = master_xpub.encode().to_vec();
        let salt = self.network.as_bytes().to_vec();
        let cost = 2048;
        hex::encode(crate::wally::pbkdf2_hmac_sha512_256(password, salt, cost))
    }

    pub fn bip32_network(&self) -> bitcoin::network::constants::Network {
        if self.mainnet {
            bitcoin::network::constants::Network::Bitcoin
        } else {
            bitcoin::network::constants::Network::Testnet
        }
    }
}

// Unique wallet id (to derive db dir) and xpub (to derive the decryption key) used by Aqua wallet for backward compatibility
pub fn aqua_unique_id_and_xpub(
    seed: &[u8],
    id: NetworkId,
) -> Result<(sha256::Hash, ExtendedPubKey), Error> {
    // master xprv must use network testnet to maintain backward compatibility
    let master_xprv =
        bitcoin::util::bip32::ExtendedPrivKey::new_master(bitcoin::Network::Testnet, seed)?;
    // Values obtained from src/network_parameters.cpp from version 0.0.37, the one used by Aqua
    // "name" field is overwritten as Aqua did.
    let s = match id {
        NetworkId::Bitcoin(bitcoin::Network::Bitcoin) => {
            r#"{"address_explorer_url": "https://blockstream.info/address/", "bip21_prefix": "bitcoin", "development": false, "electrum_url": "blockstream.info:700", "liquid": false, "mainnet": true, "name": "electrum-mainnet", "network": "electrum-mainnet", "server_type": "electrum", "spv_enabled": false, "tls": true, "tx_explorer_url": "https://blockstream.info/tx/"}"#
        }
        NetworkId::Bitcoin(bitcoin::Network::Testnet) => {
            r#"{"address_explorer_url": "https://blockstream.info/testnet/address/", "bip21_prefix": "bitcoin", "development": false, "electrum_url": "blockstream.info:993", "liquid": false, "mainnet": false, "name": "electrum-testnet", "network": "electrum-testnet", "server_type": "electrum", "spv_enabled": false, "tls": true, "tx_explorer_url": "https://blockstream.info/testnet/tx/"}"#
        }
        NetworkId::Elements(ElementsNetwork::Liquid) => {
            r#"{"address_explorer_url": "https://blockstream.info/liquid/address/", "asset_registry_onion_url": "http://vi5flmr4z3h3luup.onion", "asset_registry_url": "https://assets.blockstream.info", "bip21_prefix": "liquidnetwork", "ct_bits": 52, "ct_exponent": 0, "development": false, "electrum_url": "blockstream.info:995", "liquid": true, "mainnet": true, "name": "liquid-electrum-mainnet", "network": "liquid-electrum-mainnet", "policy_asset": "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d", "server_type": "electrum", "spv_enabled": false, "tls": true, "tx_explorer_url": "https://blockstream.info/liquid/tx/"}"#
        }
        _ => return Err("network was not supported".into()),
    };

    let secp = Secp256k1::new();
    let purpose = 49;
    let coin_type = match id {
        NetworkId::Bitcoin(bitcoin::Network::Bitcoin) => 0,
        NetworkId::Bitcoin(bitcoin::Network::Testnet) => 1,
        NetworkId::Elements(ElementsNetwork::Liquid) => 1776,
        _ => return Err("network was not supported".into()),
    };
    let bip32_account_num = 0;
    let path: DerivationPath =
        format!("m/{}'/{}'/{}'", purpose, coin_type, bip32_account_num).parse().unwrap();
    let xprv = master_xprv.derive_priv(&secp, &path).unwrap();
    let xpub = ExtendedPubKey::from_private(&secp, &xprv);

    // Fields used to compute the unique identifier. Must be kept with the exact same names,
    // data types and ordering.
    #[derive(Debug, Deserialize)]
    struct Network {
        name: String,
        network: String,
        development: bool,
        liquid: bool,
        mainnet: bool,
        tx_explorer_url: String,
        address_explorer_url: String,
        tls: Option<bool>,
        electrum_url: Option<String>,
        validate_domain: Option<bool>,
        policy_asset: Option<String>,
        sync_interval: Option<u32>,
        ct_bits: Option<i32>,
        ct_exponent: Option<i32>,
        ct_min_value: Option<u64>,
        spv_enabled: Option<bool>,
        asset_registry_url: Option<String>,
        asset_registry_onion_url: Option<String>,
    }

    let net_unique: Network = serde_json::from_value(serde_json::from_str(s).unwrap()).unwrap();

    let wallet_desc = format!("{}{:?}", xpub, net_unique);
    Ok((sha256::Hash::hash(wallet_desc.as_bytes()), xpub))
}

#[cfg(test)]
mod tests {
    use crate::network::{aqua_unique_id_and_xpub, ElementsNetwork, NetworkId};
    use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
    use bitcoin::Network;
    use std::str::FromStr;

    #[test]
    fn test_aqua() {
        let seed = crate::wally::bip39_mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        ).unwrap();
        let (wallet_id_testnet, xpub_testnet) =
            aqua_unique_id_and_xpub(&seed, NetworkId::Bitcoin(Network::Testnet)).unwrap();
        let (wallet_id_bitcoin, xpub_bitcoin) =
            aqua_unique_id_and_xpub(&seed, NetworkId::Bitcoin(Network::Bitcoin)).unwrap();
        let (wallet_id_liquid, xpub_liquid) =
            aqua_unique_id_and_xpub(&seed, NetworkId::Elements(ElementsNetwork::Liquid)).unwrap();
        assert_eq!(
            hex::encode(wallet_id_testnet),
            "588079b940d8d1fd18d0fc26c3ed1af358c603b4572adea13482fc85ff100bb2"
        );
        assert_eq!(
            hex::encode(wallet_id_bitcoin),
            "9abca26e46f9caffbf676e40e96a4a9e3318fad85e720ae4c49ed2d629c26ff8"
        );
        assert_eq!(
            hex::encode(wallet_id_liquid),
            "0f703b3ea6a782d45d7d2b109db94f79d812bd4459faa481c7c7e437818a1835"
        );
        assert_eq!(
            xpub_testnet,
            ExtendedPubKey::from_str("tpubDD7tXK8KeQ3YY83yWq755fHY2JW8Ha8Q765tknUM5rSvjPcGWfUppDFMpQ1ScziKfW3ZNtZvAD7M3u7bSs7HofjTD3KP3YxPK7X6hwV8Rk2").unwrap()
        );
        assert_eq!(
            xpub_bitcoin,
            ExtendedPubKey::from_str("tpubDCUQwB7GDsQKGfGk1CpCxzkWwWQodwKRttFB55vhCbMu8RGdQZ1k2ayVXmdJrER313963TTB4dRdx12JLjjBNpcs3v6shG93ci6A2XiGuJN").unwrap()
        );
        assert_eq!(
            xpub_liquid,
            ExtendedPubKey::from_str("tpubDCj7tPbTBu12vKY9UjbQSsBMVm9c1ktgp6cEHsPiv4WEB8vngnMpyY8tsmUDgEs3fg6SEvhmv7YF9fLYMiLsHt7B5oABqGTQuiShhp6DuVU").unwrap()
        );
    }

    #[test]
    fn test_wallet_hash_id() {
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let seed = crate::wally::bip39_mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
        ).unwrap();
        let master_xprv = ExtendedPrivKey::new_master(bitcoin::Network::Bitcoin, &seed).unwrap();
        let master_xpub = ExtendedPubKey::from_private(&secp, &master_xprv);
        let mut network = crate::Network::default();
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
