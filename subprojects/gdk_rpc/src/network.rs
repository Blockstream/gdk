use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;

use bitcoin::network::constants::Network as NetworkType;
use bitcoincore_rpc::{Auth, Client};
use url::Url;

use crate::bitcoincore_rpc::RpcApi;
use crate::errors::{Error, OptionExt};

use hyper::client::Client as HyperClient;
use hyper_socks::Socks5HttpConnector;
use jsonrpc::client::Client as RpcClient;

#[derive(Debug, Serialize, Clone)]
pub struct RpcConfig {
    pub url: String,
    pub cred: Option<(String, String)>, // (username, password)
    pub cookie: Option<String>,
    pub socks5: Option<String>,
}

#[derive(Debug, Serialize, Clone)]
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

    // unimplemented
    default_peers: Vec<String>,
    service_chain_code: String,
    service_pubkey: String,
    wamp_onion_url: String,
    wamp_url: String,
    wamp_cert_pins: Vec<String>,
    wamp_cert_roots: Vec<String>,
}

lazy_static! {
    static ref NETWORKS: HashMap<String, Network> = {
        let mut networks = HashMap::new();

        let rpc_url = env::var("BITCOIND_URL")
            .ok()
            .unwrap_or_else(|| "http://127.0.0.1:18443".to_string());

        let rpc_cookie = env::var("BITCOIND_DIR")
            .ok()
            .map(|p| Path::new(&p).join(".cookie").to_string_lossy().into_owned());

        networks.insert(
            "bitcoin-regtest".to_string(),
            Network {
                name: "Regtest".to_string(),
                network: "regtest".to_string(),
                tx_explorer_url: "https://blockstream.info/tx/".to_string(),
                address_explorer_url: "https://blockstream.info/address/".to_string(),

                bech32_prefix: "bcrt".to_string(),
                p2pkh_version: 111,
                p2sh_version: 196,

                development: true, // TODO
                liquid: false,
                mainnet: false,

                default_peers: vec![],
                service_chain_code: "".to_string(),
                service_pubkey: "".to_string(),
                wamp_onion_url: "".to_string(),
                wamp_url: "".to_string(),
                wamp_cert_pins: vec![],
                wamp_cert_roots: vec![],
            },
        );

        networks.insert(
            "elements-regtest".to_string(),
            Network {
                name: "Elements Regtest".to_string(),
                network: "elementsregtest".to_string(),
                tx_explorer_url: "https://blockstream.info/tx/".to_string(),
                address_explorer_url: "https://blockstream.info/address/".to_string(),

                bech32_prefix: "ert".to_string(),
                p2pkh_version: 235,
                p2sh_version: 75,

                development: true, // TODO
                liquid: true,
                mainnet: false,

                default_peers: vec![],
                service_chain_code: "".to_string(),
                service_pubkey: "".to_string(),
                wamp_onion_url: "".to_string(),
                wamp_url: "".to_string(),
                wamp_cert_pins: vec![],
                wamp_cert_roots: vec![],
            },
        );

        networks.insert(
            "bitcoin-mainnet".to_string(),
            Network {
                name: "Bitcoin Mainnet".to_string(),
                network: "mainnet".to_string(),
                tx_explorer_url: "https://blockstream.info/tx/".to_string(),
                address_explorer_url: "https://blockstream.info/address/".to_string(),

                bech32_prefix: "bc".to_string(),
                p2pkh_version: 0,
                p2sh_version: 5,

                development: false, // TODO
                liquid: false,
                mainnet: true,

                default_peers: vec![],
                service_chain_code: "".to_string(),
                service_pubkey: "".to_string(),
                wamp_onion_url: "".to_string(),
                wamp_url: "".to_string(),
                wamp_cert_pins: vec![],
                wamp_cert_roots: vec![],
            },
        );

        networks
    };
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

fn make_socks5_client(url: &str) -> Option<HyperClient> {
    let connector = Socks5HttpConnector::new(url).ok();
    connector.map(hyper::Client::with_connector)
}

impl Network {
    pub fn list() -> &'static HashMap<String, Network> {
        &NETWORKS
    }

    pub fn get(id: &str) -> Option<&'static Network> {
        NETWORKS.get(id)
    }

    pub fn connect(rpc: &RpcConfig, wallet: Option<&str>) -> Result<Client, Error> {
        let cred = rpc
            .cred
            .clone()
            .or_else(|| rpc.cookie.as_ref().and_then(|path| read_cookie(path).ok()))
            .or_err("missing rpc credentials")?;

        let (rpc_user, rpc_pass) = cred;

        let mut rpc_url = Url::parse(&rpc.url)?;
        if let Some(wallet) = wallet {
            rpc_url = rpc_url.join(&format!("/wallet/{}", wallet))?;
        }

        if let Some(socks5client) = rpc.socks5.as_ref().and_then(|s| make_socks5_client(&s)) {
            let jsonrpc = RpcClient::with_client(
                rpc_url.to_string(),
                Some(rpc_user),
                Some(rpc_pass),
                socks5client,
            );
            Ok(Client::from_jsonrpc(jsonrpc))
        } else {
            Client::new(rpc_url.to_string(), Auth::UserPass(rpc_user, rpc_pass))
                .map_err(|e| e.into())
        }
    }

    pub fn id(&self) -> NetworkId {
        match (self.liquid, self.mainnet, self.development) {
            (true, true, false) => NetworkId::Elements(ElementsNetwork::Liquid),
            (true, false, true) => NetworkId::Elements(ElementsNetwork::ElementsRegtest),
            (_, true, false) => NetworkId::Bitcoin(bitcoin::Network::Bitcoin),
            (_, false, true) => NetworkId::Bitcoin(bitcoin::Network::Regtest),
            (l, m, d) => panic!("inconsistent network parameters: lq={}, main={}, dev={}", l, m, d),
        }
    }
}

pub fn detect_network_config(client: Client, is_elements: bool) -> Result<Network, Error> {
    let info = client.get_blockchain_info()?;
    // let blockhash = client.get_block_hash(0)?;

    // let genesis = "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f";

    let chain_type = match info.chain.as_ref() {
        "main" => Some(NetworkType::Bitcoin),
        "test" => Some(NetworkType::Testnet),
        "regtest" => Some(NetworkType::Regtest),
        _ => None,
    }
    .ok_or(Error::Other("unknown chain type".into()))?;

    let lookup = match (chain_type, is_elements) {
        (NetworkType::Bitcoin, false) => Some("bitcoin-mainnet"),
        (NetworkType::Regtest, false) => Some("bitcoin-regtest"),
        (NetworkType::Testnet, false) => Some("bitcoin-testnet"),
        (NetworkType::Bitcoin, true) => Some("elements-mainnet"),
        (NetworkType::Regtest, true) => Some("elements-regtest"),
        (NetworkType::Testnet, true) => Some("elements-testnet"),
        _ => None,
    }
    .ok_or(Error::Other("unknown network configuration".into()))?;

    Network::get(lookup).map(|n| n.clone()).ok_or(Error::Other("unknown network config".into()))
}

fn read_cookie(path: &str) -> Result<(String, String), Error> {
    let contents = fs::read_to_string(path)?;
    let parts: Vec<&str> = contents.split(':').collect();
    Ok((parts[0].to_string(), parts[1].to_string()))
}
