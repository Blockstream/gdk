use std::fs;

use bitcoincore_rpc::{Auth, Client};
use url::Url;

use crate::errors::{Error, OptionExt};

use hyper::client::Client as HyperClient;
use hyper_socks::Socks5HttpConnector;
use jsonrpc::client::Client as RpcClient;

#[derive(Debug, Serialize, Clone)]
pub struct RpcConfig {
    pub url: String,
    pub network: String,
    pub cred: Option<(String, String)>, // (username, password)
    pub cookie: Option<String>,
    pub socks5: Option<String>,
}

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

fn make_socks5_client(url: &str) -> Option<HyperClient> {
    let connector = Socks5HttpConnector::new(url).ok();
    connector.map(hyper::Client::with_connector)
}

impl Network {
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
            (false, true, false) => NetworkId::Bitcoin(bitcoin::Network::Bitcoin),
            (false, false, false) => NetworkId::Bitcoin(bitcoin::Network::Testnet),
            (false, false, true) => NetworkId::Bitcoin(bitcoin::Network::Regtest),
            (l, m, d) => panic!("inconsistent network parameters: lq={}, main={}, dev={}", l, m, d),
        }
    }
}

fn read_cookie(path: &str) -> Result<(String, String), Error> {
    let contents = fs::read_to_string(path)?;
    let parts: Vec<&str> = contents.split(':').collect();
    Ok((parts[0].to_string(), parts[1].to_string()))
}
