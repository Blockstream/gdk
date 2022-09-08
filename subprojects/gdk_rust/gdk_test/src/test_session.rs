use std::thread;
use std::time::Duration;

use electrsd::bitcoind::bitcoincore_rpc::RpcApi;
use electrum_client::ElectrumApi;
use log::{info, warn};
use serde_json::{json, Value};
use tempfile::TempDir;

use gdk_common::be::*;
use gdk_common::model::*;
use gdk_common::session::Session;
use gdk_common::{ElementsNetwork, NetworkId, NetworkParameters, State};
use gdk_electrum::{ElectrumSession, Notification, TransactionNotification};

use crate::env;
use crate::RpcNodeExt;

const MAX_FEE_PERCENT_DIFF: f64 = 0.05;

#[allow(unused)]
pub struct TestSession {
    pub node: electrsd::bitcoind::BitcoinD,
    pub electrs: electrsd::ElectrsD,
    pub session: ElectrumSession,
    pub credentials: Credentials,
    tx_status: u64,
    block_status: (u32, BEBlockHash),
    state_dir: TempDir,
    network_id: NetworkId,
    pub network: NetworkParameters,
    pub p2p_port: u16,
}

impl TestSession {
    pub fn new<F>(is_liquid: bool, network_conf: Option<F>) -> Self
    where
        F: FnOnce(&mut NetworkParameters),
    {
        let (node, electrs) = if !is_liquid {
            (env::BITCOIND_EXEC, env::ELECTRS_EXEC)
        } else {
            (env::ELEMENTSD_EXEC, env::ELECTRS_LIQUID_EXEC)
        };

        let is_debug = std::env::var("DEBUG").is_ok();

        let _ = env_logger::try_init();

        let mut args = vec!["-fallbackfee=0.0001", "-dustrelayfee=0.00000001"];
        let network = if is_liquid {
            args.extend_from_slice(&[
                "-chain=liquidregtest",
                "-initialfreecoins=2100000000",
                "-validatepegin=0",
            ]);
            "liquidregtest"
        } else {
            args.extend_from_slice(&["-regtest"]);
            "regtest"
        };
        let mut conf = electrsd::bitcoind::Conf::default();
        conf.args = args;
        conf.view_stdout = is_debug;
        conf.p2p = electrsd::bitcoind::P2P::Yes;
        conf.network = network;

        let node = electrsd::bitcoind::BitcoinD::with_conf(&node, &conf).unwrap();
        info!("node spawned");

        node.client.generatetoaddress(1, None, None).unwrap();

        if is_liquid {
            // the rescan is needed to see the initialfreecoins
            node.client.rescan_blockchain(None, None).unwrap();
        }

        let p2p_port = node.params.p2p_socket.unwrap().port();

        let mut args = vec![];
        if is_debug {
            args.push("-v");
        }

        let mut conf = electrsd::Conf::default();
        conf.args = args;
        conf.view_stderr = is_debug;
        conf.http_enabled = false;
        conf.network = network;

        let electrs = electrsd::ElectrsD::with_conf(&electrs, &node, &conf).unwrap();
        info!("Electrs spawned");

        let mut hashes = node.client.generatetoaddress(100, None, None).unwrap();
        electrs.trigger().unwrap();

        let mut i = 60;
        loop {
            assert!(i > 0, "timeout waiting for updates");
            i -= 1;
            let height = electrs.client.block_headers_subscribe_raw().unwrap().height;
            if height == 101 {
                break;
            } else {
                warn!("height: {}", height);
            }
            thread::sleep(Duration::from_secs(1));
        }
        info!("Electrs synced with node");

        let mut network = NetworkParameters::default();
        network.electrum_url = Some(electrs.electrum_url.clone());
        network.sync_interval = Some(1);
        network.development = true;
        network.spv_enabled = Some(true);
        network.set_asset_registry_url("https://assets.blockstream.info".to_string());
        if is_liquid {
            network.liquid = true;
            network.policy_asset =
                Some("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225".into());
        }

        if let Some(f) = network_conf {
            f(&mut network);
        }

        let state_dir = TempDir::new().unwrap();

        let state_dir_str = format!("{}", state_dir.path().display());
        network.state_dir = state_dir_str;

        info!("creating gdk session");
        let mut session = ElectrumSession::new(network.clone()).unwrap();
        let ntf_len = session.filter_events("network").len();
        session.connect(&serde_json::to_value(network.clone()).unwrap()).unwrap();
        assert_eq!(
            session.filter_events("network").last(),
            Some(&ntf_network(State::Connected, State::Connected))
        );
        assert_eq!(session.filter_events("network").len(), ntf_len + 1);

        let mnemonic_str = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string();
        let credentials = Credentials {
            mnemonic: mnemonic_str.clone(),
            bip39_passphrase: "".to_string(),
        };
        info!("logging in gdk session");
        let login_data = session.login(credentials.clone()).unwrap();
        assert!(session.filter_events("settings").last().is_some());

        assert_eq!(network.name, ""); // network name contributes to wallet hash id
        assert_eq!(
            login_data.wallet_hash_id,
            "540dced6da44434f0fcc02cb6cda7e7a9ae5d961759a698797e1835dddc0cd6b"
        );
        let tx_status = session.tx_status().unwrap();
        assert_eq!(tx_status, 15130871412783076140);
        let mut i = 60;
        let block_status = loop {
            assert!(i > 0, "timeout waiting for updates");
            i -= 1;
            let block_status = session.block_status().unwrap();
            if block_status.0 == 101 {
                break block_status;
            } else {
                thread::sleep(Duration::from_secs(1));
            }
        };
        assert_eq!(block_status.0, 101);
        let hash = hashes.pop().unwrap();
        let prev_hash = hashes.pop().unwrap();
        let expected = json!({"block":{"block_height":101u32,"block_hash":hash,"previous_hash":prev_hash},"event":"block"});
        for i in 0.. {
            assert!(i < 10);
            if session.filter_events("block").last() == Some(&expected) {
                break;
            } else {
                std::thread::sleep(Duration::from_millis(100));
            }
        }

        let network_id = if is_liquid {
            NetworkId::Elements(ElementsNetwork::ElementsRegtest)
        } else {
            NetworkId::Bitcoin(bitcoin::Network::Regtest)
        };

        info!("returning TestSession");

        TestSession {
            tx_status,
            block_status,
            node,
            electrs,
            session,
            credentials,
            state_dir,
            network_id,
            network,
            p2p_port,
        }
    }
}

pub fn convertutxos(utxos: &GetUnspentOutputs) -> CreateTxUtxos {
    serde_json::to_value(utxos).and_then(serde_json::from_value).unwrap()
}

/// Json of network notification
pub fn ntf_network(current: State, desired: State) -> Value {
    serde_json::to_value(&Notification::new_network(current, desired)).unwrap()
}

/// Json of transaction notification
pub fn ntf_transaction(ntf: &TransactionNotification) -> Value {
    serde_json::to_value(&Notification::new_transaction(ntf)).unwrap()
}
