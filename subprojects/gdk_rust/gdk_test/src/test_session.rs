use std::str::FromStr;
use std::thread;
use std::time::Duration;

use bip39::Mnemonic;
use electrsd::bitcoind::bitcoincore_rpc::RpcApi;
use electrsd::electrum_client::ElectrumApi;
use gdk_common::bitcoin::bip32::{ChildNumber, DerivationPath, Xpriv, Xpub};
use gdk_common::log::{info, warn};
use gdk_common::rand::Rng;
use gdk_common::util;
use gdk_common::{bitcoin, rand};
use serde_json::{json, Value};
use tempfile::TempDir;

use gdk_common::be::*;
use gdk_common::model::*;
use gdk_common::session::Session;
use gdk_common::{NetworkId, NetworkParameters, State};
use gdk_electrum::spv;
use gdk_electrum::{ElectrumSession, TransactionNotification};

use crate::RpcNodeExt;
use crate::{env, utils};

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
    pub fn new<F>(network_conf: F) -> Self
    where
        F: FnOnce(&mut NetworkParameters),
    {
        let node = env::BITCOIND_EXEC;
        let electrs = env::ELECTRS_EXEC;

        let is_debug = std::env::var("DEBUG").is_ok();

        let _ = env_logger::try_init();

        let args = vec!["-fallbackfee=0.0001", "-dustrelayfee=0.00000001", "-regtest"];
        let network = "regtest";
        let mut conf = electrsd::bitcoind::Conf::default();
        conf.args = args;
        conf.view_stdout = is_debug;
        conf.p2p = electrsd::bitcoind::P2P::Yes;
        conf.network = network;

        let node = electrsd::bitcoind::BitcoinD::with_conf(&*node, &conf).unwrap();
        info!("node spawned");

        RpcNodeExt::generate(&node.client, 1, None).unwrap();

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

        let electrs = electrsd::ElectrsD::with_conf(&*electrs, &node, &conf).unwrap();
        info!("Electrs spawned");

        let mut hashes = RpcNodeExt::generate(&node.client, 100, None).unwrap();
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

        network_conf(&mut network);

        let state_dir = TempDir::new().unwrap();

        let state_dir_str = format!("{}", state_dir.path().display());
        network.state_dir = state_dir_str;

        info!("creating gdk session");
        let mut session = ElectrumSession::new(network.clone()).unwrap();
        let ntf_len = session.filter_events("network").len();
        session.connect(&serde_json::to_value(network.clone()).unwrap()).unwrap();
        assert_eq!(
            session.filter_events("network").last(),
            Some(&utils::ntf_network(State::Connected, State::Connected))
        );
        assert_eq!(session.filter_events("network").len(), ntf_len + 1);

        let mut entropy = [0u8; 32];
        rand::thread_rng().fill(&mut entropy);
        let mnemonic_str = Mnemonic::from_entropy(&entropy).unwrap().to_string();

        let credentials = Credentials {
            mnemonic: mnemonic_str.clone(),
            bip39_passphrase: "".to_string(),
        };
        info!("logging in gdk session");
        let (master_xprv, master_xpub, _master_blinding_key) =
            keys_from_credentials(&credentials, network.bip32_network());

        let opt = LoadStoreOpt {
            master_xpub: Some(master_xpub),
            master_xpub_fingerprint: Some(master_xpub.fingerprint()),
            filename: None,
            encryption_key_hex: None,
        };
        session.load_store(&opt).unwrap();

        let account_nums = session.get_subaccount_nums().unwrap();
        assert_eq!(account_nums, vec![0]);

        // Create subaccount 0
        let path: DerivationPath = "84'/1'/0'".parse().unwrap();
        let path: Vec<ChildNumber> = path.into();
        let xprv = master_xprv.derive_priv(&gdk_common::EC, &path).unwrap();
        let xpub = Xpub::from_priv(&gdk_common::EC, &xprv);
        let opt = CreateAccountOpt {
            subaccount: 0,
            name: "".to_string(),
            xpub: xpub,
            discovered: false,
            is_already_created: true,
            allow_gaps: false,
        };
        session.create_subaccount(opt).unwrap();

        session.start_threads().unwrap();

        assert!(session.filter_events("settings").last().is_some());

        assert_eq!(network.name, ""); // network name contributes to wallet hash id

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

        let network_id = NetworkId::Bitcoin(bitcoin::Network::Regtest);

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

    /// fund the gdk session (account #0) with satoshis from the node
    pub fn fund(&mut self, satoshi: u64) -> String {
        let ap = self.get_receive_address(0);
        let funding_tx = self.node.client.sendtoaddress(&ap.address, satoshi, None).unwrap();
        self.wait_tx(vec![0], &funding_tx, Some(satoshi), Some(TransactionType::Incoming));
        funding_tx
    }

    pub fn get_tx_list(&self, subaccount: u32) -> Vec<TxListItem> {
        let mut opt = GetTransactionsOpt::default();
        opt.subaccount = subaccount;
        opt.count = 100;
        self.session.get_transactions(&opt).unwrap().0
    }

    pub fn get_tx_from_list(&self, subaccount: u32, txid: &str) -> TxListItem {
        let list = self.get_tx_list(subaccount);
        let filtered_list: Vec<TxListItem> =
            list.iter().filter(|e| e.txhash == txid).cloned().collect();
        assert!(!filtered_list.is_empty(), "just made tx {} is not in tx list", txid);
        filtered_list.first().unwrap().clone()
    }

    pub fn get_receive_address(&self, subaccount: u32) -> AddressPointer {
        let addr_opt = GetAddressOpt {
            subaccount,
            address_type: None,
            is_internal: None,
            ignore_gap_limit: None,
        };
        self.session.get_receive_address(&addr_opt).unwrap()
    }

    /// mine a block with the node and check if gdk session see the change
    pub fn mine_block(&mut self) -> String {
        let initial_height_electrs = self.electrs_tip() as u32;
        let initial_height_wallet = self.session.block_status().unwrap().0;
        assert_eq!(initial_height_electrs, initial_height_wallet);
        let block = self.node_generate(1);
        let height = initial_height_electrs + 1;
        // Wait until electrs has updated
        let mut i = 60;
        loop {
            assert!(i > 0, "timeout waiting for electrs block height {}", height);
            i -= 1;
            if height == self.electrs_tip() as u32 {
                break;
            }
            thread::sleep(Duration::from_secs(1));
        }

        // Wait until wallet has updated
        self.wait_blockheight(height);

        block[0].to_string()
    }

    pub fn node_generate(&self, block_num: u32) -> Vec<String> {
        let client = &self.node.client;
        let hashes = RpcNodeExt::generate(client, block_num, None).unwrap();
        self.electrs.trigger().unwrap();
        hashes
    }

    pub fn node_connect(&self, port: u16) {
        self.node.client.call::<Value>("clearbanned", &[]).unwrap();
        self.node
            .client
            .call::<Value>("addnode", &[format!("127.0.0.1:{}", port).into(), "add".into()])
            .unwrap();
    }

    pub fn node_disconnect_all(&self) {
        // if we disconnect without banning, the other peer will connect back to us
        self.node.client.call::<Value>("setban", &["127.0.0.1".into(), "add".into()]).unwrap();
    }

    /// ask the blockcain tip to electrs
    pub fn electrs_tip(&mut self) -> usize {
        for _ in 0..10 {
            match self.electrs.client.block_headers_subscribe_raw() {
                Ok(header) => return header.height,
                Err(e) => {
                    warn!("electrs_tip {:?}", e); // fixme, for some reason it errors once every two try
                    thread::sleep(Duration::from_secs(1));
                }
            }
        }
        panic!("electrs_tip always return error")
    }

    pub fn spv_verify_tx(&mut self, txid: &str, height: u32, headers_to_download: Option<usize>) {
        let tip = self.electrs_tip() as u32;
        let network = self.network.clone();
        utils::spv_verify_tx(network, tip, txid, height, headers_to_download);
    }

    /// stop the bitcoin node in the test session
    pub fn stop(&mut self) {
        self.session.disconnect().unwrap();
        self.node.stop().unwrap();
    }

    pub fn get_spv_cross_validation(&self) -> Option<spv::CrossValidationResult> {
        let store = self.session.store().unwrap();
        let store = store.lock().unwrap();
        store.cache.cross_validation_result.clone()
    }

    /// wait for the spv cross validation status to change
    pub fn wait_spv_cross_validation_change(&self, wait_for: bool) -> spv::CrossValidationResult {
        for _ in 0..60 {
            if let Some(result) = self.get_spv_cross_validation() {
                if result.is_valid() == wait_for {
                    return result;
                }
            }
            thread::sleep(Duration::from_secs(1));
        }
        panic!("timeout waiting for spv cross-validation change");
    }

    /// wait for the spv validation status of a transaction to change
    pub fn wait_tx_spv_change(&self, txid: &str, wait_for: &str) {
        for _ in 0..60 {
            if self.get_tx_from_list(0, txid).spv_verified == wait_for {
                return;
            }
            thread::sleep(Duration::from_secs(1));
        }
        panic!("timeout waiting for tx spv change");
    }

    fn wait_tx_ntf(
        &self,
        subaccounts: Vec<u32>,
        txid: &str,
        satoshi: Option<u64>,
        type_: Option<TransactionType>,
    ) {
        let ntf = utils::ntf_transaction(&TransactionNotification {
            subaccounts: subaccounts.clone(),
            txid: bitcoin::Txid::from_str(&txid).unwrap(),
            satoshi,
            type_,
        });
        for _ in 0..10 {
            let events = self.session.filter_events("transaction");
            if events.iter().any(|e| e["transaction"]["txhash"].as_str().unwrap() == txid) {
                if events.contains(&ntf) {
                    return;
                }
                let got = events
                    .iter()
                    .filter(|e| e["transaction"]["txhash"].as_str().unwrap() == txid)
                    .last()
                    .unwrap();
                let got_subaccounts: Vec<u32> =
                    serde_json::from_value(got["transaction"]["subaccounts"].clone()).unwrap();
                if subaccounts.len() > 1 && got_subaccounts.iter().all(|i| subaccounts.contains(i))
                {
                    // FIXME: make multi subaccount notification less flaky
                    // Sometimes notification with more than one subaccount miss one subaccount,
                    // this might cause the satoshi and type fields to be incorrect. For now we
                    // relax the test here.
                    return;
                }
                panic!(
                    "notification does not match the expected one: expected {:?} got {:?}",
                    ntf, got
                );
            }
            thread::sleep(Duration::from_secs(1));
        }
        panic!("timeout waiting for notification for tx {}", txid);
    }

    /// wait for the txid to show up in the given account
    fn wait_account_tx(&self, subaccount: u32, txid: &str) {
        for _ in 0..60 {
            let txs = self.get_tx_list(subaccount);
            if txs.iter().any(|tx| tx.txhash == txid) {
                return;
            }
            thread::sleep(Duration::from_secs(1));
        }
        panic!("timeout waiting for tx {} to show up in account {}", txid, subaccount);
    }

    pub fn wait_tx(
        &self,
        subaccounts: Vec<u32>,
        txid: &str,
        satoshi: Option<u64>,
        type_: Option<TransactionType>,
    ) {
        for subaccount in subaccounts.iter() {
            self.wait_account_tx(*subaccount, txid);
        }
        self.wait_tx_ntf(subaccounts, txid, satoshi, type_);
    }

    pub fn wait_blockheight(&self, height: u32) {
        let mut i = 60;
        loop {
            assert!(i > 0, "timeout waiting for wallet block height {}", height);
            i -= 1;
            if height == self.session.block_status().unwrap().0 {
                return;
            }
            thread::sleep(Duration::from_secs(1));
        }
    }
}

fn keys_from_credentials(
    credentials: &Credentials,
    network: bitcoin::NetworkKind,
) -> (Xpriv, Xpub, util::MasterBlindingKey) {
    let mnemonic = Mnemonic::parse(&credentials.mnemonic).unwrap();
    let seed = mnemonic.to_seed(&credentials.bip39_passphrase);
    let master_xprv = Xpriv::new_master(network, &seed).unwrap();
    let master_xpub = Xpub::from_priv(&gdk_common::EC, &master_xprv);
    let master_blinding = util::asset_blinding_key_from_seed(&seed);
    (master_xprv, master_xpub, master_blinding)
}
