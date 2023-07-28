use std::str::FromStr;
use std::thread;
use std::time::Duration;

use electrsd::bitcoind::bitcoincore_rpc::RpcApi;
use electrsd::electrum_client::ElectrumApi;
use gdk_common::log::{info, warn};
use gdk_common::rand::Rng;
use gdk_common::wally::bip39_mnemonic_from_entropy;
use gdk_common::{bitcoin, rand};
use serde_json::{json, Value};
use tempfile::TempDir;

use gdk_common::be::*;
use gdk_common::model::*;
use gdk_common::session::Session;
use gdk_common::{ElementsNetwork, NetworkId, NetworkParameters, State};
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
    pub fn new<F>(is_liquid: bool, network_conf: F) -> Self
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

        let node = electrsd::bitcoind::BitcoinD::with_conf(&*node, &conf).unwrap();
        info!("node spawned");

        RpcNodeExt::generate(&node.client, 1, None).unwrap();

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
        if is_liquid {
            network.liquid = true;
            network.policy_asset =
                Some("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225".into());
        }

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
        let mnemonic_str = bip39_mnemonic_from_entropy(&entropy);

        let credentials = Credentials {
            mnemonic: mnemonic_str.clone(),
            bip39_passphrase: "".to_string(),
        };
        info!("logging in gdk session");
        let _login_data = session.login(credentials.clone()).unwrap();
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

    /// fund the gdk session (account #0) with satoshis from the node, if on liquid issue `assets_to_issue` assets
    pub fn fund(&mut self, satoshi: u64, assets_to_issue: Option<u8>) -> Vec<String> {
        let initial_satoshis = self.balance_gdk(None);
        let ap = self.get_receive_address(0);
        let funding_tx = self.node.client.sendtoaddress(&ap.address, satoshi, None).unwrap();
        self.wait_tx(vec![0], &funding_tx, Some(satoshi), Some(TransactionType::Incoming));
        let mut assets_issued = vec![];

        for _ in 0..assets_to_issue.unwrap_or(0) {
            let asset = self.node.client.issueasset(satoshi).unwrap();
            let txid = self.node.client.sendtoaddress(&ap.address, satoshi, Some(&*asset)).unwrap();
            self.wait_tx(vec![0], &txid, None, None);
            assets_issued.push(asset);
        }

        // node is allowed to make tx below dust with dustrelayfee, but gdk session should not see
        // this as spendable, thus the balance should not change
        let satoshi = if satoshi < DUST_VALUE {
            0
        } else {
            satoshi
        };

        assert_eq!(self.balance_gdk(None), initial_satoshis + satoshi);
        assets_issued
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

    pub fn asset_id(&self) -> Option<String> {
        match self.network_id {
            NetworkId::Bitcoin(_) => None,
            NetworkId::Elements(_) => self.network.policy_asset.clone(),
        }
    }

    /// balance in satoshi (or liquid satoshi) of the gdk session for account 0
    fn balance_gdk(&self, asset: Option<String>) -> u64 {
        self.balance_account(0, asset, None)
    }

    pub fn balance_account(
        &self,
        account_num: u32,
        asset: Option<String>,
        confidential_utxos_only: Option<bool>,
    ) -> u64 {
        let opt = GetBalanceOpt {
            subaccount: account_num,
            num_confs: 0,
            confidential_utxos_only,
        };
        let balance = self.session.get_balance(&opt).unwrap();
        match self.network_id {
            NetworkId::Elements(_) => {
                let asset =
                    asset.unwrap_or(self.network.policy_asset.as_ref().unwrap().to_string());
                *balance.get(&asset).unwrap_or(&0i64) as u64
            }
            NetworkId::Bitcoin(_) => *balance.get("btc").unwrap() as u64,
        }
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
        let store = store.read().unwrap();
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
        let is_liquid = self.network.liquid;
        let (satoshi, type_) = if is_liquid {
            (None, None)
        } else {
            (satoshi, type_)
        };
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
