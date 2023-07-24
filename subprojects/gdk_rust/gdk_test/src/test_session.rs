use std::str::FromStr;
use std::thread;
use std::time::Duration;

use electrsd::bitcoind::bitcoincore_rpc::RpcApi;
use electrsd::electrum_client::ElectrumApi;
use gdk_common::bitcoin::hashes::hex::FromHex;
use gdk_common::bitcoin::Amount;
use gdk_common::log::{info, warn};
use gdk_common::rand::Rng;
use gdk_common::wally::bip39_mnemonic_from_entropy;
use gdk_common::{bitcoin, elements, rand};
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

    pub fn network_parameters(&self) -> &NetworkParameters {
        &self.network
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

    pub fn btc_key(&self) -> String {
        match self.network.id() {
            NetworkId::Elements(_) => {
                "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225".to_string()
            }
            NetworkId::Bitcoin(_) => "btc".to_string(),
        }
    }

    /// send a tx from the gdk session to the specified address
    pub fn send_tx(
        &mut self,
        address: &str,
        satoshi: u64,
        asset: Option<String>,
        memo: Option<String>,
        unspent_outputs: Option<GetUnspentOutputs>,
        confidential_utxos_only: Option<bool>,
        utxo_strategy: Option<UtxoStrategy>,
    ) -> String {
        let init_sat = self.balance_gdk(asset.clone());
        let init_node_balance = self.balance_node(asset.clone());
        let mut create_opt = CreateTransaction::default();
        let fee_rate = match self.network.id() {
            NetworkId::Elements(_) => 100,
            NetworkId::Bitcoin(_) => 1000,
        };
        create_opt.fee_rate = Some(fee_rate);
        create_opt.addressees.push(AddressAmount {
            address: address.to_string(),
            satoshi,
            asset_id: asset.clone().or(self.asset_id()),
        });
        create_opt.memo = memo;
        create_opt.utxos = utils::convertutxos(&unspent_outputs.unwrap_or_else(|| self.utxos(0)));
        create_opt.confidential_utxos_only = confidential_utxos_only.unwrap_or(false);
        if let Some(strategy) = utxo_strategy {
            create_opt.utxo_strategy = strategy;
        }
        let tx = self.session.create_transaction(&mut create_opt).unwrap();
        match self.network.id() {
            NetworkId::Elements(_) => assert!(!tx.rbf_optin),
            NetworkId::Bitcoin(_) => assert!(tx.rbf_optin),
        };
        let num_utxos: usize = create_opt.utxos.iter().map(|(_, au)| au.len()).sum();
        let num_used_utxos = tx.used_utxos.len();
        match create_opt.utxo_strategy {
            UtxoStrategy::Manual => assert_eq!(num_used_utxos, num_utxos),
            UtxoStrategy::Default => assert!(num_used_utxos > 0 && num_used_utxos <= num_utxos),
        }
        let signed_tx = self.session.sign_transaction(&tx).unwrap();
        self.check_fee_rate(fee_rate, &signed_tx, MAX_FEE_PERCENT_DIFF);
        let txid = self.session.broadcast_transaction(&signed_tx.hex).unwrap();
        self.wait_tx(
            vec![create_opt.subaccount],
            &txid,
            Some(satoshi + signed_tx.fee),
            Some(TransactionType::Outgoing),
        );

        self.tx_checks(&signed_tx.hex);

        let fee = if asset.is_none() || asset == self.network.policy_asset {
            tx.fee
        } else {
            0
        };
        assert_eq!(
            self.balance_node(asset.clone()),
            init_node_balance + satoshi,
            "node balance does not match"
        );

        let expected = init_sat - satoshi - fee;
        for _ in 0..5 {
            if expected != self.balance_gdk(asset.clone()) {
                // FIXME I should not wait again, but apparently after reconnect it's needed
                thread::sleep(Duration::from_secs(1));
            }
        }
        assert_eq!(self.balance_gdk(asset.clone()), expected, "gdk balance does not match");

        assert!(
            !tx.create_transaction.unwrap().send_all,
            "send_all in tx is true but should be false"
        );
        assert!(
            !signed_tx.create_transaction.unwrap().send_all,
            "send_all in signed_tx is true but should be false"
        );

        txid
    }

    pub fn reconnect(&mut self) {
        let ntf_len = self.session.filter_events("network").len();
        self.session.disconnect().unwrap();

        assert_eq!(
            self.session.filter_events("network").last(),
            Some(&utils::ntf_network(State::Disconnected, State::Disconnected))
        );
        assert_eq!(self.session.filter_events("network").len(), ntf_len + 1);

        self.session.connect(&Value::Null).unwrap();

        assert_eq!(
            self.session.filter_events("network").last(),
            Some(&utils::ntf_network(State::Connected, State::Connected))
        );
        assert_eq!(self.session.filter_events("network").len(), ntf_len + 2);

        let address = self.node.client.getnewaddress(None, None).unwrap();
        let _txid = self.send_tx(&address, 1000, None, None, None, None, None);
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

    /// send a tx, check it spend utxo with the same script_pubkey together
    /// requires zero balance in session, the node will send two amounts to the same address
    pub fn send_tx_same_script(&mut self) {
        // TODO check same script for different assets
        let init_sat = self.balance_gdk(None);
        assert_eq!(init_sat, 0);

        let utxo_satoshi = 100_000;
        let ap = self.get_receive_address(0);
        let txid = self.node.client.sendtoaddress(&ap.address, utxo_satoshi, None).unwrap();
        self.wait_tx(vec![0], &txid, Some(utxo_satoshi), Some(TransactionType::Incoming));
        let txid = self.node.client.sendtoaddress(&ap.address, utxo_satoshi, None).unwrap();
        self.wait_tx(vec![0], &txid, Some(utxo_satoshi), Some(TransactionType::Incoming));
        let satoshi = 50_000; // one utxo would be enough
        let mut create_opt = CreateTransaction::default();
        let fee_rate = 1000;
        let address = self.node.client.getnewaddress(None, None).unwrap();
        create_opt.fee_rate = Some(fee_rate);
        create_opt.addressees.push(AddressAmount {
            address: address.to_string(),
            satoshi,
            asset_id: self.asset_id(),
        });
        create_opt.utxos = utils::convertutxos(&self.utxos(create_opt.subaccount));
        let tx = self.session.create_transaction(&mut create_opt).unwrap();
        let signed_tx = self.session.sign_transaction(&tx).unwrap();
        self.check_fee_rate(fee_rate, &signed_tx, MAX_FEE_PERCENT_DIFF);
        let txid = self.session.broadcast_transaction(&signed_tx.hex).unwrap();
        self.wait_tx(
            vec![create_opt.subaccount],
            &txid,
            Some(satoshi + signed_tx.fee),
            Some(TransactionType::Outgoing),
        );
        self.tx_checks(&signed_tx.hex);

        let transaction = BETransaction::from_hex(&signed_tx.hex, self.network_id).unwrap();
        assert_eq!(2, transaction.input_len());
    }

    pub fn create_opt(
        &self,
        address: &str,
        satoshi: u64,
        asset_id: Option<String>,
        fee_rate: Option<u64>,
        subaccount: u32,
        utxos: GetUnspentOutputs,
    ) -> CreateTransaction {
        let mut create_opt = CreateTransaction::default();
        create_opt.subaccount = subaccount;
        create_opt.fee_rate = fee_rate;
        create_opt.utxos = utils::convertutxos(&utxos);
        create_opt.addressees.push(AddressAmount {
            address: address.to_string(),
            satoshi,
            asset_id,
        });
        create_opt
    }

    /// performs checks on transactions, like checking for address reuse in outputs and on liquid confidential commitments inequality
    pub fn tx_checks(&self, hex: &str) {
        match self.network_id {
            NetworkId::Elements(_) => {
                let tx: elements::Transaction =
                    elements::encode::deserialize(&Vec::<u8>::from_hex(hex).unwrap()).unwrap();
                let output_nofee: Vec<&elements::TxOut> =
                    tx.output.iter().filter(|o| !o.is_fee()).collect();
                for current in output_nofee.iter() {
                    assert_eq!(
                        1,
                        output_nofee
                            .iter()
                            .filter(|o| o.script_pubkey == current.script_pubkey)
                            .count(),
                        "address reuse"
                    ); // for example using the same change address for lbtc and asset change
                    assert_eq!(
                        1,
                        output_nofee.iter().filter(|o| o.asset == current.asset).count(),
                        "asset commitment equal"
                    );
                    assert_eq!(
                        1,
                        output_nofee.iter().filter(|o| o.value == current.value).count(),
                        "value commitment equal"
                    );
                    assert_eq!(
                        1,
                        output_nofee.iter().filter(|o| o.nonce == current.nonce).count(),
                        "nonce commitment equal"
                    );
                }
                assert!(tx.output.last().unwrap().is_fee(), "last output is not a fee");
            }
            NetworkId::Bitcoin(_) => {
                let tx: bitcoin::Transaction =
                    bitcoin::consensus::encode::deserialize(&Vec::<u8>::from_hex(hex).unwrap())
                        .unwrap();
                for current in tx.output.iter() {
                    assert_eq!(
                        1,
                        tx.output
                            .iter()
                            .filter(|o| o.script_pubkey == current.script_pubkey)
                            .count(),
                        "address reuse"
                    ); // for example using the same change address for lbtc and asset change
                }
            }
        }
    }

    /// test get_subaccount
    pub fn get_subaccount(&mut self) {
        assert!(self.session.get_subaccount(0).is_ok());
        assert!(self.session.get_subaccount(1).is_err());
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

    pub fn node_getnewaddress(&self, kind: Option<&str>) -> String {
        self.node.client.getnewaddress(None, kind).unwrap()
    }

    pub fn node_sendtoaddress(&self, address: &str, satoshi: u64, asset: Option<&str>) -> String {
        self.node.client.sendtoaddress(address, satoshi, asset).unwrap()
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

    pub fn check_fee_rate(&self, req_rate: u64, tx_meta: &TransactionMeta, max_perc_diff: f64) {
        let transaction = BETransaction::from_hex(&tx_meta.hex, self.network_id).unwrap();
        let real_rate = tx_meta.fee as f64 / (transaction.get_weight() as f64 / 4.0);
        let req_rate = req_rate as f64 / 1000.0;
        assert!(
            ((real_rate - req_rate).abs() / real_rate) < max_perc_diff,
            "real_rate:{} req_rate:{}",
            real_rate,
            req_rate
        ); // percentage difference between fee rate requested vs real fee
        let relay_fee =
            self.node.client.get_network_info().unwrap().relay_fee.to_sat() as f64 / 1000.0;
        assert!(real_rate > relay_fee, "fee rate:{} is under relay_fee:{}", real_rate, relay_fee);
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

    /// balance in satoshi of the node
    fn balance_node(&self, asset: Option<String>) -> u64 {
        let balance: Value = self.node.client.call("getbalance", &[]).unwrap();
        let unconfirmed_balance: Value =
            self.node.client.call("getunconfirmedbalance", &[]).unwrap();
        match self.network_id {
            NetworkId::Bitcoin(_) => {
                let conf_sat = Amount::from_btc(balance.as_f64().unwrap()).unwrap().to_sat();
                let unconf_sat =
                    Amount::from_btc(unconfirmed_balance.as_f64().unwrap()).unwrap().to_sat();
                conf_sat + unconf_sat
            }
            NetworkId::Elements(_) => {
                let asset_or_policy = asset.or(Some("bitcoin".to_string())).unwrap();
                let conf_sat = match balance.get(&asset_or_policy) {
                    Some(Value::Number(s)) => {
                        Amount::from_btc(s.as_f64().unwrap()).unwrap().to_sat()
                    }
                    _ => 0,
                };
                let unconf_sat = match unconfirmed_balance.get(&asset_or_policy) {
                    Some(Value::Number(s)) => {
                        Amount::from_btc(s.as_f64().unwrap()).unwrap().to_sat()
                    }
                    _ => 0,
                };
                conf_sat + unconf_sat
            }
        }
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

    pub fn utxos(&self, subaccount: u32) -> GetUnspentOutputs {
        let utxo_opt = GetUnspentOpt {
            subaccount,
            num_confs: None,
            confidential_utxos_only: None,
            all_coins: None,
        };
        self.session.get_unspent_outputs(&utxo_opt).unwrap()
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
