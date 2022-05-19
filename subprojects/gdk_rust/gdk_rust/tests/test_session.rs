use bitcoin::hashes::hex::FromHex;
use bitcoin::network::constants::Network as Bip32Network;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{self, Amount};
use electrsd::bitcoind::bitcoincore_rpc::{Client, RpcApi};
use electrum_client::ElectrumApi;
use elements;
use gdk_common::be::{BEAddress, BEBlockHash, BETransaction, BETxid, DUST_VALUE};
use gdk_common::mnemonic::Mnemonic;
use gdk_common::scripts::ScriptType;
use gdk_common::wally::{asset_blinding_key_from_seed, MasterBlindingKey};
use gdk_common::NetworkParameters;
use gdk_common::{model::*, wally};
use gdk_common::{ElementsNetwork, NetworkId};
use gdk_electrum::error::Error;
use gdk_electrum::{determine_electrum_url, spv, ElectrumSession, State};
use gdk_electrum::{headers, Notification, TransactionNotification};
use log::{info, warn, Metadata, Record};
use serde_json::{json, Value};
use std::collections::HashSet;
use std::iter::FromIterator;
use std::str::FromStr;
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;

use bitcoin::blockdata::script::Builder as ScriptBuilder;
use bitcoin::blockdata::transaction::SigHashType;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Message;
use bitcoin::util::address::Address;
use bitcoin::util::bip143::SigHashCache;

const MAX_FEE_PERCENT_DIFF: f64 = 0.05;

pub fn convertutxos(utxos: &GetUnspentOutputs) -> CreateTxUtxos {
    let s = serde_json::to_string(utxos).unwrap();
    let utxos: CreateTxUtxos = serde_json::from_str(&s).unwrap();
    utxos
}

#[allow(unused)]
pub struct TestSession {
    pub node: electrsd::bitcoind::BitcoinD,
    pub electrs: electrsd::ElectrsD,
    pub session: ElectrumSession,
    pub mnemonic: Mnemonic,
    tx_status: u64,
    block_status: (u32, BEBlockHash),
    state_dir: TempDir,
    network_id: NetworkId,
    pub network: NetworkParameters,
    pub p2p_port: u16,
}

//TODO duplicated why I cannot import?
pub struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
            println!(
                "{:02}.{:03} {} - {}",
                ts.as_secs() % 60,
                ts.subsec_millis(),
                record.level(),
                record.args()
            );
        }
    }

    fn flush(&self) {}
}

pub fn setup(
    is_liquid: bool,
    is_debug: bool,
    electrs_exec: &str,
    node_exec: &str,
    network_conf: impl FnOnce(&mut NetworkParameters),
) -> TestSession {
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

    let node = electrsd::bitcoind::BitcoinD::with_conf(&node_exec, &conf).unwrap();
    info!("node spawned");

    node_generate(&node.client, 1, None);
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

    let electrs = electrsd::ElectrsD::with_conf(&electrs_exec, &node, &conf).unwrap();
    info!("Electrs spawned");

    let mut hashes = node_generate(&node.client, 100, None);
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
    network.ct_bits = Some(52);
    network.ct_exponent = Some(0);
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

    let proxy = Some("");
    let url = determine_electrum_url(&network).unwrap();

    info!("creating gdk session");
    let mut session = ElectrumSession::create_session(network.clone(), proxy, url);
    let ntf_len = session.filter_events("network").len();
    session.connect(&serde_json::to_value(network.clone()).unwrap()).unwrap();
    assert_eq!(
        session.filter_events("network").last(),
        Some(&ntf_network(State::Connected, State::Connected))
    );
    assert_eq!(session.filter_events("network").len(), ntf_len + 1);

    let mnemonic: Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string().into();
    info!("logging in gdk session");
    let login_data = session.login(&mnemonic, None).unwrap();
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
        mnemonic,
        state_dir,
        network_id,
        network,
        p2p_port,
    }
}

// NOTE: Methods that don't accept an explicit account number operate on account #0
impl TestSession {
    pub fn network_parameters(&self) -> &NetworkParameters {
        &self.network
    }

    /// test fees are 25 elements and greater than relay_fee
    pub fn fees(&mut self) {
        let fees = self.session.get_fee_estimates().unwrap();
        let relay_fee = self.node.client.get_network_info().unwrap().relay_fee.as_sat();
        assert_eq!(fees.len(), 25);
        assert!(fees.iter().all(|f| f.0 >= relay_fee));
        assert!(fees.windows(2).all(|s| s[0].0 <= s[1].0)); // monotonic
    }

    /// test a change in the settings is saved
    pub fn settings(&mut self) {
        let mut settings = self.session.get_settings().unwrap();
        settings.altimeout += 1;
        self.session.change_settings(&serde_json::to_value(settings.clone()).unwrap()).unwrap();
        let new_settings = self.session.get_settings().unwrap();
        assert_eq!(settings, new_settings);

        settings.unit = "sats".to_string();
        let partial =
            serde_json::from_str(r#"{"unit": "sats", "another_key": "another_value"}"#).unwrap();
        self.session.change_settings(&partial).unwrap();
        let new_settings = self.session.get_settings().unwrap();
        assert_eq!(settings, new_settings);
    }

    pub fn fund_asset(&mut self, satoshi: u64, address: &str) -> (String, String) {
        let asset = self.node_issueasset(satoshi);
        let txid = self.node_sendtoaddress(address, satoshi, Some(asset.clone()));
        // TODO: use AssetId and Txid
        (asset, txid)
    }

    /// fund the gdk session (account #0) with satoshis from the node, if on liquid issue `assets_to_issue` assets
    pub fn fund(&mut self, satoshi: u64, assets_to_issue: Option<u8>) -> Vec<String> {
        let initial_satoshis = self.balance_gdk(None);
        let ap = self.get_receive_address(0);
        let funding_tx = self.node_sendtoaddress(&ap.address, satoshi, None);
        self.wait_tx(vec![0], &funding_tx, Some(satoshi), Some(TransactionType::Incoming));
        self.list_tx_contains(&funding_tx, &vec![], false);
        let mut assets_issued = vec![];

        for _ in 0..assets_to_issue.unwrap_or(0) {
            let asset = self.node_issueasset(satoshi);
            let txid = self.node_sendtoaddress(&ap.address, satoshi, Some(asset.clone()));
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

    /// send all of the balance of the  tx from the gdk session to the specified address
    pub fn send_all(&mut self, address: &str, asset_id: Option<String>) {
        self.send_all_from_account(0, address, asset_id, None, None);
    }
    pub fn send_all_from_account(
        &mut self,
        subaccount: u32,
        address: &str,
        asset_id: Option<String>,
        unspent_outputs: Option<GetUnspentOutputs>,
        utxo_strategy: Option<UtxoStrategy>,
    ) -> (String, u64, u64) {
        let init_sat = self.balance_account(subaccount, asset_id.clone(), None);
        let mut create_opt = CreateTransaction::default();
        create_opt.subaccount = subaccount;
        let utxos = unspent_outputs.unwrap_or(self.utxos(create_opt.subaccount));
        create_opt.utxos = convertutxos(&utxos);
        if let Some(strategy) = utxo_strategy {
            create_opt.utxo_strategy = strategy;
        }
        let fee_rate = if asset_id.is_none() {
            1000
        } else {
            100
        };
        create_opt.fee_rate = Some(fee_rate);
        create_opt.addressees.push(AddressAmount {
            address: address.to_string(),
            satoshi: 0,
            asset_id: asset_id.clone().or(self.asset_id()),
        });
        create_opt.send_all = true;
        let tx = self.session.create_transaction(&mut create_opt).unwrap();
        let signed_tx = self.session.sign_transaction(&tx).unwrap();

        self.check_fee_rate(fee_rate, &signed_tx, MAX_FEE_PERCENT_DIFF);
        let txid = self.session.broadcast_transaction(&signed_tx.hex).unwrap();
        // TODO: use wait_tx, but need to passed the subaccounts involved in the transaction
        self.wait_account_tx(subaccount, &txid);

        let key = asset_id.clone().unwrap_or(self.btc_key());
        let sent_sat: u64 = utxos.0.get(&key).unwrap().iter().map(|u| u.satoshi).sum();
        let end_sat = init_sat - sent_sat;
        assert_eq!(self.balance_account(subaccount, asset_id, None), end_sat);

        assert!(tx.create_transaction.unwrap().send_all);
        assert!(signed_tx.create_transaction.unwrap().send_all);
        (txid, init_sat, signed_tx.fee)
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
        create_opt.utxos = convertutxos(&unspent_outputs.unwrap_or_else(|| self.utxos(0)));
        create_opt.confidential_utxos_only = confidential_utxos_only.unwrap_or(false);
        if let Some(strategy) = utxo_strategy {
            create_opt.utxo_strategy = strategy;
        }
        let tx = self.session.create_transaction(&mut create_opt).unwrap();
        assert!(!tx.user_signed, "tx is marked as user_signed");
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
        assert!(signed_tx.user_signed, "tx is not marked as user_signed");
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

        self.list_tx_contains(&txid, &vec![address.to_string()], true);

        txid
    }

    pub fn send_tx_from(
        &mut self,
        subaccount: u32,
        address: &str,
        satoshi: u64,
        asset: Option<String>,
    ) -> (String, u64) {
        let mut create_opt = CreateTransaction::default();
        create_opt.subaccount = subaccount;
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
        create_opt.utxos = convertutxos(&self.utxos(create_opt.subaccount));
        let tx = self.session.create_transaction(&mut create_opt).unwrap();
        let signed_tx = self.session.sign_transaction(&tx).unwrap();
        let txid = self.session.broadcast_transaction(&signed_tx.hex).unwrap();
        // caller is expected to call wait_tx
        (txid, signed_tx.fee)
    }

    pub fn test_set_get_memo(&mut self, txid: &str, old: &str, new: &str) {
        assert_eq!(self.get_tx_from_list(0, txid).memo, old);
        assert!(self.session.set_transaction_memo(txid, &"a".repeat(1025)).is_err());
        assert!(self.session.set_transaction_memo(txid, new).is_ok());
        assert_eq!(self.get_tx_from_list(0, txid).memo, new);
    }

    pub fn is_verified(&mut self, txid: &str, verified: SPVVerifyTxResult) {
        let tx = self.get_tx_from_list(0, txid);
        assert_eq!(tx.spv_verified, verified.to_string());
    }

    pub fn reconnect(&mut self) {
        let ntf_len = self.session.filter_events("network").len();
        self.session.disconnect().unwrap();

        assert_eq!(
            self.session.filter_events("network").last(),
            Some(&ntf_network(State::Disconnected, State::Disconnected))
        );
        assert_eq!(self.session.filter_events("network").len(), ntf_len + 1);

        self.session.connect(&Value::Null).unwrap();

        assert_eq!(
            self.session.filter_events("network").last(),
            Some(&ntf_network(State::Connected, State::Connected))
        );
        assert_eq!(self.session.filter_events("network").len(), ntf_len + 2);

        let address = self.node_getnewaddress(None);
        let txid = self.send_tx(&address, 1000, None, None, None, None, None);
        self.list_tx_contains(&txid, &[address], true);
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

    fn list_tx_contains(&mut self, txid: &str, addressees: &[String], user_signed: bool) {
        let tx = self.get_tx_from_list(0, txid);
        if !addressees.is_empty() {
            let recipients = match self.network_id {
                NetworkId::Bitcoin(_) => addressees.to_vec(),
                NetworkId::Elements(_) => {
                    // We can't check Liquid unconfidential addressees because we can't compute those from only blockchain + mnemonic
                    addressees
                        .iter()
                        .map(|s| {
                            let mut a = elements::Address::from_str(s).unwrap();
                            a.blinding_pubkey = None;
                            a.to_string()
                        })
                        .collect()
                }
            };
            let a: HashSet<String> = HashSet::from_iter(recipients.iter().cloned());
            let b: HashSet<String> = HashSet::from_iter(tx.addressees.iter().cloned());
            assert_eq!(a, b, "tx does not contain recipient addresses");
        }
        assert_eq!(tx.user_signed, user_signed);
    }

    pub fn get_receive_address(&self, subaccount: u32) -> AddressPointer {
        let addr_opt = GetAddressOpt {
            subaccount,
            address_type: None,
            is_internal: None,
        };
        self.session.get_receive_address(&addr_opt).unwrap()
    }

    /// send a tx with multiple recipients with same amount from the gdk session to generated
    /// node's addressees, if `assets` contains values, they are used as asset_id cyclically
    pub fn send_multi(&mut self, recipients: u8, amount: u64, assets: &Vec<String>) {
        let init_sat = self.balance_gdk(None);
        let init_assets_sat = self.balance_gdk_all();
        let mut create_opt = CreateTransaction::default();
        let fee_rate = 1000;
        create_opt.fee_rate = Some(fee_rate);
        let mut addressees = vec![];
        let mut assets_cycle = assets.iter().cycle();
        let mut tags = vec![];
        for _ in 0..recipients {
            let address = self.node_getnewaddress(None);
            let asset_id = if assets.is_empty() {
                self.asset_id()
            } else {
                let current = assets_cycle.next().unwrap().to_string();
                tags.push(current.clone());
                Some(current)
            };

            create_opt.addressees.push(AddressAmount {
                address: address.to_string(),
                satoshi: amount,
                asset_id,
            });
            addressees.push(address);
        }
        create_opt.utxos = convertutxos(&self.utxos(create_opt.subaccount));
        let tx = self.session.create_transaction(&mut create_opt).unwrap();
        let signed_tx = self.session.sign_transaction(&tx).unwrap();
        self.check_fee_rate(fee_rate, &signed_tx, MAX_FEE_PERCENT_DIFF);
        let txid = self.session.broadcast_transaction(&signed_tx.hex).unwrap();
        let tot_sat = signed_tx.fee + amount * recipients as u64;
        self.wait_tx(
            vec![create_opt.subaccount],
            &txid,
            Some(tot_sat),
            Some(TransactionType::Outgoing),
        );
        self.tx_checks(&signed_tx.hex);

        if assets.is_empty() {
            assert_eq!(init_sat - tx.fee - recipients as u64 * amount, self.balance_gdk(None));
        } else {
            assert_eq!(init_sat - tx.fee, self.balance_gdk(None));
            for tag in assets {
                let outputs_for_this_asset = tags.iter().filter(|t| t == &tag).count() as u64;
                assert_eq!(
                    *init_assets_sat.get(tag).unwrap() as u64 - outputs_for_this_asset * amount,
                    self.balance_gdk(Some(tag.to_string()))
                );
            }
        }
        //TODO check node balance
        self.list_tx_contains(&txid, &addressees, true);
    }

    pub fn receive_unconfidential(&mut self) {
        let policy_asset = &self.network.policy_asset.clone().unwrap();
        let init_sat = self.balance_gdk(None);
        let mut utxos_opt = GetUnspentOpt::default();
        let utxos = self.session.get_unspent_outputs(&utxos_opt).unwrap();
        let init_num_utxos = utxos.0.get(policy_asset).unwrap().len();
        let ap = self.get_receive_address(0);
        let unconf_address = to_unconfidential(&ap.address);
        let unconf_sat = 10_000;
        let unconf_txid = self.node_sendtoaddress(&unconf_address, unconf_sat, None);
        self.wait_tx(vec![0], &unconf_txid, Some(unconf_sat), Some(TransactionType::Incoming));
        // confidential balance
        assert_eq!(init_sat, self.balance_account(0, None, Some(true)));
        utxos_opt.confidential_utxos_only = Some(true);
        let utxos = self.session.get_unspent_outputs(&utxos_opt).unwrap();
        assert_eq!(init_num_utxos, utxos.0.get(policy_asset).unwrap().len());
        assert!(utxos.0.get(policy_asset).unwrap().iter().all(|u| u.confidential.unwrap_or(false)));
        // confidential and unconfidential balance (default)
        assert_eq!(init_sat + unconf_sat, self.balance_account(0, None, Some(false)));
        utxos_opt.confidential_utxos_only = Some(false);
        let utxos = self.session.get_unspent_outputs(&utxos_opt).unwrap();
        assert_eq!(init_num_utxos + 1, utxos.0.get(policy_asset).unwrap().len());
        assert!(utxos.0.get(policy_asset).unwrap().iter().any(|u| u.confidential.unwrap_or(false)));
        assert!(utxos
            .0
            .get(policy_asset)
            .unwrap()
            .iter()
            .any(|u| !u.confidential.unwrap_or(false)));

        // Spend only confidential utxos
        let node_address = self.node_getnewaddress(None);
        let mut create_opt = CreateTransaction::default();
        //let fee_rate = match self.network.id() {
        //    NetworkId::Elements(_) => 100,
        //    NetworkId::Bitcoin(_) => 1000,
        //};
        //create_opt.fee_rate = Some(fee_rate);
        create_opt.addressees.push(AddressAmount {
            address: node_address.to_string(),
            satoshi: init_sat, // not enough to pay the fee with confidential utxos only
            asset_id: self.asset_id(),
        });
        create_opt.utxos = convertutxos(&self.utxos(create_opt.subaccount));
        create_opt.confidential_utxos_only = true;
        assert!(matches!(
            self.session.create_transaction(&mut create_opt),
            Err(Error::InsufficientFunds)
        ));

        let balance_node_before = self.balance_node(None);
        let sat = 1_000;
        let txid = self.send_tx(&node_address, sat, None, None, None, Some(true), None);
        self.list_tx_contains(&txid, &[node_address], true);
        assert_eq!(balance_node_before + sat, self.balance_node(None));

        // Spend a unconfidential utxos
        // Note that unlike Elements Core, a transaction with 1 confidential output and 0
        // confidential inputs, will be blinded by the wallet. This is a waste of fees (any
        // observer can deduce asset and amount from the remaining inputs and outputs), however it
        // reduces complexity.
        let node_address = self.node_getnewaddress(None);
        let balance_node_before = self.balance_node(None);
        utxos_opt.confidential_utxos_only = None;
        let mut utxos = self.session.get_unspent_outputs(&utxos_opt).unwrap();
        utxos.0.get_mut(policy_asset).unwrap().retain(|e| e.txhash == unconf_txid);
        assert_eq!(utxos.0.get(policy_asset).unwrap().len(), 1);
        assert!(utxos
            .0
            .get(policy_asset)
            .unwrap()
            .iter()
            .all(|u| !u.confidential.unwrap_or(false)));
        let sat = unconf_sat / 2;
        let txid = self.send_tx(&node_address, sat, None, None, Some(utxos), None, None);
        self.list_tx_contains(&txid, &[node_address], true);
        assert_eq!(balance_node_before + sat, self.balance_node(None));
    }

    /// send a tx, check it spend utxo with the same script_pubkey together
    /// requires zero balance in session, the node will send two amounts to the same address
    pub fn send_tx_same_script(&mut self) {
        // TODO check same script for different assets
        let init_sat = self.balance_gdk(None);
        assert_eq!(init_sat, 0);

        let utxo_satoshi = 100_000;
        let ap = self.get_receive_address(0);
        let txid = self.node_sendtoaddress(&ap.address, utxo_satoshi, None);
        self.wait_tx(vec![0], &txid, Some(utxo_satoshi), Some(TransactionType::Incoming));
        let txid = self.node_sendtoaddress(&ap.address, utxo_satoshi, None);
        self.wait_tx(vec![0], &txid, Some(utxo_satoshi), Some(TransactionType::Incoming));
        let satoshi = 50_000; // one utxo would be enough
        let mut create_opt = CreateTransaction::default();
        let fee_rate = 1000;
        let address = self.node_getnewaddress(None);
        create_opt.fee_rate = Some(fee_rate);
        create_opt.addressees.push(AddressAmount {
            address: address.to_string(),
            satoshi,
            asset_id: self.asset_id(),
        });
        create_opt.utxos = convertutxos(&self.utxos(create_opt.subaccount));
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
        create_opt.utxos = convertutxos(&utxos);
        create_opt.addressees.push(AddressAmount {
            address: address.to_string(),
            satoshi: satoshi,
            asset_id: asset_id,
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
        node_getnewaddress(&self.node.client, kind)
    }

    pub fn node_sendtoaddress(&self, address: &str, satoshi: u64, asset: Option<String>) -> String {
        node_sendtoaddress(&self.node.client, address, satoshi, asset)
    }
    pub fn node_issueasset(&self, satoshi: u64) -> String {
        node_issueasset(&self.node.client, satoshi)
    }
    pub fn node_generate(&self, block_num: u32) -> Vec<String> {
        let hashes = node_generate(&self.node.client, block_num, None);
        self.electrs.trigger().unwrap();
        hashes
    }

    pub fn node_generatetoaddress(&self, block_num: u32, address: String) {
        node_generate(&self.node.client, block_num, Some(address));
        self.electrs.trigger().unwrap();
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
            self.node.client.get_network_info().unwrap().relay_fee.as_sat() as f64 / 1000.0;
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

    fn _addr(&self, address: &str) -> BEAddress {
        match self.network_id {
            NetworkId::Bitcoin(_) => {
                BEAddress::Elements(elements::Address::from_str(address).unwrap())
            }
            NetworkId::Elements(_) => {
                BEAddress::Bitcoin(bitcoin::Address::from_str(address).unwrap())
            }
        }
    }

    /// balance in satoshi of the node
    fn balance_node(&self, asset: Option<String>) -> u64 {
        let balance: Value = self.node.client.call("getbalance", &[]).unwrap();
        let unconfirmed_balance: Value =
            self.node.client.call("getunconfirmedbalance", &[]).unwrap();
        match self.network_id {
            NetworkId::Bitcoin(_) => {
                let conf_sat = Amount::from_btc(balance.as_f64().unwrap()).unwrap().as_sat();
                let unconf_sat =
                    Amount::from_btc(unconfirmed_balance.as_f64().unwrap()).unwrap().as_sat();
                conf_sat + unconf_sat
            }
            NetworkId::Elements(_) => {
                let asset_or_policy = asset.or(Some("bitcoin".to_string())).unwrap();
                let conf_sat = match balance.get(&asset_or_policy) {
                    Some(Value::Number(s)) => {
                        Amount::from_btc(s.as_f64().unwrap()).unwrap().as_sat()
                    }
                    _ => 0,
                };
                let unconf_sat = match unconfirmed_balance.get(&asset_or_policy) {
                    Some(Value::Number(s)) => {
                        Amount::from_btc(s.as_f64().unwrap()).unwrap().as_sat()
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
    fn balance_gdk_all(&self) -> Balances {
        let opt = GetBalanceOpt {
            subaccount: 0,
            num_confs: 0,
            confidential_utxos_only: None,
        };
        self.session.get_balance(&opt).unwrap()
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
        spv_verify_tx(network, tip, txid, height, headers_to_download);
    }

    pub fn utxos(&self, subaccount: u32) -> GetUnspentOutputs {
        let utxo_opt = GetUnspentOpt {
            subaccount: subaccount,
            num_confs: None,
            confidential_utxos_only: None,
            all_coins: None,
        };
        self.session.get_unspent_outputs(&utxo_opt).unwrap()
    }

    /// check `get_unspent_outputs` contains the `expected_amounts` for the given `asset`
    pub fn utxo(&self, asset: &str, mut expected_amounts: Vec<u64>) -> GetUnspentOutputs {
        let outputs = self.utxos(0);
        let amounts = if expected_amounts.len() == 0 {
            vec![]
        } else {
            let option = outputs.0.get(asset);
            assert!(option.is_some());
            expected_amounts.sort();
            let mut amounts: Vec<u64> = option.unwrap().iter().map(|e| e.satoshi).collect();
            amounts.sort();
            amounts
        };
        assert_eq!(expected_amounts, amounts, "amounts in utxo doesn't match in number or amounts");

        outputs
    }

    /// stop the bitcoin node in the test session
    pub fn stop(&mut self) {
        self.session.disconnect().unwrap();
        self.node.stop().unwrap();
    }

    pub fn check_decryption(&mut self, tip: u32, txids: &[&str]) {
        let cache = self.session.export_cache().unwrap();
        assert_eq!(cache.tip_height(), tip);
        let account0 = cache.accounts.get(&0).expect("default account");
        for txid in txids {
            assert!(account0
                .all_txs
                .get(&BETxid::from_hex(txid, self.network.id()).unwrap())
                .is_some())
        }
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
        let ntf = ntf_transaction(&TransactionNotification {
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

    /// wait for the n txs to show up in the given account
    pub fn wait_account_n_txs(&self, subaccount: u32, n: usize) {
        wait_account_n_txs(&self.session, subaccount, n);
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

    pub fn test_signer(&self) -> TestSigner {
        TestSigner::new(
            &self.mnemonic.clone().get_mnemonic_str(),
            self.session.network.bip32_network(),
            self.session.network.liquid,
        )
    }
}
fn node_sendtoaddress(
    client: &Client,
    address: &str,
    satoshi: u64,
    asset: Option<String>,
) -> String {
    let amount = Amount::from_sat(satoshi);
    let btc = amount.to_string_in(bitcoin::util::amount::Denomination::Bitcoin);
    info!("node_sendtoaddress {} {}", address, btc);
    let r = match asset {
        Some(asset) => client
            .call::<Value>(
                "sendtoaddress",
                &[
                    address.into(),
                    btc.into(),
                    "".into(),
                    "".into(),
                    false.into(),
                    false.into(),
                    1.into(),
                    "UNSET".into(),
                    false.into(),
                    asset.into(),
                ],
            )
            .unwrap(),
        None => client.call::<Value>("sendtoaddress", &[address.into(), btc.into()]).unwrap(),
    };
    info!("node_sendtoaddress result {:?}", r);
    r.as_str().unwrap().to_string()
}

fn node_getnewaddress(client: &Client, kind: Option<&str>) -> String {
    let kind = kind.unwrap_or("p2sh-segwit");
    let addr: Value = client.call("getnewaddress", &["label".into(), kind.into()]).unwrap();
    addr.as_str().unwrap().to_string()
}

fn node_generate(client: &Client, block_num: u32, address: Option<String>) -> Vec<String> {
    let address = address.unwrap_or(node_getnewaddress(client, None));
    let r = client.call::<Value>("generatetoaddress", &[block_num.into(), address.into()]).unwrap();
    if block_num < 10 {
        info!("generate result {:?}", r);
    } else {
        info!("generated {} blocks", block_num);
    }
    serde_json::from_value(r).unwrap()
}

fn node_issueasset(client: &Client, satoshi: u64) -> String {
    let amount = Amount::from_sat(satoshi);
    let btc = amount.to_string_in(bitcoin::util::amount::Denomination::Bitcoin);
    let r = client.call::<Value>("issueasset", &[btc.into(), 0.into()]).unwrap();
    info!("node_issueasset result {:?}", r);
    r.get("asset").unwrap().as_str().unwrap().to_string()
}

pub fn to_unconfidential(elements_address: &str) -> String {
    let mut address_unconf = elements::Address::from_str(elements_address).unwrap();
    address_unconf.blinding_pubkey = None;
    address_unconf.to_string()
}

pub fn to_not_unblindable(elements_address: &str) -> String {
    let pk = elements::secp256k1_zkp::PublicKey::from_slice(&[2; 33]).unwrap();
    let mut address = elements::Address::from_str(elements_address).unwrap();
    address.blinding_pubkey = Some(pk);
    address.to_string()
}

/// wait for the n txs to show up in the given account
pub fn wait_account_n_txs(session: &ElectrumSession, subaccount: u32, n: usize) {
    let mut opt = GetTransactionsOpt::default();
    opt.subaccount = subaccount;
    opt.count = n;
    for _ in 0..10 {
        if session.get_transactions(&opt).unwrap().0.len() >= n {
            return;
        }
        thread::sleep(Duration::from_secs(1));
    }
    panic!("timeout waiting for {} txs to show up in account {}", n, subaccount);
}

// Perform BIP44 account discovery as it is performed in the resolver
pub fn discover_subaccounts(session: &mut ElectrumSession, mnemonic: Mnemonic) {
    let signer = TestSigner::new(
        &mnemonic.clone().get_mnemonic_str(),
        session.network.bip32_network(),
        session.network.liquid,
    );

    for script_type in ScriptType::types() {
        loop {
            let opt = GetNextAccountOpt {
                script_type: *script_type,
            };
            let account_num = session.get_next_subaccount(opt).unwrap();
            let opt = GetAccountPathOpt {
                subaccount: account_num,
            };
            let path = session.get_subaccount_root_path(opt).unwrap().path;
            let xpub = signer.account_xpub(&path.into());
            let opt = DiscoverAccountOpt {
                script_type: *script_type,
                xpub,
            };
            if session.discover_subaccount(opt).unwrap() {
                let opt = CreateAccountOpt {
                    subaccount: account_num,
                    xpub: Some(xpub),
                    discovered: true,
                    ..Default::default()
                };
                session.create_subaccount(opt).unwrap();
            } else {
                // Empty subaccount
                break;
            }
        }
    }
}

pub fn spv_verify_tx(
    network: NetworkParameters,
    tip: u32,
    txid: &str,
    height: u32,
    headers_to_download: Option<usize>,
) {
    let id = network.id();
    let common = SPVCommonParams {
        network,
        timeout: None,
        encryption_key: Some("testing".to_string()),
    };
    let param = SPVVerifyTxParams {
        txid: txid.to_string(),
        height,
        params: common.clone(),
    };
    let param_download = SPVDownloadHeadersParams {
        params: common.clone(),
        headers_to_download,
    };

    let mut handle = None;
    if let NetworkId::Bitcoin(_) = id {
        // Liquid doesn't need to download headers chain
        handle = Some(thread::spawn(move || {
            let mut synced = 0;

            while synced < tip {
                if let Ok(result) = headers::download_headers(&param_download) {
                    synced = result.height;
                }
                thread::sleep(Duration::from_millis(100));
            }
        }));
    }

    loop {
        match headers::spv_verify_tx(&param) {
            Ok(SPVVerifyTxResult::InProgress) => {
                thread::sleep(Duration::from_millis(100));
            }
            Ok(SPVVerifyTxResult::Verified) => break,
            Ok(e) => assert!(false, "status {:?}", e),
            Err(e) => assert!(false, "error {:?}", e),
        }
    }

    // second should verify immediately, (and also hit cache)
    assert!(matches!(headers::spv_verify_tx(&param), Ok(SPVVerifyTxResult::Verified)));

    if let Some(handle) = handle {
        handle.join().unwrap();
    }
}

// Simulate login through the auth handler
pub fn auth_handler_login(session: &mut ElectrumSession, mnemonic: Mnemonic) {
    let signer = TestSigner::new(
        &mnemonic.clone().get_mnemonic_str(),
        session.network.bip32_network(),
        session.network.liquid,
    );

    // Connect must be done before login
    session.connect(&serde_json::to_value(session.network.clone()).unwrap()).unwrap();

    // Load the rust persisted cache
    let opt = LoadStoreOpt {
        master_xpub: signer.master_xpub(),
    };
    session.load_store(&opt).unwrap();

    // Set the master blinding key if missing in the cache
    if session.network.liquid {
        if session.get_master_blinding_key().unwrap().master_blinding_key.is_none() {
            // Master blinding key is missing
            let master_blinding_key = signer.master_blinding();
            let opt = SetMasterBlindingKeyOpt {
                master_blinding_key,
            };
            session.set_master_blinding_key(&opt).unwrap();
        }
    }

    // Set the account xpubs if missing in the cache
    for account_num in session.get_subaccount_nums().unwrap() {
        let opt = GetAccountXpubOpt {
            subaccount: account_num,
        };
        if session.get_subaccount_xpub(opt).unwrap().xpub.is_none() {
            // Account xpub is missing
            let opt = GetAccountPathOpt {
                subaccount: account_num,
            };
            let path = session.get_subaccount_root_path(opt).unwrap();
            let xpub = signer.account_xpub(&path.path.into());

            let opt = CreateAccountOpt {
                subaccount: account_num,
                name: "".to_string(),
                xpub: Some(xpub),
                discovered: false,
            };
            session.create_subaccount(opt).unwrap();
        }
    }

    // We got everything from the signer
    session.start_threads().unwrap();
}

/// Json of network notification
pub fn ntf_network(current: State, desired: State) -> Value {
    serde_json::to_value(&Notification::new_network(current, desired)).unwrap()
}

/// Json of network notification
pub fn ntf_transaction(ntf: &TransactionNotification) -> Value {
    serde_json::to_value(&Notification::new_transaction(ntf)).unwrap()
}

/// Struct that holds the secret, so that we can replicate the resolver behavior
pub struct TestSigner {
    pub mnemonic: String,
    pub network: Bip32Network,
    is_liquid: bool,
    secp: Secp256k1<All>,
}

impl TestSigner {
    pub fn new(mnemonic: &str, network: Bip32Network, is_liquid: bool) -> Self {
        TestSigner {
            mnemonic: mnemonic.into(),
            network,
            is_liquid,
            secp: bitcoin::secp256k1::Secp256k1::new(),
        }
    }
    fn seed(&self) -> [u8; 64] {
        wally::bip39_mnemonic_to_seed(&self.mnemonic, "").unwrap()
    }

    fn master_xprv(&self) -> ExtendedPrivKey {
        ExtendedPrivKey::new_master(self.network, &self.seed()).unwrap()
    }

    fn master_xpub(&self) -> ExtendedPubKey {
        ExtendedPubKey::from_private(&self.secp, &self.master_xprv())
    }

    fn master_blinding(&self) -> MasterBlindingKey {
        asset_blinding_key_from_seed(&self.seed())
    }

    pub fn account_xpub(&self, path: &DerivationPath) -> ExtendedPubKey {
        let xprv = self.master_xprv().derive_priv(&self.secp, path).unwrap();
        ExtendedPubKey::from_private(&self.secp, &xprv)
    }

    pub fn sign_tx(&self, details: &TransactionMeta) -> TransactionMeta {
        let be_tx: BETransaction = if self.is_liquid {
            // FIXME: sort out what we need to do with blinding and implement this
            unimplemented!();
        } else {
            let tx: bitcoin::Transaction =
                bitcoin::consensus::deserialize(&Vec::<u8>::from_hex(&details.hex).unwrap())
                    .unwrap();
            let mut out_tx = tx.clone();

            let num_inputs = tx.input.len();
            assert_eq!(details.used_utxos.len(), num_inputs);

            for i in 0..num_inputs {
                let utxo = &details.used_utxos[i];

                let path: DerivationPath = utxo.user_path.clone().into();
                let private_key =
                    self.master_xprv().derive_priv(&self.secp, &path).unwrap().private_key;

                // Optional sanity checks
                let public_key = private_key.public_key(&self.secp);
                assert_eq!(utxo.public_key, public_key.to_string());
                let script_code =
                    Address::p2pkh(&public_key, Bip32Network::Regtest).script_pubkey();
                assert_eq!(utxo.script_code, script_code.to_hex());
                assert_eq!(utxo.is_segwit, utxo.address_type != "p2pkh");

                let signature_hash = if utxo.is_segwit {
                    SigHashCache::new(&tx).signature_hash(
                        i,
                        &script_code,
                        utxo.satoshi,
                        SigHashType::All,
                    )
                } else {
                    tx.signature_hash(i, &script_code, SigHashType::All as u32)
                };

                let message = Message::from_slice(&signature_hash.into_inner()[..]).unwrap();
                let signature = self.secp.sign(&message, &private_key.key);

                let mut der = signature.serialize_der().to_vec();
                der.push(SigHashType::All as u8);

                let pk = public_key.to_bytes();
                let (script_sig, witness) = match utxo.address_type.as_str() {
                    "p2pkh" => (
                        ScriptBuilder::new()
                            .push_slice(der.as_slice())
                            .push_slice(pk.as_slice())
                            .into_script(),
                        vec![],
                    ),
                    "p2sh-p2wpkh" => (
                        Address::p2shwpkh(&public_key, Bip32Network::Regtest)
                            .unwrap()
                            .script_pubkey(),
                        vec![der, pk],
                    ),
                    "p2wpkh" => (bitcoin::Script::new(), vec![der, pk]),
                    _ => unimplemented!(),
                };

                out_tx.input[i].script_sig = script_sig;
                out_tx.input[i].witness = witness;
            }
            BETransaction::Bitcoin(out_tx)
        };

        let mut details_out: TransactionMeta = be_tx.into();
        // FIXME: set more fields
        details_out.fee = details.fee;
        details_out.create_transaction = details.create_transaction.clone();
        details_out.user_signed = true;
        details_out
    }
}
