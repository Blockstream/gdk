use bitcoin::{self, Amount};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use electrum_client::client::ElectrumPlaintextStream;
use elements;
use gdk_common::be::{BEAddress, BETransaction};
use gdk_common::mnemonic::Mnemonic;
use gdk_common::model::*;
use gdk_common::session::Session;
use gdk_common::Network;
use gdk_common::{ElementsNetwork, NetworkId};
use gdk_electrum::error::Error;
use gdk_electrum::{determine_electrum_url_from_net, ElectrumSession};
use log::LevelFilter;
use log::{info, warn, Metadata, Record};
use serde_json::Value;
use std::collections::HashSet;
use std::iter::FromIterator;
use std::net::TcpStream;
use std::process::Child;
use std::process::Command;
use std::str::FromStr;
use std::sync::Once;
use std::thread;
use std::time::Duration;
use tempdir::TempDir;

static LOGGER: SimpleLogger = SimpleLogger;
const MAX_FEE_PERCENT_DIFF: f64 = 0.05;

#[allow(unused)]
pub struct TestSession {
    node: Client,
    electrs: electrum_client::Client<ElectrumPlaintextStream>,
    electrs_header: electrum_client::Client<ElectrumPlaintextStream>,
    session: ElectrumSession,
    status: u64,
    node_process: Child,
    electrs_process: Child,
    node_work_dir: TempDir,
    electrs_work_dir: TempDir,
    network_id: NetworkId,
    network: Network,
}

//TODO duplicated why I cannot import?
pub struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            if record.level() <= LevelFilter::Warn {
                println!("{} - {}", record.level(), record.args());
            } else {
                println!("{}", record.args());
            }
        }
    }

    fn flush(&self) {}
}

static START: Once = Once::new();

pub fn setup(
    is_liquid: bool,
    is_debug: bool,
    electrs_exec: String,
    node_exec: String,
) -> TestSession {
    START.call_once(|| {
        let filter = if is_debug {
            LevelFilter::Info
        } else {
            LevelFilter::Off
        };
        log::set_logger(&LOGGER)
            .map(|()| log::set_max_level(filter))
            .expect("cannot initialize logging");
    });

    let node_work_dir = TempDir::new("electrum_integration_tests").unwrap();
    let node_work_dir_str = format!("{}", &node_work_dir.path().display());
    let sum_port = is_liquid as u16;

    let rpc_port = 55363u16 + sum_port;
    let p2p_port = 34975u16 + sum_port;
    let socket = format!("127.0.0.1:{}", rpc_port);
    let node_url = format!("http://{}", socket);

    let test = TcpStream::connect(&socket);
    assert!(test.is_err(), "check the port is not open with a previous instance of bitcoind");

    let datadir_arg = format!("-datadir={}", &node_work_dir.path().display());
    let rpcport_arg = format!("-rpcport={}", rpc_port);
    let p2pport_arg = format!("-port={}", p2p_port);
    let mut args: Vec<&str> = vec![&datadir_arg, &rpcport_arg, &p2pport_arg];
    if is_liquid {
        args.push("-initialfreecoins=2100000000");
        args.push("-chain=liquidregtest");
        args.push("-validatepegin=0");
    } else {
        args.push("-regtest");
    };
    if !is_debug {
        args.push("-daemon");
    }
    info!("LAUNCHING: {} {}", node_exec, args.join(" "));
    let node_process = Command::new(node_exec).args(args).spawn().unwrap();
    info!("node spawned");

    let par_network = if is_liquid {
        "liquidregtest"
    } else {
        "regtest"
    };
    let cookie_file = node_work_dir.path().join(par_network).join(".cookie");
    let cookie_file_str = format!("{}", cookie_file.as_path().display());
    // wait bitcoind is ready, use default wallet
    let node: Client = loop {
        thread::sleep(Duration::from_millis(500));
        assert!(node_process.stderr.is_none());
        let client_result = Client::new(node_url.clone(), Auth::CookieFile(cookie_file.clone()));
        match client_result {
            Ok(client) => match client.call::<Value>("getblockchaininfo", &[]) {
                Ok(_) => break client,
                Err(e) => warn!("{:?}", e),
            },
            Err(e) => warn!("{:?}", e),
        }
    };
    info!("Bitcoin started");
    let cookie_value = std::fs::read_to_string(&cookie_file).unwrap();

    let electrs_port = 62431u16 + sum_port;
    let electrs_work_dir = TempDir::new("electrum_integration_tests").unwrap();
    let electrs_work_dir_str = format!("{}", &electrs_work_dir.path().display());
    let electrs_url = format!("127.0.0.1:{}", electrs_port);
    let daemon_url = format!("127.0.0.1:{}", rpc_port);
    let mut args: Vec<&str> = vec![
        "--db-dir",
        &electrs_work_dir_str,
        "--daemon-dir",
        &node_work_dir_str,
        "--electrum-rpc-addr",
        &electrs_url,
        "--daemon-rpc-addr",
        &daemon_url,
        "--network",
        par_network,
    ];
    if is_liquid {
        args.push("--cookie");
        args.push(&cookie_value);
    } else {
        args.push("--cookie-file");
        args.push(&cookie_file_str);
    };
    if is_debug {
        args.push("-v");
    }

    info!("LAUNCHING: {} {}", electrs_exec, args.join(" "));
    let electrs_process = Command::new(electrs_exec).args(args).spawn().unwrap();
    info!("Electrs spawned");

    node_generate(&node, 101);

    info!("creating electrs client");
    let electrs = loop {
        match electrum_client::Client::new(&electrs_url) {
            Ok(c) => break c,
            Err(e) => {
                warn!("{:?}", e);
                thread::sleep(Duration::from_millis(500));
            }
        }
    };
    info!("done creating electrs client");
    let mut electrs_header = electrum_client::Client::new(&electrs_url).unwrap();
    let header = electrs_header.block_headers_subscribe_raw().unwrap();
    assert_eq!(header.height, 101);

    let mut network = Network::default();
    network.url = Some(electrs_url.to_string());
    network.sync_interval = Some(1);
    network.development = true;
    network.ct_bits = 52;
    network.ct_exponent = 0;
    network.ct_min_value = 1;
    if is_liquid {
        network.liquid = true;
        network.policy_asset =
            Some("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225".into());
    }
    let db_root =
        format!("{}", TempDir::new("electrum_integration_tests").unwrap().path().display());
    let url = determine_electrum_url_from_net(&network).unwrap();

    info!("creating gdk session");
    let mut session = ElectrumSession::create_session(network.clone(), &db_root, url);

    let mnemonic: Mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string().into();
    info!("logging in gdk session");
    session.login(&mnemonic, None).unwrap();

    let network_id = if is_liquid {
        NetworkId::Elements(ElementsNetwork::ElementsRegtest)
    } else {
        NetworkId::Bitcoin(bitcoin::Network::Regtest)
    };

    let status = session.status().unwrap();
    assert_eq!(status, 9288996555440648771);
    info!("returning TestSession");
    TestSession {
        status,
        node,
        electrs,
        electrs_header,
        session,
        node_process,
        electrs_process,
        node_work_dir,
        electrs_work_dir,
        network_id,
        network,
    }
}

impl TestSession {
    /// wait gdk session status to change (new tx)
    fn wait_status_change(&mut self) {
        loop {
            if let Ok(new_status) = self.session.status() {
                if self.status != new_status {
                    self.status = new_status;
                    break;
                }
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    /// test fees are 25 elements and greater than relay_fee
    pub fn fees(&mut self) {
        let fees = self.session.get_fee_estimates().unwrap();
        let relay_fee = self.node.get_network_info().unwrap().relay_fee.as_sat();
        assert_eq!(fees.len(), 25);
        assert!(fees.iter().all(|f| f.0 >= relay_fee));
    }

    /// test a change in the settings is saved
    pub fn settings(&mut self) {
        let mut settings = self.session.get_settings().unwrap();
        settings.altimeout += 1;
        self.session.change_settings(&settings).unwrap();
        let new_settings = self.session.get_settings().unwrap();
        assert_eq!(settings, new_settings);
    }

    /// fund the gdk session with satoshis from the node, if on liquid issue `assets_to_issue` assets
    pub fn fund(&mut self, satoshi: u64, assets_to_issue: Option<u8>) -> Vec<String> {
        let initial_satoshis = self.balance_gdk(None);
        let ap = self.session.get_receive_address(&Value::Null).unwrap();
        let funding_tx = self.node_sendtoaddress(&ap.address, satoshi, None);
        self.wait_status_change();
        self.list_tx_contains(&funding_tx, &vec![], false);
        let mut assets_issued = vec![];

        for _ in 0..assets_to_issue.unwrap_or(0) {
            let asset = self.node_issueasset(satoshi);
            self.node_sendtoaddress(&ap.address, satoshi, Some(asset.clone()));
            self.wait_status_change();
            assets_issued.push(asset);
        }

        assert_eq!(self.balance_gdk(None), initial_satoshis + satoshi);
        assets_issued
    }

    /// send all of the balance of the  tx from the gdk session to the specified address
    pub fn send_all(&mut self, address: &str, asset_tag: Option<String>) {
        //let init_sat = self.balance_gdk();
        //let init_sat_addr = self.balance_addr(address);
        let mut create_opt = CreateTransaction::default();
        let fee_rate = 1000;
        create_opt.fee_rate = Some(fee_rate);
        create_opt.addressees.push(AddressAmount {
            address: address.to_string(),
            satoshi: 0,
            asset_tag: asset_tag.clone(),
        });
        create_opt.send_all = Some(true);
        let tx = self.session.create_transaction(&mut create_opt).unwrap();
        let signed_tx = self.session.sign_transaction(&tx).unwrap();

        self.check_fee_rate(fee_rate, &signed_tx, MAX_FEE_PERCENT_DIFF);
        self.session.broadcast_transaction(&signed_tx.hex).unwrap();
        self.wait_status_change();
        //let end_sat_addr = self.balance_addr(address);
        //assert_eq!(init_sat_addr + init_sat - tx.fee, end_sat_addr);
        assert_eq!(self.balance_gdk(asset_tag), 0);

        assert!(tx.create_transaction.unwrap().send_all.unwrap());
        assert!(signed_tx.create_transaction.unwrap().send_all.unwrap());
    }

    /// send a tx from the gdk session to the specified address
    pub fn send_tx(&mut self, address: &str, satoshi: u64, asset: Option<String>) {
        let init_sat = self.balance_gdk(asset.clone());
        let init_node_balance = self.balance_node(asset.clone());
        //let init_sat_addr = self.balance_addr(address);
        let mut create_opt = CreateTransaction::default();
        let fee_rate = match self.network.id() {
            NetworkId::Elements(_) => 100,
            NetworkId::Bitcoin(_) => 1000,
        };
        create_opt.fee_rate = Some(fee_rate);
        create_opt.addressees.push(AddressAmount {
            address: address.to_string(),
            satoshi,
            asset_tag: asset.clone().or(self.asset_tag()),
        });
        let tx = self.session.create_transaction(&mut create_opt).unwrap();
        assert!(tx.user_signed);
        match self.network.id() {
            NetworkId::Elements(_) => assert!(!tx.rbf_optin),
            NetworkId::Bitcoin(_) => assert!(tx.rbf_optin),
        };
        let signed_tx = self.session.sign_transaction(&tx).unwrap();
        self.check_fee_rate(fee_rate, &signed_tx, MAX_FEE_PERCENT_DIFF);
        let txid = self.session.broadcast_transaction(&signed_tx.hex).unwrap();
        self.wait_status_change();

        self.tx_checks(&signed_tx.hex);

        let fee = if asset.is_none() || asset == self.network.policy_asset {
            tx.fee
        } else {
            0
        };
        assert_eq!(self.balance_node(asset.clone()), init_node_balance + satoshi);
        assert_eq!(self.balance_gdk(asset.clone()), init_sat - satoshi - fee);

        assert!(!tx.create_transaction.unwrap().send_all.unwrap());
        assert!(!signed_tx.create_transaction.unwrap().send_all.unwrap());

        self.list_tx_contains(&txid, &vec![address.to_string()], true);
    }

    fn list_tx_contains(&mut self, txid: &str, addressees: &[String], user_signed: bool) {
        let mut opt = GetTransactionsOpt::default();
        opt.count = 100;

        let list = self.session.get_transactions(&opt).unwrap().0;
        let filtered_list: Vec<&TxListItem> = list.iter().filter(|e| e.txhash == txid).collect();
        assert!(!filtered_list.is_empty(), "just made tx {} is not in tx list", txid);

        let tx = filtered_list.first().unwrap();

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

    /// send a tx with multiple recipients with same amount from the gdk session to generated
    /// node's addressees, if `assets` contains values, they are used as asset_tag cyclically
    pub fn send_multi(&mut self, recipients: u8, amount: u64, assets: Vec<String>) {
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
            let asset_tag = if assets.is_empty() {
                self.asset_tag()
            } else {
                let current = assets_cycle.next().unwrap().to_string();
                tags.push(current.clone());
                Some(current)
            };

            create_opt.addressees.push(AddressAmount {
                address: address.to_string(),
                satoshi: amount,
                asset_tag,
            });
            addressees.push(address);
        }
        let tx = self.session.create_transaction(&mut create_opt).unwrap();
        let signed_tx = self.session.sign_transaction(&tx).unwrap();
        self.check_fee_rate(fee_rate, &signed_tx, MAX_FEE_PERCENT_DIFF);
        let txid = self.session.broadcast_transaction(&signed_tx.hex).unwrap();
        self.wait_status_change();
        self.tx_checks(&signed_tx.hex);

        if assets.is_empty() {
            assert_eq!(init_sat - tx.fee - recipients as u64 * amount, self.balance_gdk(None));
        } else {
            assert_eq!(init_sat - tx.fee, self.balance_gdk(None));
            for tag in assets {
                let outputs_for_this_asset = tags.iter().filter(|t| t == &&tag).count() as u64;
                assert_eq!(
                    *init_assets_sat.get(&tag).unwrap() as u64 - outputs_for_this_asset * amount,
                    self.balance_gdk(Some(tag))
                );
            }
        }
        //TODO check node balance
        self.list_tx_contains(&txid, &addressees, true);
    }

    pub fn send_tx_to_unconf(&mut self) {
        let init_sat = self.balance_gdk(None);
        let ap = self.session.get_receive_address(&Value::Null).unwrap();
        let unconf_address = to_unconfidential(ap.address);
        self.node_sendtoaddress(&unconf_address, 10_000, None);
        self.wait_status_change();
        assert_eq!(init_sat, self.balance_gdk(None));
    }

    /// send a tx, check it spend utxo with the same script_pubkey together
    pub fn send_tx_same_script(&mut self) {
        // TODO check same script for different assets
        let init_sat = self.balance_gdk(None);
        assert_eq!(init_sat, 0);

        let utxo_satoshi = 100_000;
        let ap = self.session.get_receive_address(&Value::Null).unwrap();
        self.node_sendtoaddress(&ap.address, utxo_satoshi, None);
        self.wait_status_change();
        self.node_sendtoaddress(&ap.address, utxo_satoshi, None);
        self.wait_status_change();
        let satoshi = 50_000; // one utxo would be enough
        let mut create_opt = CreateTransaction::default();
        let fee_rate = 1000;
        let address = self.node_getnewaddress(None);
        create_opt.fee_rate = Some(fee_rate);
        create_opt.addressees.push(AddressAmount {
            address: address.to_string(),
            satoshi,
            asset_tag: self.asset_tag(),
        });
        let tx = self.session.create_transaction(&mut create_opt).unwrap();
        let signed_tx = self.session.sign_transaction(&tx).unwrap();
        self.check_fee_rate(fee_rate, &signed_tx, MAX_FEE_PERCENT_DIFF);
        self.session.broadcast_transaction(&signed_tx.hex).unwrap();
        self.wait_status_change();
        self.tx_checks(&signed_tx.hex);

        let transaction = BETransaction::from_hex(&signed_tx.hex, self.network_id).unwrap();
        assert_eq!(2, transaction.input_len());
    }

    /// check send failure reasons
    pub fn send_fails(&mut self) {
        let init_sat = self.balance_gdk(None);
        let mut create_opt = CreateTransaction::default();
        let fee_rate = 1000;
        let address = self.node_getnewaddress(None);
        create_opt.fee_rate = Some(fee_rate);
        create_opt.addressees.push(AddressAmount {
            address: address.to_string(),
            satoshi: 0,
            asset_tag: self.asset_tag(),
        });
        assert!(matches!(
            self.session.create_transaction(&mut create_opt),
            Err(Error::InvalidAmount)
        ));

        create_opt.addressees[0].satoshi = 200; // below dust limit
        assert!(matches!(
            self.session.create_transaction(&mut create_opt),
            Err(Error::InvalidAmount)
        ));

        create_opt.addressees[0].satoshi = init_sat; // not enough to pay the fee
        assert!(matches!(
            self.session.create_transaction(&mut create_opt),
            Err(Error::InsufficientFunds)
        ));

        create_opt.subaccount = Some(1);
        assert!(matches!(
            self.session.create_transaction(&mut create_opt),
            Err(Error::InvalidSubaccount(1))
        ));
        create_opt.subaccount = None;

        create_opt.previous_transaction.insert("txhash".into(), "something".into());
        assert!(matches!(self.session.create_transaction(&mut create_opt), Err(Error::Generic(_))));
        create_opt.previous_transaction.clear();

        create_opt.addressees[0].address = "x".to_string();
        assert!(matches!(
            self.session.create_transaction(&mut create_opt),
            Err(Error::InvalidAddress)
        ));

        create_opt.addressees[0].address = "38CMdevthTKYAtxaSkYYtcv5QgkHXdKKk5".to_string(); //
        assert!(
            matches!(self.session.create_transaction(&mut create_opt), Err(Error::InvalidAddress)),
            "address with different network should fail"
        );

        create_opt.addressees[0].address =
            "VJLCbLBTCdxhWyjVLdjcSmGAksVMtabYg15maSi93zknQD2ihC38R7CUd8KbDFnV8A4hiykxnRB3Uv6d"
                .to_string();
        assert!(
            matches!(self.session.create_transaction(&mut create_opt), Err(Error::InvalidAddress)),
            "address with different network should fail"
        );

        let addr =
            "Azpt6vXqrbPuUtsumAioGjKnvukPApDssC1HwoFdSWZaBYJrUVSe5K8x9nk2HVYiYANy9mVQbW3iQ6xU";
        let mut addr = elements::Address::from_str(addr).unwrap();
        addr.blinding_pubkey = None;
        create_opt.addressees[0].address = addr.to_string();
        assert!(
            matches!(self.session.create_transaction(&mut create_opt), Err(Error::InvalidAddress)),
            "unblinded address should fail"
        );

        create_opt.addressees.clear();
        assert!(matches!(
            self.session.create_transaction(&mut create_opt),
            Err(Error::EmptyAddressees)
        ));
    }

    /// performs checks on transactions, like checking for address reuse in outputs and on liquid confidential commitments inequality
    pub fn tx_checks(&self, hex: &str) {
        match self.network_id {
            NetworkId::Elements(_) => {
                let tx: elements::Transaction =
                    elements::encode::deserialize(&hex::decode(hex).unwrap()).unwrap();
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
                    bitcoin::consensus::encode::deserialize(&hex::decode(hex).unwrap()).unwrap();
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
        assert!(self.session.get_subaccount(0, 0).is_ok());
        assert!(self.session.get_subaccount(1, 0).is_err());
    }

    /// mine a block with the node and check if gdk session see the change
    pub fn mine_block(&mut self) {
        let initial_height = self.electrs_tip();
        info!("mine_block initial_height {}", initial_height);
        self.node_generate(1);
        self.wait_status_change();
        let new_height = loop {
            // apparently even if gdk session status changed (thus new height come in)
            // it could happend this is the old height (maybe due to caching) thus we loop wait
            let new_height = self.electrs_tip();
            if new_height != initial_height {
                break new_height;
            }
            info!("height still the same");
            thread::sleep(Duration::from_millis(500));
        };
        info!("mine_block new_height {}", new_height);
        assert_eq!(initial_height + 1, new_height);
    }

    pub fn node_getnewaddress(&self, kind: Option<&str>) -> String {
        node_getnewaddress(&self.node, kind)
    }

    fn node_sendtoaddress(&self, address: &str, satoshi: u64, asset: Option<String>) -> String {
        node_sendtoaddress(&self.node, address, satoshi, asset)
    }
    fn node_issueasset(&self, satoshi: u64) -> String {
        node_issueasset(&self.node, satoshi)
    }
    fn node_generate(&self, block_num: u32) {
        node_generate(&self.node, block_num)
    }

    pub fn check_fee_rate(&self, req_rate: u64, tx_meta: &TransactionMeta, max_perc_diff: f64) {
        let transaction = BETransaction::from_hex(&tx_meta.hex, self.network_id).unwrap();
        let real_rate = tx_meta.fee as f64 / (transaction.get_weight() as f64 / 4.0);
        let req_rate = req_rate as f64 / 1000.0;
        assert!(
            ((real_rate - req_rate).abs() / real_rate) < max_perc_diff,
            format!("real_rate:{} req_rate:{}", real_rate, req_rate)
        ); // percentage difference between fee rate requested vs real fee
        let relay_fee = self.node.get_network_info().unwrap().relay_fee.as_sat() as f64 / 1000.0;
        assert!(
            real_rate > relay_fee,
            format!("fee rate:{} is under relay_fee:{}", real_rate, relay_fee)
        );
    }

    /// ask the blockcain tip to electrs
    fn electrs_tip(&mut self) -> usize {
        for _ in 0..10 {
            match self.electrs_header.block_headers_subscribe_raw() {
                Ok(header) => return header.height,
                Err(e) => {
                    warn!("electrs_tip {:?}", e); // fixme, for some reason it errors once every two try
                    thread::sleep(Duration::from_millis(500));
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
        let balance: Value = self.node.call("getbalance", &[]).unwrap();
        let unconfirmed_balance: Value = self.node.call("getunconfirmedbalance", &[]).unwrap();
        match self.network_id {
            NetworkId::Bitcoin(_) => {
                ((balance.as_f64().unwrap() + unconfirmed_balance.as_f64().unwrap())
                    * 100_000_000.0) as u64
            }
            NetworkId::Elements(_) => {
                let asset_or_policy = asset.or(Some("bitcoin".to_string())).unwrap();
                let balance = match balance.get(&asset_or_policy) {
                    Some(Value::Number(s)) => s.as_f64().unwrap(),
                    _ => 0.0,
                };
                let unconfirmed_balance = match unconfirmed_balance.get(&asset_or_policy) {
                    Some(Value::Number(s)) => s.as_f64().unwrap(),
                    _ => 0.0,
                };
                ((balance + unconfirmed_balance) * 100_000_000.0) as u64
            }
        }
    }

    pub fn asset_tag(&self) -> Option<String> {
        match self.network_id {
            NetworkId::Bitcoin(_) => None,
            NetworkId::Elements(_) => self.network.policy_asset.clone(),
        }
    }

    /// balance in satoshi (or liquid satoshi) of the gdk session
    fn balance_gdk_all(&self) -> Balances {
        self.session.get_balance(0, None).unwrap()
    }

    /// balance in satoshi (or liquid satoshi) of the gdk session
    fn balance_gdk(&self, asset: Option<String>) -> u64 {
        let balance = self.session.get_balance(0, None).unwrap();
        info!("balance: {:?}", balance);
        match self.network_id {
            NetworkId::Elements(_) => {
                let asset =
                    asset.unwrap_or(self.network.policy_asset.as_ref().unwrap().to_string());
                *balance.get(&asset).unwrap_or(&0i64) as u64
            }
            NetworkId::Bitcoin(_) => *balance.get("btc").unwrap() as u64,
        }
    }

    /// stop the bitcoin node in the test session
    pub fn stop(&mut self) {
        self.node.stop().unwrap();
        self.node_process.wait().unwrap();
        self.electrs_process.kill().unwrap();
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

fn node_generate(client: &Client, block_num: u32) {
    let address = node_getnewaddress(client, None);
    let r = client.call::<Value>("generatetoaddress", &[block_num.into(), address.into()]).unwrap();
    info!("generate result {:?}", r);
}

fn node_issueasset(client: &Client, satoshi: u64) -> String {
    let amount = Amount::from_sat(satoshi);
    let btc = amount.to_string_in(bitcoin::util::amount::Denomination::Bitcoin);
    let r = client.call::<Value>("issueasset", &[btc.into(), 0.into()]).unwrap();
    info!("node_issueasset result {:?}", r);
    r.get("asset").unwrap().as_str().unwrap().to_string()
}

fn to_unconfidential(elements_address: String) -> String {
    let mut address_unconf = elements::Address::from_str(&elements_address).unwrap();
    address_unconf.blinding_pubkey = None;
    address_unconf.to_string()
}
