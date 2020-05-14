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
use log::{debug, info, warn, Metadata, Record};
use serde_json::Value;
use std::net::TcpStream;
use std::process::Child;
use std::process::Command;
use std::str::FromStr;
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

pub fn setup(
    is_liquid: bool,
    is_debug: bool,
    electrs_exec: String,
    node_exec: String,
) -> TestSession {
    let filter = if is_debug {
        LevelFilter::Info
    } else {
        LevelFilter::Off
    };
    log::set_logger(&LOGGER)
        .map(|()| log::set_max_level(filter))
        .expect("cannot initialize logging");

    let node_work_dir = TempDir::new("electrum_integration_tests").unwrap();
    let node_work_dir_str = format!("{}", &node_work_dir.path().display());
    let sum_port = if is_liquid {
        1
    } else {
        0
    };

    let rpc_port = 55363u16 + sum_port;
    let socket = format!("127.0.0.1:{}", rpc_port);
    let node_url = format!("http://{}", socket);

    let test = TcpStream::connect(&socket);
    assert!(test.is_err(), "check the port is not open with a previous instance of bitcoind");

    let datadir_arg = format!("-datadir={}", &node_work_dir.path().display());
    let rpcport_arg = format!("-rpcport={}", rpc_port);
    let mut args: Vec<&str> = vec![&datadir_arg, &rpcport_arg];
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
    debug!("node spawned");

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
    debug!("Bitcoin started");
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
    debug!("Electrs spawned");

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
    if is_liquid {
        network.liquid = true;
        network.development = true;
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
            let new_status = self.session.status().unwrap();
            if self.status != new_status {
                self.status = new_status;
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
    }

    pub fn fees(&mut self) {
        let fees = self.session.get_fee_estimates().unwrap();
        let relay_fee = self.node.get_network_info().unwrap().relay_fee.as_sat();
        assert!(fees.iter().all(|f| f.0 >= relay_fee));
    }

    pub fn settings(&mut self) {
        let mut settings = self.session.get_settings().unwrap();
        settings.altimeout += 1;
        self.session.change_settings(&settings).unwrap();
        let new_settings = self.session.get_settings().unwrap();
        assert_eq!(settings, new_settings);
    }

    /// fund the gdk session with satoshis from the node
    pub fn fund(&mut self, satoshi: u64) {
        let initial_satoshis = self.balance_gdk();
        let ap = self.session.get_receive_address(&Value::Null).unwrap();
        self.node_sendtoaddress(&ap.address, satoshi);

        self.wait_status_change();

        assert_eq!(self.balance_gdk(), initial_satoshis + satoshi);
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
            asset_tag,
        });
        create_opt.send_all = Some(true);
        let tx = self.session.create_transaction(&mut create_opt).unwrap();
        let signed_tx = self.session.sign_transaction(&tx).unwrap();

        self.check_fee_rate(fee_rate, &signed_tx, MAX_FEE_PERCENT_DIFF);
        self.session.broadcast_transaction(&signed_tx.hex).unwrap();
        self.wait_status_change();
        //let end_sat_addr = self.balance_addr(address);
        //assert_eq!(init_sat_addr + init_sat - tx.fee, end_sat_addr);
        assert_eq!(self.balance_gdk(), 0);
    }

    /// send a tx from the gdk session to the specified address
    pub fn send_tx(&mut self, address: &str, satoshi: u64) {
        let init_sat = self.balance_gdk();
        //let init_sat_addr = self.balance_addr(address);
        let mut create_opt = CreateTransaction::default();
        let fee_rate = 1000;
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
        //let end_sat_addr = self.balance_addr(address);
        //assert_eq!(init_sat_addr + satoshi, end_sat_addr);
        assert_eq!(self.balance_gdk(), init_sat - satoshi - tx.fee);
    }

    /// send a tx with multiple recipients with same amount from the gdk session to generated
    /// node's addressees
    pub fn send_multi(&mut self, recipients: u8, amount: u64) {
        let init_sat = self.balance_gdk();
        let mut create_opt = CreateTransaction::default();
        let fee_rate = 1000;
        create_opt.fee_rate = Some(fee_rate);
        let mut addressees = vec![];
        for _ in 0..recipients {
            let address = self.node_getnewaddress();
            create_opt.addressees.push(AddressAmount {
                address: address.to_string(),
                satoshi: amount,
                asset_tag: self.asset_tag(),
            });
            addressees.push(address);
        }
        let tx = self.session.create_transaction(&mut create_opt).unwrap();
        let signed_tx = self.session.sign_transaction(&tx).unwrap();
        self.check_fee_rate(fee_rate, &signed_tx, MAX_FEE_PERCENT_DIFF);
        self.session.broadcast_transaction(&signed_tx.hex).unwrap();
        self.wait_status_change();
        //for el in addressees {
        //    assert_eq!(amount, self.balance_addr(&el))
        //}
        assert_eq!(init_sat - tx.fee - recipients as u64 * amount, self.balance_gdk());
    }

    /// send a tx, check it spend utxo with the same script_pubkey together
    pub fn send_tx_same_script(&mut self) {
        let init_sat = self.balance_gdk();
        assert_eq!(init_sat, 0);

        let utxo_satoshi = 100_000;
        let ap = self.session.get_receive_address(&Value::Null).unwrap();
        self.node_sendtoaddress(&ap.address, utxo_satoshi);
        self.node_sendtoaddress(&ap.address, utxo_satoshi);

        self.wait_status_change();
        let satoshi = 50_000; // one utxo would be enough
        let mut create_opt = CreateTransaction::default();
        let fee_rate = 1000;
        let address = self.node_getnewaddress();
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

        let transaction = BETransaction::from_hex(&signed_tx.hex, self.network_id).unwrap();
        assert_eq!(2, transaction.input_len());
    }

    /// check send failure reasons
    pub fn send_fails(&mut self) {
        let init_sat = self.balance_gdk();
        let mut create_opt = CreateTransaction::default();
        let fee_rate = 1000;
        let address = self.node_getnewaddress();
        create_opt.fee_rate = Some(fee_rate);
        create_opt.addressees.push(AddressAmount {
            address: address.to_string(),
            satoshi: 0,
            asset_tag: self.asset_tag(),
        });
        match self.session.create_transaction(&mut create_opt) {
            Err(Error::InvalidAmount) => assert!(true),
            _ => assert!(false),
        }
        create_opt.addressees[0].satoshi = init_sat;
        match self.session.create_transaction(&mut create_opt) {
            Err(Error::InsufficientFunds) => assert!(true),
            _ => assert!(false),
        }
        create_opt.addressees[0].address = "x".to_string();
        match self.session.create_transaction(&mut create_opt) {
            Err(Error::InvalidAddress) => assert!(true),
            _ => assert!(false),
        }
        create_opt.addressees.clear();
        match self.session.create_transaction(&mut create_opt) {
            Err(Error::EmptyAddressees) => assert!(true),
            _ => assert!(false),
        }
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

    pub fn node_getnewaddress(&self) -> String {
        node_getnewaddress(&self.node)
    }

    fn node_sendtoaddress(&self, address: &str, satoshi: u64) {
        node_sendtoaddress(&self.node, address, satoshi)
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
    fn _balance_node(&self) -> u64 {
        // using deprectated getunconfirmedbalance because getbalances not yet available in
        // elements

        let balance: Value = self.node.call("getbalance", &[]).unwrap();
        let unconfirmed_balance: Value = self.node.call("getunconfirmedbalance", &[]).unwrap();
        let val = match self.network_id {
            NetworkId::Bitcoin(_) => {
                balance.get("bitcoin").unwrap().as_f64().unwrap()
                    + unconfirmed_balance.get("bitcoin").unwrap().as_f64().unwrap()
            }
            NetworkId::Elements(_) => {
                balance.as_f64().unwrap() + unconfirmed_balance.as_f64().unwrap()
            }
        };
        Amount::from_btc(val).unwrap().as_sat()
    }

    pub fn asset_tag(&self) -> Option<String> {
        match self.network_id {
            NetworkId::Bitcoin(_) => None,
            NetworkId::Elements(_) => self.network.policy_asset.clone(),
        }
    }

    /// balance in satoshi (or liquid satoshi) of the gdk session
    fn balance_gdk(&self) -> u64 {
        let balance = self.session.get_balance(0, None).unwrap();
        info!("balance: {:?}", balance);
        match self.network_id {
            NetworkId::Elements(_) => {
                *balance.get(self.network.policy_asset.as_ref().unwrap()).unwrap() as u64
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

fn node_sendtoaddress(client: &Client, address: &str, satoshi: u64) {
    let amount = Amount::from_sat(satoshi);
    let btc = amount.to_string_in(bitcoin::util::amount::Denomination::Bitcoin);
    info!("node_sendtoaddress {} {}", address, btc);
    let r = client.call::<Value>("sendtoaddress", &[address.into(), btc.into()]).unwrap();
    debug!("node_sendtoaddress result {:?}", r);
}

fn node_getnewaddress(client: &Client) -> String {
    let addr: Value = client.call("getnewaddress", &[]).unwrap();
    addr.as_str().unwrap().to_string()
}

fn node_generate(client: &Client, block_num: u32) {
    let address = node_getnewaddress(client);
    let r = client.call::<Value>("generatetoaddress", &[block_num.into(), address.into()]).unwrap();
    debug!("generate result {:?}", r);
}
