extern crate clap;
use clap::{Arg, App, SubCommand};

use wgdsau::interface::WalletCtx;
use wgdsau::interface::lib_init;
use wgdsau::model::*;

fn main() {
    let matches = App::new("WGDSAU")
                          .version("1.0")
                          .about("Does awesome things")
                          .arg(Arg::with_name("wallet")
                               .short("w")
                               .long("wallet")
                               .value_name("WALLET")
                               .help("Set the wallet_name")
                               .takes_value(true))
                          .arg(Arg::with_name("path")
                               .short("p")
                               .long("path")
                               .value_name("FOLDER")
                               .help("Set a custom db path")
                               .takes_value(true))
                          .arg(Arg::with_name("url")
                               .short("u")
                               .long("url")
                               .value_name("URL")
                               .help("Set a custom Electrum url")
                               .takes_value(true))
                          .subcommand(SubCommand::with_name("fee")
                                      .about("Get fees")
                                      .arg(Arg::with_name("nblocks")
                                          .short("n")
                                          .long("nblocks")
                                          .value_name("TARGET")
                                          .help("Fee block target")
                                          .takes_value(true)))
                          .subcommand(SubCommand::with_name("dump_db")
                                      .about("Dump the database"))
                          .subcommand(SubCommand::with_name("sync")
                                       .arg(Arg::with_name("xpub")
                                          .short("x")
                                          .long("xpub")
                                          .value_name("XPUB")
                                          .help("The xpub to sync")
                                          .takes_value(true))
                                      .about("Sync with xpub"))
                          .subcommand(SubCommand::with_name("list_tx")
                                      .about("Get transactions from db"))
                          .subcommand(SubCommand::with_name("utxos")
                                      .about("Get unspent outputs from db"))
                          .subcommand(SubCommand::with_name("balance")
                                      .about("Get balance from db"))
                          .subcommand(SubCommand::with_name("create_tx")
                                      .about("Create a transaction")
                                       .arg(Arg::with_name("xpub")
                                          .short("x")
                                          .long("xpub")
                                          .value_name("XPUB")
                                          .help("The xpub to sync")
                                          .takes_value(true))
                                      .arg(Arg::with_name("to_addr")
                                          .short("a")
                                          .long("to_addr")
                                          .value_name("ADDRESS")
                                          .help("Recipient address")
                                          .takes_value(true))
                                      .arg(Arg::with_name("to_value")
                                          .short("v")
                                          .long("to_value")
                                          .value_name("SATOSHI")
                                          .help("Amount to send")
                                          .takes_value(true)))
                          .subcommand(SubCommand::with_name("sign")
                                      .about("Sign a transaction")
                                       .arg(Arg::with_name("xprv")
                                          .short("x")
                                          .long("xprv")
                                          .value_name("XPRV")
                                          .help("The xprv used to sign")
                                          .takes_value(true))
                                      .arg(Arg::with_name("transaction")
                                          .short("t")
                                          .long("transaction")
                                          .value_name("TRANSACTION")
                                          .help("The transaction JSON")
                                          .takes_value(true))
                                      .arg(Arg::with_name("derivation_paths")
                                          .short("d")
                                          .long("derivation_paths")
                                          .value_name("[PATHS]")
                                          .help("Array of paths like [\"m/0/0\"]")
                                          .takes_value(true)))
                          .subcommand(SubCommand::with_name("broadcast")
                                      .about("Broadcast a signed transaction")
                                       .arg(Arg::with_name("transaction")
                                          .short("t")
                                          .long("transaction")
                                          .value_name("TRANSACTION")
                                          .help("The transaction")
                                          .takes_value(true)))
                          .subcommand(SubCommand::with_name("address")
                                       .arg(Arg::with_name("xpub")
                                          .short("x")
                                          .long("xpub")
                                          .value_name("XPUB")
                                          .help("The xpub to sync")
                                          .takes_value(true))
                                      .about("Get a new address"))
                          .get_matches();

    let wallet_name = matches.value_of("wallet").unwrap_or("wallet");
    let path = matches.value_of("path").unwrap_or("/tmp/wgdasu.db").to_string();
    //let url = matches.value_of("url").unwrap_or("192.168.2.134:60001");
    let url = matches.value_of("url").unwrap_or("tn.not.fyi:55001");

    // call init
    unsafe { lib_init(WGInit { path } ); };

    let mut w = WalletCtx::new(wallet_name.to_string(), Some(url)).unwrap();

    if let Some(matches) = matches.subcommand_matches("fee") {
        let nblocks: u32 = matches.value_of("nblocks").unwrap_or("6").parse().unwrap();
        let r = w.fee(WGEstimateFeeReq{ nblocks });

        println!("{:?}", r);
    } else if let Some(_matches) = matches.subcommand_matches("dump_db") {
        w.dump_db();
    } else if let Some(matches) = matches.subcommand_matches("sync") {
        use bitcoin::util::bip32::ExtendedPubKey;
        use std::str::FromStr;

        let xpub = matches.value_of("xpub").unwrap();

        let ret = w.sync(WGSyncReq { xpub: ExtendedPubKey::from_str(xpub).unwrap(), url: None  });
        println!("{:?}", ret);
    } else if let Some(_matches) = matches.subcommand_matches("list_tx") {
        let ret = w.list_tx();

        println!("{:?}", ret);
    } else if let Some(_matches) = matches.subcommand_matches("utxos") {
        let ret = w.utxos();

        println!("{:?}", ret);
    } else if let Some(_matches) = matches.subcommand_matches("balance") {
        let ret = w.balance();

        println!("{:?}", ret);
    } else if let Some(matches) = matches.subcommand_matches("create_tx") {
        use bitcoin::util::address::Address;
        use bitcoin::util::bip32::ExtendedPubKey;
        use std::str::FromStr;

        let xpub = matches.value_of("xpub").unwrap();
        let addr = matches.value_of("to_addr").unwrap();
        let value: u64 = matches.value_of("to_value").unwrap().parse().unwrap();

        let tx = w.create_tx(WGCreateTxReq {
            utxo: None,
            xpub: ExtendedPubKey::from_str(xpub).unwrap(),
            fee_perkb: 10000.0,
            addresses_amounts: vec![WGAddressAmount { address: Address::from_str(addr).unwrap(), satoshi: value } ]
        });

        println!("{:?}", tx);
        println!("{}", serde_json::to_string(&tx.unwrap().transaction).unwrap());
    } else if let Some(matches) = matches.subcommand_matches("sign") {
        use bitcoin::util::bip32::{ExtendedPrivKey, DerivationPath};
        use std::str::FromStr;

        let xprv = matches.value_of("xprv").unwrap();
        let tx = serde_json::from_str(matches.value_of("transaction").unwrap()).unwrap();
        let derivation_paths: Vec<DerivationPath> = serde_json::from_str(matches.value_of("derivation_paths").unwrap()).unwrap();

        let tx = w.sign(WGSignReq {
            xprv: ExtendedPrivKey::from_str(xprv).unwrap(),
            transaction: tx,
            derivation_paths
        });

        println!("{:?}", tx);
        println!("{}", serde_json::to_string(&tx.unwrap().transaction).unwrap());
    } else if let Some(matches) = matches.subcommand_matches("broadcast") {
        let tx = serde_json::from_str(matches.value_of("transaction").unwrap()).unwrap();

        w.broadcast(WGTransaction::new(tx, 0, 0, 0, None, vec![], vec![]));
    } else if let Some(matches) = matches.subcommand_matches("address") {
        use bitcoin::util::bip32::ExtendedPubKey;
        use std::str::FromStr;

        let xpub = matches.value_of("xpub").unwrap();
        let ret = w.get_address(WGExtendedPubKey { xpub: ExtendedPubKey::from_str(xpub).unwrap() });

        println!("{:?}", ret);
    }
}
