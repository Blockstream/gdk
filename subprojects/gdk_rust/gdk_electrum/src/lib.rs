#![allow(dead_code)] // TODO remove

#[macro_use]
extern crate serde_json;

use log::{error, info};
use std::ffi::CStr;
use std::os::raw::c_char;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(target_os = "android")]
use android_logger::Config;
#[cfg(target_os = "android")]
use log::Level;

pub mod client;
pub mod db;
pub mod error;
pub mod interface;
pub mod mnemonic;
pub mod model;
pub mod tools;

use crate::error::Error;
use crate::interface::{lib_init, WalletCtx};
use crate::model::*;

use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey, DerivationPath};
use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;
use gdk_common::network::Network;
use gdk_common::Session;
use secp256k1::Secp256k1;
use std::net::ToSocketAddrs;
use std::str::FromStr;

#[derive(Debug)]
#[repr(C)]
pub struct ElectrumSession {
    pub network: Network,
    pub mnemonic: Option<String>,
}

impl ElectrumSession {
    pub fn create_session(network: Network) -> Result<ElectrumSession, Error> {
        match network.electrum_url {
            Some(_) => {
                let init = WGInit {
                    path: "/tmp/gdk_rust".to_string(), // TODO should be passed through GDK.init
                };
                unsafe { lib_init(init) };
                println!("returning session");
                Ok(ElectrumSession {
                    network,
                    mnemonic: None,
                })
            }
            None => Err(Error::Generic(
                "ElectrumSession create_session without electrum server url".into(),
            )),
        }
    }
}

impl Session<Error> for ElectrumSession {
    // type Value = ElectrumSession;

    fn destroy_session(&self) -> Result<(), Error> {
        Err(Error::Generic("implementme: ElectrumSession destroy_session".into()))
    }

    fn poll_session(&self) -> Result<(), Error> {
        Err(Error::Generic("implementme: ElectrumSession poll_session".into()))
    }

    fn connect(&mut self, _net_params: &Value) -> Result<(), Error> {
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        Err(Error::Generic("implementme: ElectrumSession connect".into()))
    }

    fn login(&mut self, mnemonic: String, password: Option<String>) -> Result<(), Error> {
        println!("login");

        // println!("login {:?}", self);  // TODO accessing to self from gdk build and python bindings launch segmentation fault

        //let url = self.network.electrum_url.unwrap(); //should be safe, since Some is checked in create_session
        let url = "tn.not.fyi:55001";
        let wallet_name = hex::encode(sha256::Hash::hash(mnemonic.as_bytes()));
        let mut wallet = WalletCtx::new(wallet_name, Some(url)).unwrap();
        //println!("WalletCtx {:?}", wallet);

        //bip39 using bitcoin-wallet, conflict on network, should upgrade repo to rust-bitcoin 0.23, imported only mnemonic.rs
        let mnemonic = mnemonic::Mnemonic::from_str(&mnemonic).unwrap();
        let seed = mnemonic.to_seed(password.as_deref());
        let secp = Secp256k1::new();
        let xprv = ExtendedPrivKey::new_master(bitcoin::network::constants::Network::Testnet, &seed)?;

        // m / purpose' / coin_type' / account' / change / address_index
        // coin_type = 0 bitcoin, 1 testnet, 1776 liquid bitcoin
        let path = DerivationPath::from_str("m/44'/0'/0'/").unwrap();
        let xprv = xprv.derive_priv(&secp, &path).unwrap();

        let xpub = ExtendedPubKey::from_private(&secp, &xprv);


        let req = WGSyncReq {
            xpub: xpub.clone(),
        };

        wallet.sync(req);

        // TODO just here for test
        let a1 = wallet.get_address(WGExtendedPubKey {
            xpub,
        });
        println!("a1: {:?} ", a1);
        let a2 = wallet.get_address(WGExtendedPubKey {
            xpub,
        });
        println!("a2: {:?} ", a2);

        Ok(())
    }

    fn get_subaccounts(&self) -> Result<Value, Error> {
        // Err(Error::Generic("implementme: ElectrumSession get_subaccounts".into()))
        let subaccounts_fake = json!({
        "type": "core",
        "pointer": 0,
        "required_ca": 0,
        "receiving_id": "",
        "name": "fake account",
        "has_transactions": true,
        "satoshi": 1000 });

        Ok(subaccounts_fake)
    }

    fn get_subaccount(&self, _index: u32) -> Result<Value, Error> {
        Err(Error::Generic("implementme: ElectrumSession get_subaccount".into()))
    }

    fn get_transactions(&self, _details: &Value) -> Result<Value, Error> {
        Err(Error::Generic("implementme: ElectrumSession get_transactions".into()))
    }

    fn get_transaction_details(&self, _txid: &str) -> Result<Value, Error> {
        Err(Error::Generic("implementme: ElectrumSession get_transaction_details".into()))
    }

    fn get_balance(&self, _details: &Value) -> Result<Value, Error> {
        Err(Error::Generic("implementme: ElectrumSession get_balance".into()))
    }

    fn set_transaction_memo(&self, _txid: &str, _memo: &str, _memo_type: u32) -> Result<(), Error> {
        Err(Error::Generic("implementme: ElectrumSession set_transaction_memo".into()))
    }

    fn create_transaction(&self, _details: &Value) -> Result<String, Error> {
        Err(Error::Generic("implementme: ElectrumSession create_transaction".into()))
    }

    fn sign_transaction(&self, _tx_detail_unsigned: &Value) -> Result<Value, Error> {
        Err(Error::Generic("implementme: ElectrumSession sign_transaction".into()))
    }

    fn send_transaction(&self, _tx_detail_signed: &Value) -> Result<String, Error> {
        Err(Error::Generic("implementme: ElectrumSession send_transaction".into()))
    }

    fn broadcast_transaction(&self, _tx_hex: &str) -> Result<String, Error> {
        Err(Error::Generic("implementme: ElectrumSession broadcast_transaction".into()))
    }

    fn get_receive_address(&self, _addr_details: &Value) -> Result<Value, Error> {

        Err(Error::Generic("implementme: ElectrumSession get_receive_address".into()))
    }

    fn get_fee_estimates(&self) -> Result<Value, Error> {
        Err(Error::Generic("implementme: ElectrumSession get_fee_estimates_address".into()))
    }

    fn get_mnemonic_passphrase(&self, _password: &str) -> Result<String, Error> {
        Err(Error::Generic("implementme: ElectrumSession get_mnemonic_passphrase".into()))
    }

    fn get_settings(&self) -> Result<Value, Error> {
        Err(Error::Generic("implementme: ElectrumSession get_settings".into()))
    }

    fn change_settings(&mut self, _settings: &Value) -> Result<(), Error> {
        Err(Error::Generic("implementme: ElectrumSession change_settings".into()))
    }

    // fn register_user(&mut self, mnemonic: String) -> Result<(), Error> {
    //     Err(Error::Generic("implementme: ElectrumSession get_fee_estimates_address"))
    // }
}

fn native_activity_create() {
    #[cfg(target_os = "android")]
    android_logger::init_once(Config::default().with_min_level(Level::Info));
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "method", content = "params")]
#[serde(rename_all = "snake_case")]
enum IncomingRequest {
    Init(WGInit),
    Sync(WGSyncReq),
    ListTx(WGEmpty),
    Utxos(WGEmpty),
    Balance(WGEmpty),
    CreateTx(WGCreateTxReq),
    Sign(WGSignReq),
    Broadcast(WGTransaction),
    ValidateAddress(WGAddress),
    Poll(WGExtendedPubKey),
    GetAddress(WGExtendedPubKey),
    Fee(WGEstimateFeeReq),
    XpubFromXprv(WGExtendedPrivKey),
    GenerateXprv(WGEmpty),
}

fn call_interface(
    wallet_name: String,
    url: Option<String>,
    req: IncomingRequest,
) -> Result<String, Error> {
    if let IncomingRequest::Init(data) = req {
        unsafe {
            lib_init(data);
        };

        return Ok("{}".to_string());
    }

    let mut wallet = WalletCtx::new(wallet_name, url)?;

    match req {
        IncomingRequest::Sync(req) => Ok(serde_json::to_string(&(wallet.sync(req)?))?),
        IncomingRequest::ListTx(_) => Ok(serde_json::to_string(&(wallet.list_tx()?))?),
        IncomingRequest::Utxos(_) => Ok(serde_json::to_string(&(wallet.utxos()?))?),
        IncomingRequest::Balance(_) => Ok(serde_json::to_string(&(wallet.balance()?))?),
        IncomingRequest::CreateTx(req) => Ok(serde_json::to_string(&(wallet.create_tx(req)?))?),
        IncomingRequest::Sign(req) => Ok(serde_json::to_string(&(wallet.sign(req)?))?),
        IncomingRequest::Broadcast(req) => Ok(serde_json::to_string(&(wallet.broadcast(req)?))?),
        IncomingRequest::ValidateAddress(req) => {
            Ok(serde_json::to_string(&(wallet.validate_address(req)?))?)
        }
        IncomingRequest::Poll(req) => Ok(serde_json::to_string(&(wallet.poll(req)?))?),
        IncomingRequest::GetAddress(req) => Ok(serde_json::to_string(&(wallet.get_address(req)?))?),
        IncomingRequest::Fee(req) => Ok(serde_json::to_string(&(wallet.fee(req)?))?),
        IncomingRequest::XpubFromXprv(req) => {
            Ok(serde_json::to_string(&(wallet.xpub_from_xprv(req)?))?)
        }
        IncomingRequest::GenerateXprv(_) => Ok(serde_json::to_string(&(wallet.generate_xprv()?))?),

        IncomingRequest::Init(_) => unreachable!(),
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonErrorInt {
    pub code: i32,
    pub message: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct JsonErrorExt {
    pub error: JsonErrorInt,
}

// TODO: add optional extra data
fn make_error(code: i32, message: String) -> String {
    error!("code: {} message: {}", code, message);

    let error = JsonErrorInt {
        code,
        message,
    };
    let error_ext = JsonErrorExt {
        error,
    };

    serde_json::to_string(&error_ext).unwrap()
}

#[cfg(test)]
mod test {
    use crate::model::{
        WGAddress, WGAddressAmount, WGBalance, WGCreateTxReq, WGEstimateFeeReq, WGEstimateFeeRes,
        WGExtendedPrivKey, WGExtendedPubKey, WGInit, WGSignReq, WGSyncReq, WGTransaction, WGUTXO,
    };
    use bitcoin::blockdata::transaction::Transaction;
    use bitcoin::consensus::deserialize;
    use bitcoin::util::address::Address;
    use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
    use bitcoin::util::misc::hex_bytes;
    use serde_json;
    use std::str::FromStr;

    #[test]
    fn test_defaults() {
        let init = WGInit {
            path: "/tmp/".to_string(),
        };
        let json = serde_json::to_string_pretty(&init).unwrap();
        println!("WGInit {}", json);

        let xpub = ExtendedPubKey::from_str("tpubD6NzVbkrYhZ4Wc77iw2W3C5EfGsHkR6TXGoVwBSoUZjVj3hdZ4bNF8eskirtD98DKcNoT3gjKcmiBxpsZX1yV3aaN6rUaM7UhoRZ85kHqwY").unwrap();
        let wgsync_req = WGSyncReq {
            xpub,
            url: Some("scamcoinbot.com:1880".to_string()),
        };
        let json = serde_json::to_string_pretty(&wgsync_req).unwrap();
        println!("WGSyncReq {}", json);

        let hex_tx = hex_bytes("0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000").unwrap();
        let tx: Result<Transaction, _> = deserialize(&hex_tx);
        let transaction = tx.unwrap();
        let wgtransaction = WGTransaction {
            transaction: transaction.clone(),
            txid: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            timestamp: 0u64,
            received: 0u64,
            sent: 0u64,
            height: Some(0u32),
            is_mine: vec![true],
        };
        let json = serde_json::to_string_pretty(&wgtransaction).unwrap();
        println!("WGTransaction {}", json);

        let wgutxo = WGUTXO::default();
        let json = serde_json::to_string_pretty(&wgutxo).unwrap();
        println!("WGUTXO {}", json);

        let wgbalance = WGBalance::default();
        let json = serde_json::to_string_pretty(&wgbalance).unwrap();
        println!("WGBalance {}", json);

        let address = Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k").unwrap();
        let wgaddress = WGAddress {
            address,
        };
        let json = serde_json::to_string_pretty(&wgaddress).unwrap();
        println!("WGAddress {}", json);

        let address = Address::from_str("33iFwdLuRpW1uK1RTRqsoi8rR4NpDzk66k").unwrap();
        let wgaddressamount = WGAddressAmount {
            address,
            satoshi: 0u64,
        };
        let json = serde_json::to_string_pretty(&wgaddressamount).unwrap();
        println!("WGAddressAmount {}", json);

        let wgestimate_fee_req = WGEstimateFeeReq::default();
        let json = serde_json::to_string_pretty(&wgestimate_fee_req).unwrap();
        println!("WGEstimateFeeReq {}", json);

        let wgestimate_fee_res = WGEstimateFeeRes::default();
        let json = serde_json::to_string_pretty(&wgestimate_fee_res).unwrap();
        println!("WGEstimateFeeRes {}", json);

        let mut wgutxo_vec = vec![];
        wgutxo_vec.push(wgutxo);
        let mut wgaddressamount_vec = vec![];
        wgaddressamount_vec.push(wgaddressamount);
        let wgcreate_tx_req = WGCreateTxReq {
            utxo: Some(wgutxo_vec),
            addresses_amounts: wgaddressamount_vec,
            fee_perkb: 0.0001f32,
            xpub: xpub,
        };
        let json = serde_json::to_string_pretty(&wgcreate_tx_req).unwrap();
        println!("WGCreateTxReq {}", json);

        let derivation_path = DerivationPath::from_str("m/0'");
        let mut derivationpath_vec = vec![];
        derivationpath_vec.push(derivation_path.unwrap());

        let xprv = ExtendedPrivKey::from_str("tprv8ZgxMBicQKsPd7Uf69XL1XwhmjHopUGep8GuEiJDZmbQz6o58LninorQAfcKZWARbtRtfnLcJ5MQ2AtHcQJCCRUcMRvmDUjyEmNUWwx8UbK").unwrap();
        let wgsign_req = WGSignReq {
            xprv,
            transaction,
            derivation_paths: derivationpath_vec,
        };
        let json = serde_json::to_string_pretty(&wgsign_req).unwrap();
        println!("WGSignReq {}", json);

        let wgxprv = WGExtendedPrivKey {
            xprv,
        };
        let json = serde_json::to_string_pretty(&wgxprv).unwrap();
        println!("WGExtendedPrivKey {}", json);

        let wgxpub = WGExtendedPubKey {
            xpub,
        };
        let json = serde_json::to_string_pretty(&wgxpub).unwrap();
        println!("WGExtendedPubKey {}", json);
    }
}
