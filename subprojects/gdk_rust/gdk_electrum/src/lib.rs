#![allow(dead_code)] // TODO remove

#[macro_use]
extern crate serde_json;

use log::error;

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(target_os = "android")]
use android_logger::Config;
#[cfg(target_os = "android")]
use log::Level;

pub mod db;
pub mod error;
pub mod interface;
pub mod model;
pub mod tools;

use crate::error::Error;
use crate::interface::WalletCtx;
use crate::model::*;

use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin_hashes::sha256;
use bitcoin_hashes::Hash;
use gdk_common::network::Network;
use gdk_common::wally::{self, asset_blinding_key_from_seed};
use gdk_common::*;

use std::str::FromStr;

pub struct ElectrumSession {
    pub url: String,
    pub validate_domain: bool,
    pub db_root: Option<String>,
    pub network: Network,
    pub mnemonic: Option<String>,
    pub wallet: Option<WalletCtx>,
}

impl ElectrumSession {
    pub fn create_session(network: Network) -> Result<ElectrumSession, Error> {
        match network.url {
            Some(_) => Ok(ElectrumSession {
                db_root: None,
                url: network.url.clone().unwrap_or("".to_string()),
                validate_domain: network.validate_electrum_domain.unwrap_or(true),
                network,
                mnemonic: None,
                wallet: None,
            }),
            None => Err(Error::Generic(
                "ElectrumSession create_session without electrum server url".into(),
            )),
        }
    }

    pub fn get_wallet(&self) -> Result<&WalletCtx, Error> {
        self.wallet.as_ref().ok_or_else(|| Error::Generic("wallet not initialized".into()))
    }

    pub fn get_wallet_mut(&mut self) -> Result<&mut WalletCtx, Error> {
        self.wallet.as_mut().ok_or_else(|| Error::Generic("wallet not initialized".into()))
    }
}

fn make_txlist_item(tx: &WGTransaction) -> TxListItem {
    TxListItem {
        block_height: tx.height.unwrap_or_default(),
        created_at: tx.timestamp,
        type_: "type".into(), // TODO: WGTransaction -> TxListItem type
        memo: "memo".into(),  // TODO: WGTransaction -> TxListItem memo
        txhash: tx.txid.clone(),
        transaction: bitcoin::consensus::encode::serialize(&tx.transaction),
        satoshi: BalanceResult((tx.received as i64) - (tx.sent as i64)),
        rbf_optin: false,           // TODO: WGTransaction -> TxListItem rbf_optin
        cap_cpfp: false,            // TODO: WGTransaction -> TxListItem cap_cpfp
        can_rbf: false,             // TODO: WGTransaction -> TxListItem can_rbf
        has_payment_request: false, // TODO: WGTransaction -> TxListItem has_payment_request
        server_signed: false,       // TODO: WGTransaction -> TxListItem server_signed
        user_signed: true,
        instant: false,
        fee: 0,        // TODO: WGTransaction -> TxListItem fee
        fee_rate: 0.0, // TODO: WGTransaction -> TxListItem fee_rate
        addresses: vec![],
        addressees: vec![], // notice the extra "e" -- its intentional
        inputs: vec![],     // tx.input.iter().map(format_gdk_input).collect(),
        outputs: vec![],    //tx.output.iter().map(format_gdk_output).collect(),
    }
}

impl Session<Error> for ElectrumSession {
    // type Value = ElectrumSession;

    fn destroy_session(&mut self) -> Result<(), Error> {
        self.wallet = None;
        Ok(())
    }

    fn poll_session(&self) -> Result<(), Error> {
        Err(Error::Generic("implementme: ElectrumSession poll_session".into()))
    }

    fn connect(&mut self, net_params: &Value) -> Result<(), Error> {
        if let None = self.db_root.as_ref() {
            self.db_root = net_params["state_dir"].as_str().map(|x| x.to_string());
            println!("setting db_root to {:?}", self.db_root);
        }

        // url param on connect can override network electrum_url
        let url = net_params["url"].as_str();
        if let Some(v) = url.as_ref() {
            self.url = v.to_string();
        }

        if self.url == "" {
            return Err(Error::Generic("connect: no url set".into()));
        }

        println!("connect {:?}", self.network);

        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        //TODO call db flush
        Err(Error::Generic("implementme: ElectrumSession connect".into()))
    }

    fn login(&mut self, mnemonic: String, password: Option<String>) -> Result<(), Error> {
        println!("login {:#?}", self.network);

        //let url = self.network.electrum_url.unwrap(); //should be safe, since Some is checked in create_session
        let db_root =
            self.db_root.as_ref().ok_or(Error::Generic("login: db_root not set".into()))?;

        // TODO: passphrase?
        let seed = wally::bip39_mnemonic_to_seed(&mnemonic, &password.unwrap_or_default())
            .ok_or(Error::InvalidMnemonic)?;
        let secp = Secp256k1::new();
        let xprv =
            ExtendedPrivKey::new_master(bitcoin::network::constants::Network::Testnet, &seed)?;

        // m / purpose' / coin_type' / account' / change / address_index
        // coin_type = 0 bitcoin, 1 testnet, 1776 liquid bitcoin
        let path = DerivationPath::from_str("m/44'/0'/0'")?;
        let xprv = xprv.derive_priv(&secp, &path)?;
        let xpub = ExtendedPubKey::from_private(&secp, &xprv);

        let wallet_name = hex::encode(sha256::Hash::hash(mnemonic.as_bytes()));

        let master_blinding = if self.network.liquid {
            Some(asset_blinding_key_from_seed(&seed))
        } else {
            None
        };

        let mut wallet: WalletCtx = WalletCtx::new(
            &db_root,
            wallet_name,
            &self.url,
            self.network.clone(),
            xpub,
            master_blinding,
        )?;
        wallet.sync()?;
        self.wallet = Some(wallet);

        Ok(())
    }

    fn get_receive_address(&self, _addr_details: &Value) -> Result<AddressResult, Error> {
        let a1 = self.wallet.as_ref().unwrap().get_address()?;
        println!("a1: {:?} ", a1);
        Ok(AddressResult(a1.address.to_string()))
    }

    fn get_subaccounts(&self) -> Result<Value, Error> {
        // Err(Error::Generic("implementme: ElectrumSession get_subaccounts".into()))
        let subaccounts_fake = json!([{
        "type": "core",
        "pointer": 0,
        "required_ca": 0,
        "receiving_id": "",
        "name": "fake account",
        "has_transactions": true,
        "satoshi": 1000 }]);

        Ok(subaccounts_fake)
    }

    fn get_subaccount(&self, _index: u32) -> Result<Value, Error> {
        Err(Error::Generic("implementme: ElectrumSession get_subaccount".into()))
    }

    fn get_transactions(&self, _details: &Value) -> Result<TxsResult, Error> {
        let txs = self.get_wallet()?.list_tx()?.iter().map(make_txlist_item).collect();

        Ok(TxsResult(txs))
    }

    fn get_transaction_details(&self, _txid: &str) -> Result<Value, Error> {
        Err(Error::Generic("implementme: ElectrumSession get_transaction_details".into()))
    }

    fn get_balance(&self, _details: &Value) -> Result<i64, Error> {
        self.get_wallet()?.balance()
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

    fn get_fee_estimates(&mut self) -> Result<Vec<FeeEstimate>, Error> {
        // TODO: can batch request many estimates like rpc?
        let wg_estimate = self.get_wallet_mut()?.fee(WGEstimateFeeReq {
            nblocks: 1,
        })?;
        let fee_estimate = wg_estimate.into();
        Ok(vec![fee_estimate])
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
    ListTx(WGEmpty),
    Utxos(WGEmpty),
    Balance(WGEmpty),
    CreateTx(WGCreateTxReq),
    Sign(WGSignReq),
    Broadcast(WGTransaction),
    Poll(WGExtendedPubKey),
    GetAddress(WGExtendedPubKey),
    Fee(WGEstimateFeeReq),
    XpubFromXprv(WGExtendedPrivKey),
    GenerateXprv(WGEmpty),
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
    /*use crate::model::{
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
    }*/
}
