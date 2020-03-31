#![allow(dead_code)] // TODO remove

#[macro_use]
extern crate serde_json;

use log::{debug, error, info, warn};

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
use crate::interface::{ElectrumUrl, WalletCtx};
use crate::model::*;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::Transaction;
pub use electrum_client::client::{ElectrumPlaintextStream, ElectrumSslStream};

use gdk_common::be::*;
use gdk_common::mnemonic::Mnemonic;
use gdk_common::model::*;
use gdk_common::network::Network;
use gdk_common::password::Password;
use gdk_common::session::Session;
use gdk_common::wally::{self, asset_blinding_key_from_seed};

use bitcoin::BitcoinHash;
use std::io::{Read, Write};
use std::str::FromStr;

pub struct ElectrumSession<S: Read + Write> {
    pub db_root: String,
    pub network: Network,
    pub client: electrum_client::Client<S>,
    pub wallet: Option<WalletCtx>,
    pub notify:
        Option<(extern "C" fn(*const libc::c_void, *const GDKRUST_json), *const libc::c_void)>,
}

fn determine_electrum_url(url: &Option<String>, tls: &Option<bool>) -> Result<ElectrumUrl, Error> {
    let url = url.as_ref().ok_or_else(|| Error::Generic("network url is missing".into()))?;
    if url == "" {
        return Err(Error::Generic("network url is empty".into()))?;
    }

    if tls.unwrap_or(false) {
        Ok(ElectrumUrl::Tls(url.into()))
    } else {
        Ok(ElectrumUrl::Plaintext(url.into()))
    }
}

fn determine_electrum_url_from_val(value: &Value) -> Result<ElectrumUrl, Error> {
    let url = value["url"].as_str().map(|x| x.to_string());
    let tls = value["tls"].as_bool();

    determine_electrum_url(&url, &tls)
}

pub fn determine_electrum_url_from_net(network: &Network) -> Result<ElectrumUrl, Error> {
    determine_electrum_url(&network.url, &network.tls)
}

impl ElectrumSession<ElectrumSslStream> {
    pub fn new_tls_session(network: Network, db_root: &str) -> Result<Self, Error> {
        let url: &str = network
            .url
            .as_ref()
            .ok_or_else(|| Error::Generic("network url missing in new_tls_session".into()))?;
        let validate = network.validate_domain.unwrap_or(true);
        let client = electrum_client::Client::new_ssl(url, validate)?;
        Ok(Self::create_session(network, db_root, client))
    }
}

impl ElectrumSession<ElectrumPlaintextStream> {
    pub fn new_plaintext_session(network: Network, db_root: &str) -> Result<Self, Error> {
        let url: &str = network
            .url
            .as_ref()
            .ok_or_else(|| Error::Generic("network url missing in new_plaintext_session".into()))?;
        let client = electrum_client::Client::new(url)?;
        Ok(Self::create_session(network, db_root, client))
    }
}

impl<S: Read + Write> ElectrumSession<S> {
    pub fn create_session(
        network: Network,
        db_root: &str,
        client: electrum_client::Client<S>,
    ) -> Self {
        Self {
            db_root: db_root.to_string(),
            client,
            network,
            wallet: None,
            notify: None,
        }
    }

    pub fn get_wallet(&self) -> Result<&WalletCtx, Error> {
        self.wallet.as_ref().ok_or_else(|| Error::Generic("wallet not initialized".into()))
    }

    pub fn get_wallet_mut(&mut self) -> Result<&mut WalletCtx, Error> {
        self.wallet.as_mut().ok_or_else(|| Error::Generic("wallet not initialized".into()))
    }

    fn notify(&self, data: Value) {
        debug!("push notification: {:?}", data);
        if let Some((handler, self_context)) = self.notify {
            handler(self_context, GDKRUST_json::new(data));
        } else {
            warn!("no registered handler to receive notification");
        }
    }

    fn try_get_fee_estimates(&mut self) -> Result<Vec<FeeEstimate>, Error> {
        let blocks: Vec<usize> = (1..25).collect();
        let mut estimates: Vec<FeeEstimate> = self
            .client
            .batch_estimate_fee(blocks)?
            .iter()
            .map(|e| FeeEstimate((*e * 100_000_000.0) as u64))
            .collect();
        let relay_fee = self.client.relay_fee()?;
        estimates.insert(0, FeeEstimate((relay_fee * 100_000_000.0) as u64));
        Ok(estimates)
    }
}

fn make_txlist_item(tx: &TransactionMeta) -> TxListItem {
    let type_ = "incoming".to_string(); // TODO, compute
    let len = tx.hex.len() / 2;
    let fee_rate = (tx.fee as f64 / len as f64) as u64;
    let addressees = vec![];

    TxListItem {
        block_height: tx.height.unwrap_or_default(),
        created_at: tx.created_at.clone(),
        type_,
        memo: "".into(), // TODO: TransactionMeta -> TxListItem memo
        txhash: tx.txid.clone(),
        transaction_size: len,
        transaction: tx.hex.clone(), // FIXME
        satoshi: tx.satoshi.clone(),
        rbf_optin: false,           // TODO: TransactionMeta -> TxListItem rbf_optin
        cap_cpfp: false,            // TODO: TransactionMeta -> TxListItem cap_cpfp
        can_rbf: false,             // TODO: TransactionMeta -> TxListItem can_rbf
        has_payment_request: false, // TODO: TransactionMeta -> TxListItem has_payment_request
        server_signed: false,       // TODO: TransactionMeta -> TxListItem server_signed
        user_signed: true,
        instant: false,
        fee: tx.fee,
        fee_rate,
        addresses: vec![],
        addressees,              // notice the extra "e" -- its intentional
        inputs: vec![],          // tx.input.iter().map(format_gdk_input).collect(),
        outputs: vec![],         //tx.output.iter().map(format_gdk_output).collect(),
        transaction_vsize: len,  //TODO
        transaction_weight: len, //TODO
    }
}

fn abs_diff(a: u64, b: u64) -> (u64, String) {
    if a > b {
        (a - b, "incoming".to_string())
    } else {
        (b - a, "outgoing".to_string())
    }
}

impl<S: Read + Write> Session<Error> for ElectrumSession<S> {
    // type Value = ElectrumSession;

    fn destroy_session(&mut self) -> Result<(), Error> {
        self.wallet = None;
        Ok(())
    }

    fn poll_session(&self) -> Result<(), Error> {
        Err(Error::Generic("implementme: ElectrumSession poll_session".into()))
    }

    fn connect(&mut self, net_params: &Value) -> Result<(), Error> {
        if self.db_root == "" {
            self.db_root =
                net_params["state_dir"].as_str().map(|x| x.to_string()).unwrap_or("".into());
            debug!("setting db_root to {:?}", self.db_root);
        }

        info!("connect {:?}", self.network);

        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        //TODO call db flush
        Err(Error::Generic("implementme: ElectrumSession connect".into()))
    }

    fn login(&mut self, mnemonic: &Mnemonic, password: Option<Password>) -> Result<(), Error> {
        debug!("login {:#?}", self.network);

        // TODO: passphrase?

        let mnem_str = mnemonic.clone().get_mnemonic_str();
        let seed = wally::bip39_mnemonic_to_seed(
            &mnem_str,
            &password.map(|p| p.get_password_str()).unwrap_or_default(),
        )
        .ok_or(Error::InvalidMnemonic)?;
        let secp = Secp256k1::new();
        let xprv =
            ExtendedPrivKey::new_master(bitcoin::network::constants::Network::Testnet, &seed)?;

        // m / purpose' / coin_type' / account' / change / address_index
        // coin_type = 0 bitcoin, 1 testnet, 1776 liquid bitcoin
        let path = DerivationPath::from_str("m/44'/0'/0'")?;
        let xprv = xprv.derive_priv(&secp, &path)?;
        let xpub = ExtendedPubKey::from_private(&secp, &xprv);

        let wallet_desc = format!("{}{:?}", xpub, self.network);
        let wallet_id = hex::encode(sha256::Hash::hash(wallet_desc.as_bytes()));

        let master_blinding = if self.network.liquid {
            Some(asset_blinding_key_from_seed(&seed))
        } else {
            None
        };

        let wallet = WalletCtx::new(
            &self.db_root,
            wallet_id,
            mnemonic.clone(),
            self.network.clone(),
            xprv,
            xpub,
            master_blinding,
        )?;

        wallet.sync(&mut self.client)?;
        self.wallet = Some(wallet);
        let block = self.client.block_headers_subscribe()?;
        self.notify(json!({"block":{"block_hash":block.header.bitcoin_hash(),"block_height": block.height },"event":"block"}));

        Ok(())
    }

    fn get_receive_address(&self, _addr_details: &Value) -> Result<AddressResult, Error> {
        let w = self.get_wallet()?;
        let a = w.get_address()?;
        Ok(AddressResult(a.address.to_string()))
    }

    fn get_subaccounts(&self) -> Result<Vec<Subaccount>, Error> {
        // TODO configurable confs?
        let index = 0;
        let confs = 0;
        let subaccount_fake = self.get_subaccount(index, confs)?;

        Ok(vec![subaccount_fake])
    }

    fn get_subaccount(&self, index: u32, num_confs: u32) -> Result<Subaccount, Error> {
        let balance = self.get_balance(num_confs, Some(index))?;
        let txs = self.get_transactions(&json!({}))?;

        let subaccounts_fake = Subaccount {
            type_: "electrum".into(),
            name: "Single sig wallet".into(),
            has_transactions: !txs.0.is_empty(),
            satoshi: balance,
        };

        Ok(subaccounts_fake)
    }

    fn get_transactions(&self, _details: &Value) -> Result<TxsResult, Error> {
        let txs = self.get_wallet()?.list_tx()?.iter().map(make_txlist_item).collect();

        Ok(TxsResult(txs))
    }

    fn get_transaction_details(&self, _txid: &str) -> Result<Value, Error> {
        Err(Error::Generic("implementme: ElectrumSession get_transaction_details".into()))
    }

    fn get_balance(&self, _num_confs: u32, _subaccount: Option<u32>) -> Result<Balances, Error> {
        self.get_wallet()?.balance()
    }

    fn set_transaction_memo(&self, _txid: &str, _memo: &str, _memo_type: u32) -> Result<(), Error> {
        Err(Error::Generic("implementme: ElectrumSession set_transaction_memo".into()))
    }

    fn create_transaction(&self, tx_req: &CreateTransaction) -> Result<TransactionMeta, Error> {
        debug!("electrum create_transaction {:#?}", tx_req);
        self.get_wallet()?.create_tx(tx_req)
    }

    fn sign_transaction(&self, create_tx: &TransactionMeta) -> Result<TransactionMeta, Error> {
        debug!("electrum sign_transaction {:#?}", create_tx);
        self.get_wallet()?.sign(create_tx)
    }

    fn send_transaction(&mut self, tx: &TransactionMeta) -> Result<String, Error> {
        debug!("electrum send_transaction {:#?}", tx);
        match &tx.transaction {
            BETransaction::Bitcoin(tx) => self.client.transaction_broadcast(&tx)?,
            BETransaction::Elements(_tx) => {
                return Err(Error::Generic("implementme: send liquid transaction".into()))
            }
        };
        Ok(format!("{}", tx.txid))
    }

    fn broadcast_transaction(&mut self, tx_hex: &str) -> Result<String, Error> {
        debug!("broadcast_transaction {:#?}", tx_hex);
        let tx: Transaction = deserialize(&hex::decode(tx_hex)?)?;
        self.client.transaction_broadcast(&tx)?;
        Ok(format!("{}", tx.txid()))
    }

    /// The estimates are returned as an array of 25 elements. Each element is
    /// an integer representing the fee estimate expressed as satoshi per 1000
    /// bytes. The first element is the minimum relay fee as returned by the
    /// network, while the remaining elements are the current estimates to use
    /// for a transaction to confirm from 1 to 24 blocks.
    fn get_fee_estimates(&mut self) -> Result<Vec<FeeEstimate>, Error> {
        Ok(self.try_get_fee_estimates().unwrap_or(vec![FeeEstimate(1000u64); 25] )) //TODO better implement default
    }

    fn get_mnemonic(&self) -> Result<&Mnemonic, Error> {
        self.get_wallet().map(|wallet| wallet.get_mnemonic())
    }

    fn get_settings(&self) -> Result<Value, Error> {
        let settings = self.get_wallet()?.get_settings()?;
        Ok(serde_json::to_value(settings)?)
    }

    fn change_settings(&mut self, settings: &Settings) -> Result<(), Error> {
        self.get_wallet()?.change_settings(settings)
    }

    fn get_available_currencies(&self) -> Result<Value, Error> {
        Ok(json!({ "all": [ "USD" ], "per_exchange": { "BITFINEX": [ "USD" ] } }))
        // TODO implement
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
    CreateTx(TransactionMeta),
    Sign(WGSignReq),
    Broadcast(TransactionMeta),
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
        WGExtendedPrivKey, WGExtendedPubKey, WGInit, WGSignReq, WGSyncReq, TransactionMeta, WGUTXO,
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
        let wgtransaction = TransactionMeta {
            transaction: transaction.clone(),
            txid: "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
            timestamp: 0u64,
            received: 0u64,
            sent: 0u64,
            height: Some(0u32),
            is_mine: vec![true],
        };
        let json = serde_json::to_string_pretty(&wgtransaction).unwrap();
        println!("TransactionMeta {}", json);

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