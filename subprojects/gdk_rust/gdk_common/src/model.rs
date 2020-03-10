use bitcoin::blockdata::transaction::Transaction;
use bitcoin::util::address::Address;
use bitcoin::Network;
use core::mem::transmute;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

use std::fmt;
use std::fmt::Display;
use chrono::{DateTime, NaiveDateTime, Utc};

#[derive(Debug)]
#[repr(C)]
pub struct GDKRUST_json(pub serde_json::Value);

impl GDKRUST_json {
    pub fn new(data: serde_json::Value) -> *const GDKRUST_json {
        unsafe { transmute(Box::new(GDKRUST_json(data))) }
    }
}

pub struct BalanceResult(pub HashMap<String, u64>);

impl BalanceResult {
    pub fn new_btc(satoshi: u64) -> Self {
        let mut map = HashMap::new();
        map.insert("btc".to_string(), satoshi);
        BalanceResult(map)
    }
}

// =========== v exchange rate stuff v ===========

// TODO use these types from bitcoin-exchange-rates lib once it's in there

#[derive(Debug, Clone, PartialEq)]
pub struct ExchangeRate {
    pub currency: String,
    pub rate: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct ExchangeRateError {
    pub message: String,
    pub error: ExchangeRateErrorType,
}

impl Display for ExchangeRateError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

impl Display for ExchangeRateErrorType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ExchangeRateOk {
    NoBackends, // this probably should't be a hard error,
    // so we label it an Ok result
    RateOk(ExchangeRate),
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub enum ExchangeRateErrorType {
    FetchError,
    ParseError,
}

pub type ExchangeRateRes = Result<ExchangeRateOk, ExchangeRateError>;

impl ExchangeRateOk {
    pub fn ok(currency: String, rate: f64) -> ExchangeRateOk {
        ExchangeRateOk::RateOk(ExchangeRate {
            currency,
            rate,
        })
    }

    pub fn no_backends() -> ExchangeRateOk {
        ExchangeRateOk::NoBackends
    }
}

// =========== ^ exchange rate stuff ^ ===========

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddressAmount {
    pub address: Address,
    pub satoshi: u64,
    pub asset_tag: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateTransaction {
    pub addressees: Vec<AddressAmount>,
    pub fee_rate: Option<f32>,
    pub subaccount: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionMeta {
    #[serde(flatten)]
    pub create_transaction: Option<CreateTransaction>,
    #[serde(rename = "transaction_object")]
    pub transaction: Transaction,
    #[serde(rename = "transaction")]
    pub hex: String,
    pub txid: String,
    pub height: Option<u32>,
    pub timestamp: Option<u32>,
    pub created_at: Option<String>, // yyyy-MM-dd HH:mm:ss
    pub received: Option<u64>,
    pub sent: Option<u64>,
    pub error: String,
    pub addressees_have_assets: bool,
    pub is_sweep: bool,
    pub satoshi: u64, // TODO it looks a copy of create_transaction.addressees[0].amount
    pub fee: u64,
    pub network: Option<Network>,
}

impl From<Transaction> for TransactionMeta {
    fn from(transaction: Transaction) -> Self {
        let txid = transaction.txid().to_string();
        let hex = hex::encode(&bitcoin::consensus::serialize(&transaction));
        TransactionMeta {
            create_transaction: None,
            transaction,
            height: None,
            created_at: None,
            timestamp: None,
            txid,
            hex,
            received: None,
            sent: None,
            error: "".to_string(),
            addressees_have_assets: false,
            is_sweep: false,
            satoshi: 0,
            fee: 0,
            network: None,
        }
    }
}

impl TransactionMeta {
    pub fn new(transaction: Transaction, height: Option<u32>, timestamp: Option<u32>, received: u64, sent: u64, network: Network) -> Self {
        let mut wgtx: TransactionMeta = transaction.into();
        let created_at = timestamp.map(|ts| {
            let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(ts as i64, 0), Utc);
            format!("{}", dt.format("%Y-%m-%d %H:%M:%S"))
        });
        wgtx.height = height;
        wgtx.timestamp = timestamp;
        wgtx.created_at = created_at;
        wgtx.sent = Some(sent);
        wgtx.received = Some(received);
        wgtx.network = Some(network);
        wgtx
    }
}

pub struct AddressIO {
    pub address: String,
    pub address_type: bitcoin::util::address::AddressType,
    pub addressee: String,
    pub is_output: String,
    pub is_relevant: String,
    pub is_spent: String,
    pub pointer: u32,
    pub pt_idx: u32,
    pub satoshi: i64,
    pub script_type: u32,
    pub subaccount: u32,
    pub subtype: u32,
}

pub struct TxListItem {
    pub block_height: u32,
    pub created_at: String,
    pub type_: String,
    pub memo: String,
    pub txhash: String,
    pub transaction: Vec<u8>,
    pub satoshi: BalanceResult,
    pub rbf_optin: bool,
    pub cap_cpfp: bool,
    pub can_rbf: bool,
    pub has_payment_request: bool,
    pub server_signed: bool,
    pub user_signed: bool,
    pub instant: bool,
    pub fee: u64,
    pub fee_rate: f64,
    pub addresses: Vec<String>,
    pub addressees: Vec<String>, // notice the extra "e" -- its intentional
    pub inputs: Vec<AddressIO>,  // tx.input.iter().map(format_gdk_input).collect(),
    pub outputs: Vec<AddressIO>, //tx.output.iter().map(format_gdk_output).collect(),
    pub transaction_size: usize,
    pub transaction_vsize: usize,
    pub transaction_weight: usize,
}

pub struct Subaccount {
    pub type_: String,
    pub name: String,
    pub has_transactions: bool,
    pub satoshi: BalanceResult,
}

// This one is simple enough to derive a serializer
#[derive(Serialize, Debug)]
pub struct FeeEstimate(pub u64);
pub struct AddressResult(pub String);
pub struct TxsResult(pub Vec<TxListItem>);
