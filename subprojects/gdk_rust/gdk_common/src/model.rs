use crate::be::{AssetId, BETransaction};
use bitcoin::Network;
use core::mem::transmute;
use serde_derive::{Deserialize, Serialize};
use std::collections::HashMap;

use chrono::{DateTime, NaiveDateTime, Utc};
use std::convert::TryInto;
use std::fmt;
use std::fmt::Display;
use std::time::{SystemTime, UNIX_EPOCH};
use serde_json::Value;

#[derive(Debug)]
#[repr(C)]
pub struct GDKRUST_json(pub serde_json::Value);

impl GDKRUST_json {
    pub fn new(data: serde_json::Value) -> *const GDKRUST_json {
        unsafe { transmute(Box::new(GDKRUST_json(data))) }
    }
}

pub type Balances = HashMap<String, i64>;

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

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct AddressAmount {
    pub address: String, // could be bitcoin or elements
    pub satoshi: u64,
    pub asset_tag: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct BlockNotification {
    //pub block_hash: bitcoin::BlockHash,
    pub block_height: u32,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionNotification {
    pub transaction_hash: bitcoin::Txid,
}

#[derive(Debug)]
pub enum Notification {
    Block(BlockNotification),
    Transaction(TransactionNotification),
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CreateTransaction {
    pub addressees: Vec<AddressAmount>,
    pub fee_rate: Option<u64>, // in satoshi/kbyte
    pub subaccount: Option<u32>,
    pub send_all: Option<bool>,
    pub previous_transaction: HashMap<String, Value>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GetTransactionsOpt {
    pub first: usize,
    pub count: usize,
    pub subaccount: usize,
    pub num_confs: Option<usize>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionMeta {
    #[serde(flatten)]
    pub create_transaction: Option<CreateTransaction>,
    #[serde(rename = "transaction")]
    pub hex: String,
    pub txid: String,
    pub height: Option<u32>,
    pub timestamp: u32, // for confirmed tx is block time for unconfirmed is when created
    pub created_at: String, // yyyy-MM-dd HH:mm:ss of timestamp
    pub error: String,
    pub addressees_have_assets: bool,
    pub is_sweep: bool,
    pub satoshi: Balances,
    pub fee: u64,
    pub network: Option<Network>,
    #[serde(rename = "type")]
    pub type_: String, // incoming or outgoing
    pub changes_used: Option<u32>,
    pub rbf_optin: bool,
    pub user_signed: bool,
}

impl From<BETransaction> for TransactionMeta {
    fn from(transaction: BETransaction) -> Self {
        let txid = transaction.txid().to_string();
        let hex = hex::encode(&transaction.serialize());
        let timestamp = now();
        let rbf_optin = transaction.rbf_optin();

        TransactionMeta {
            create_transaction: None,
            height: None,
            created_at: format(timestamp),
            timestamp,
            txid,
            hex,
            error: "".to_string(),
            addressees_have_assets: false,
            is_sweep: false,
            satoshi: HashMap::new(),
            fee: 0,
            network: None,
            type_: "unknown".to_string(),
            changes_used: None,
            user_signed: false,
            rbf_optin,
        }
    }
}

impl TransactionMeta {
    pub fn new(
        transaction: BETransaction,
        height: Option<u32>,
        timestamp: Option<u32>,
        satoshi: Balances,
        fee: u64,
        network: Network,
        type_: String,
        create_transaction: CreateTransaction,
        user_signed: bool,
    ) -> Self {
        let mut wgtx: TransactionMeta = transaction.into();
        let timestamp = timestamp.unwrap_or_else(now);
        let created_at = format(timestamp);

        wgtx.create_transaction = Some(create_transaction);
        wgtx.height = height;
        wgtx.timestamp = timestamp;
        wgtx.created_at = created_at;
        wgtx.satoshi = satoshi;
        wgtx.network = Some(network);
        wgtx.fee = fee;
        wgtx.type_ = type_;
        wgtx.user_signed = user_signed;
        wgtx
    }
}

#[derive(Debug)]
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

// TODO remove TxListItem, make TransactionMeta compatible and automatically serialized
#[derive(Debug)]
pub struct TxListItem {
    pub block_height: u32,
    pub created_at: String,
    pub type_: String,
    pub memo: String,
    pub txhash: String,
    pub transaction: String,
    pub satoshi: Balances,
    pub rbf_optin: bool,
    pub cap_cpfp: bool,
    pub can_rbf: bool,
    pub has_payment_request: bool,
    pub server_signed: bool,
    pub user_signed: bool,
    pub instant: bool,
    pub fee: u64,
    pub fee_rate: u64,
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
    pub satoshi: Balances,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AddressPointer {
    pub address: String,
    pub pointer: u32,
}

// This one is simple enough to derive a serializer
#[derive(Serialize, Debug, Clone)]
pub struct FeeEstimate(pub u64);
pub struct TxsResult(pub Vec<TxListItem>);

/// Change to the model of Settings and Pricing structs could break old versions.
/// You can't remove fields, change fields type and if you add a new field, it must be Option<T>
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Settings {
    pub unit: String,
    pub required_num_blocks: u32,
    pub altimeout: u32,
    pub pricing: Pricing,
    pub sound: bool,
}

/// {"icons":true,"assets":false,"refresh":false}
#[derive(Serialize, Deserialize, Debug)]
pub struct RefreshAssets {
    pub icons: bool,
    pub assets: bool,
    pub refresh: bool,
}

/// see comment for struct Settings
#[derive(Serialize, Deserialize, Debug, PartialEq)]
pub struct Pricing {
    currency: String,
    exchange: String,
}

impl Default for Settings {
    fn default() -> Self {
        let pricing = Pricing {
            currency: "USD".to_string(),
            exchange: "BITFINEX".to_string(),
        };
        Settings {
            unit: "BTC".to_string(),
            required_num_blocks: 12,
            altimeout: 600,
            pricing,
            sound: false,
        }
    }
}

impl AddressAmount {
    pub fn asset(&self) -> Option<AssetId> {
        if let Some(asset_tag) = self.asset_tag.as_ref() {
            let vec = hex::decode(asset_tag).ok();
            if let Some(mut vec) = vec {
                vec.reverse();
                return (&vec[..]).try_into().ok();
            }
        }
        None
    }
}

fn now() -> u32 {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    since_the_epoch.as_secs() as u32
}

fn format(timestamp: u32) -> String {
    let dt = DateTime::<Utc>::from_utc(NaiveDateTime::from_timestamp(timestamp as i64, 0), Utc);
    format!("{}", dt.format("%Y-%m-%d %H:%M:%S"))
}
