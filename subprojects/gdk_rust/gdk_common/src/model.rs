use crate::be::{BEOutPoint, BEScript, BETransaction, BETransactionEntry, UTXOInfo, Utxos};
use crate::util::StringSerialized;
use bitcoin::Network;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::error::Error;
use crate::scripts::ScriptType;
use bitcoin::util::address::AddressType;
use bitcoin::util::bip32::{ChildNumber, DerivationPath};
use std::convert::TryFrom;
use std::fmt;
use std::fmt::Display;
use std::time::{SystemTime, UNIX_EPOCH};

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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
}

impl AddressAmount {
    pub fn asset_id(&self) -> Option<elements::issuance::AssetId> {
        self.asset_id.as_ref().and_then(|a| a.parse().ok())
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct LoginData {
    pub wallet_hash_id: String,
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Eq, Hash, Clone)]
#[serde(rename_all = "snake_case")]
pub enum UtxoStrategy {
    /// Add utxos until the addressees amounts and fees are covered
    Default,

    /// Uses all and only the utxos specified by the caller
    Manual,
}

impl Default for UtxoStrategy {
    fn default() -> Self {
        UtxoStrategy::Default
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct CreateTransaction {
    #[serde(default)]
    pub addressees: Vec<AddressAmount>,
    pub fee_rate: Option<u64>, // in satoshi/kbyte
    pub subaccount: u32,
    #[serde(default)]
    pub send_all: bool,
    #[serde(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_transaction: Option<TxListItem>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    #[serde(default)]
    pub utxos: GetUnspentOutputs,
    /// Minimum number of confirmations for coin selection
    #[serde(default)]
    pub num_confs: u32,
    #[serde(default)]
    pub confidential_utxos_only: bool,
    #[serde(default)]
    pub utxo_strategy: UtxoStrategy,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GetTransactionsOpt {
    pub first: usize,
    pub count: usize,
    pub subaccount: u32,
    pub num_confs: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GetBalanceOpt {
    pub subaccount: u32,
    pub num_confs: u32,
    #[serde(rename = "confidential")]
    pub confidential_utxos_only: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GetUnspentOpt {
    pub subaccount: u32,
    pub num_confs: Option<u32>,
    #[serde(rename = "confidential")]
    pub confidential_utxos_only: Option<bool>,
    pub all_coins: Option<bool>, // unused
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct GetAddressOpt {
    pub subaccount: u32,
    pub address_type: Option<String>, // unused
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateAccountOpt {
    pub subaccount: u32,
    pub name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct GetNextAccountOpt {
    #[serde(rename = "type")]
    pub script_type: ScriptType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RenameAccountOpt {
    pub subaccount: u32,
    pub new_name: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SPVVerifyTx {
    pub txid: String,
    pub height: u32,
    pub path: String,
    pub network: crate::network::Network,
    pub encryption_key: String,
    pub tor_proxy: Option<String>,
    pub headers_to_download: Option<usize>, // defaults to 2016, useful to set for testing
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum SPVVerifyResult {
    Unconfirmed,
    InProgress,
    Verified,
    NotVerified,
    NotLongest,
    Disabled,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionMeta {
    #[serde(flatten)]
    pub create_transaction: Option<CreateTransaction>,
    #[serde(rename = "transaction")]
    pub hex: String,
    #[serde(rename = "txhash")]
    pub txid: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    pub timestamp: u64, // in microseconds, for confirmed tx is block time for unconfirmed is when created or when list_tx happens
    pub error: String,
    pub addressees_have_assets: bool,
    pub addressees_read_only: bool,
    pub is_sweep: bool,
    pub satoshi: Balances,
    pub fee: u64,
    pub network: Option<Network>,
    #[serde(rename = "type")]
    pub type_: String, // incoming or outgoing
    pub changes_used: Option<u32>,
    pub rbf_optin: bool,
    pub user_signed: bool,
    pub spv_verified: SPVVerifyResult,
    #[serde(rename = "transaction_weight")]
    pub weight: usize,
    #[serde(rename = "transaction_vsize")]
    pub vsize: usize,
    #[serde(rename = "transaction_size")]
    pub size: usize,
}

impl From<BETransaction> for TransactionMeta {
    fn from(transaction: BETransaction) -> Self {
        let txid = transaction.txid().to_string();
        let hex = hex::encode(&transaction.serialize());
        let timestamp = now();
        let rbf_optin = transaction.rbf_optin();
        let weight = transaction.get_weight();

        TransactionMeta {
            create_transaction: None,
            height: None,
            timestamp,
            txid,
            hex,
            error: "".to_string(),
            addressees_have_assets: false,
            addressees_read_only: false,
            is_sweep: false,
            satoshi: HashMap::new(),
            fee: 0,
            network: None,
            type_: "unknown".to_string(),
            changes_used: None,
            user_signed: false,
            spv_verified: SPVVerifyResult::InProgress,
            rbf_optin,
            weight,
            vsize: (weight as f32 / 4.0) as usize,
            size: transaction.get_size(),
        }
    }
}
impl From<BETransactionEntry> for TransactionMeta {
    fn from(txe: BETransactionEntry) -> Self {
        let mut txm: TransactionMeta = txe.tx.into();
        txm.weight = txe.weight;
        txm.size = txe.size;
        txm
    }
}
impl TransactionMeta {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        transaction: impl Into<TransactionMeta>,
        height: Option<u32>,
        timestamp: Option<u64>,
        satoshi: Balances,
        fee: u64,
        network: Network,
        type_: String,
        create_transaction: CreateTransaction,
        user_signed: bool,
        spv_verified: SPVVerifyResult,
    ) -> Self {
        let mut wgtx: TransactionMeta = transaction.into();
        let timestamp = timestamp.unwrap_or_else(now);

        wgtx.create_transaction = Some(create_transaction);
        wgtx.height = height;
        wgtx.timestamp = timestamp;
        wgtx.satoshi = satoshi;
        wgtx.network = Some(network);
        wgtx.fee = fee;
        wgtx.type_ = type_;
        wgtx.user_signed = user_signed;
        wgtx.spv_verified = spv_verified;
        wgtx
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddressIO {
    pub address: String,
    pub address_type: StringSerialized<AddressType>,
    pub addressee: String,
    pub is_output: bool,
    // True if the corresponding scriptpubkey belongs to the account (not the wallet)
    pub is_relevant: bool,
    pub is_spent: bool,
    pub pointer: u32, // child_number in bip32 terminology
    pub pt_idx: u32,  // vout
    pub satoshi: u64,
    pub asset_id: String,
    pub assetblinder: String,
    pub amountblinder: String,
    pub script_type: u32,
    pub subaccount: u32,
    pub subtype: u32, // unused here, but used in gdk interface for CSV bucketing
}

impl Default for AddressIO {
    fn default() -> Self {
        AddressIO {
            address: "".into(),
            address_type: bitcoin::util::address::AddressType::P2sh.into(),
            addressee: "".into(),
            asset_id: "".into(),
            is_output: false,
            is_relevant: false,
            is_spent: false,
            pointer: 0,
            pt_idx: 0,
            satoshi: 0,
            script_type: 0,
            subaccount: 0,
            subtype: 0,
            assetblinder: "".into(),
            amountblinder: "".into(),
        }
    }
}

// TODO remove TxListItem, make TransactionMeta compatible and automatically serialized
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TxListItem {
    pub block_height: u32,
    pub created_at_ts: u64, // in microseconds
    #[serde(rename = "type")]
    pub type_: String,
    pub memo: String,
    pub txhash: String,
    pub transaction: String,
    #[serde(serialize_with = "serialize_tx_balances")]
    pub satoshi: Balances,
    pub rbf_optin: bool,
    pub can_cpfp: bool,
    pub can_rbf: bool,
    #[serde(skip)]
    pub has_payment_request: bool,
    pub server_signed: bool,
    pub user_signed: bool,
    #[serde(skip)]
    pub instant: bool,
    pub spv_verified: String,
    pub fee: u64,
    pub fee_rate: u64,
    pub addressees: Vec<String>, // receiver's addresses
    pub inputs: Vec<AddressIO>,  // tx.input.iter().map(format_gdk_input).collect(),
    pub outputs: Vec<AddressIO>, //tx.output.iter().map(format_gdk_output).collect(),
    pub transaction_size: usize,
    pub transaction_vsize: usize,
    pub transaction_weight: usize,
}

// Negative (sent) amounts are expected to be provided as positive numbers.
// The app side will use the 'type' field to try and determine whether its sent or received,
// which works in the typical case but not with transactions that has mixed types. To be fixed later.
fn serialize_tx_balances<S>(balances: &Balances, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let mut balances_abs = balances.clone();
    for (_, v) in balances_abs.iter_mut() {
        *v = v.abs();
    }
    balances_abs.serialize(serializer)
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AccountInfo {
    #[serde(rename = "pointer")]
    pub account_num: u32,
    #[serde(rename = "type")]
    pub script_type: ScriptType,
    #[serde(flatten)]
    pub settings: AccountSettings,
    pub required_ca: u32,     // unused, always 0
    pub receiving_id: String, // unused, always ""
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PinSetDetails {
    pub pin: String,
    pub mnemonic: String,
    pub device_id: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct PinGetDetails {
    pub salt: String,
    pub encrypted_data: String,
    pub pin_identifier: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct AddressPointer {
    pub address: String,
    pub pointer: u32, // child_number in bip32 terminology
}

// This one is simple enough to derive a serializer
#[derive(Serialize, Debug, Clone, Deserialize)]
pub struct FeeEstimate(pub u64);
pub struct TxsResult(pub Vec<TxListItem>);

/// Change to the model of Settings and Pricing structs could break old versions.
/// You can't remove fields, change fields type and if you add a new field, it must be Option<T>
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Settings {
    pub unit: String,
    pub required_num_blocks: u32,
    pub altimeout: u32,
    pub pricing: Pricing,
    pub sound: bool,
}

impl Settings {
    pub fn update(&mut self, json: &serde_json::Value) {
        if let Some(unit) = json.get("unit").and_then(|v| v.as_str()) {
            self.unit = unit.to_string();
        }
        if let Some(required_num_blocks) = json.get("required_num_blocks").and_then(|v| v.as_u64())
        {
            self.required_num_blocks = required_num_blocks as u32;
        }
        if let Some(altimeout) = json.get("altimeout").and_then(|v| v.as_u64()) {
            self.altimeout = altimeout as u32;
        }
        if let Some(pricing) =
            json.get("pricing").and_then(|v| serde_json::from_value(v.clone()).ok())
        {
            self.pricing = pricing;
        }
        if let Some(sound) = json.get("sound").and_then(|v| v.as_bool()) {
            self.sound = sound;
        }
    }
}

#[derive(Default, Serialize, Deserialize, Clone, Debug)]
pub struct AccountSettings {
    pub name: String,
    pub hidden: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct UpdateAccountOpt {
    pub subaccount: u32,
    pub name: Option<String>,
    pub hidden: Option<bool>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SetAccountHiddenOpt {
    pub subaccount: u32,
    pub hidden: bool,
}

/// {"icons":true,"assets":false,"refresh":false}
#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
pub struct RefreshAssets {
    pub icons: bool,
    pub assets: bool,
    pub refresh: bool,
}

impl Default for RefreshAssets {
    fn default() -> Self {
        Self {
            icons: false,
            assets: false,
            refresh: true,
        }
    }
}

impl RefreshAssets {
    pub fn new(icons: bool, assets: bool, refresh: bool) -> Self {
        RefreshAssets {
            icons,
            assets,
            refresh,
        }
    }
}

/// see comment for struct Settings
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
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
            altimeout: 5,
            pricing,
            sound: false,
        }
    }
}

fn now() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    // Realistic timestamps can be converted to u64
    u64::try_from(since_the_epoch.as_micros()).unwrap_or(u64::MAX)
}

impl SPVVerifyResult {
    pub fn as_i32(&self) -> i32 {
        match self {
            SPVVerifyResult::InProgress => 0,
            SPVVerifyResult::Verified => 1,
            SPVVerifyResult::NotVerified => 2,
            SPVVerifyResult::Disabled => 3,
            SPVVerifyResult::NotLongest => 4,
            SPVVerifyResult::Unconfirmed => 5,
        }
    }
}

impl Display for SPVVerifyResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SPVVerifyResult::InProgress => write!(f, "in_progress"),
            SPVVerifyResult::Verified => write!(f, "verified"),
            SPVVerifyResult::NotVerified => write!(f, "not_verified"),
            SPVVerifyResult::Disabled => write!(f, "disabled"),
            SPVVerifyResult::NotLongest => write!(f, "not_longest"),
            SPVVerifyResult::Unconfirmed => write!(f, "unconfirmed"),
        }
    }
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetUnspentOutputs(pub HashMap<String, Vec<UnspentOutput>>);

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnspentOutput {
    pub address_type: String,
    pub block_height: u32,
    pub pointer: u32,
    pub pt_idx: u32,
    pub satoshi: u64,
    pub subaccount: u32,
    pub txhash: String,
    /// `true` iff belongs to internal chain, i.e. is change
    pub is_internal: bool,
    pub confidential: bool,
    #[serde(skip)]
    pub derivation_path: DerivationPath,
    #[serde(skip)]
    pub scriptpubkey: BEScript,
}

impl UnspentOutput {
    pub fn new(outpoint: &BEOutPoint, info: &UTXOInfo) -> Self {
        let mut unspent_output = UnspentOutput::default();
        unspent_output.address_type = "p2shwpkh".to_string();
        unspent_output.satoshi = info.value;
        unspent_output.txhash = format!("{}", outpoint.txid());
        unspent_output.pt_idx = outpoint.vout();
        unspent_output.derivation_path = info.path.clone();
        unspent_output.scriptpubkey = info.script.clone();
        unspent_output.confidential = info.confidential;
        let mut iter = info.path.into_iter().rev();
        if let Some(&ChildNumber::Normal {
            index,
        }) = iter.next()
        {
            // last
            unspent_output.pointer = index;
        };
        if let Some(&ChildNumber::Normal {
            index,
        }) = iter.next()
        {
            // second-to-last
            unspent_output.is_internal = index == 1;
        };
        unspent_output.block_height = info.height.unwrap_or(0);
        unspent_output
    }
}

impl TryFrom<&GetUnspentOutputs> for Utxos {
    type Error = Error;

    fn try_from(unspent_outputs: &GetUnspentOutputs) -> Result<Self, Error> {
        let mut utxos = vec![];
        for (asset, v) in unspent_outputs.0.iter() {
            for e in v {
                let height = match e.block_height {
                    0 => None,
                    n => Some(n),
                };
                let (outpoint, utxo_info) = match &asset[..] {
                    "btc" => (
                        BEOutPoint::new_bitcoin(e.txhash.parse()?, e.pt_idx),
                        UTXOInfo::new_bitcoin(
                            e.satoshi,
                            e.scriptpubkey.clone().into(),
                            height,
                            e.derivation_path.clone(),
                        ),
                    ),
                    _ => (
                        BEOutPoint::new_elements(e.txhash.parse()?, e.pt_idx),
                        UTXOInfo::new_elements(
                            asset.parse()?,
                            e.satoshi,
                            e.scriptpubkey.clone().into(),
                            height,
                            e.derivation_path.clone(),
                            e.confidential,
                        ),
                    ),
                };
                utxos.push((outpoint, utxo_info));
            }
        }
        Ok(utxos)
    }
}

#[cfg(test)]
mod test {
    use crate::model::GetUnspentOutputs;

    #[test]
    fn test_unspent() {
        let json_str = r#"{"btc": [{"address_type": "p2wsh", "block_height": 1806588, "pointer": 3509, "pt_idx": 1, "satoshi": 3650144, "subaccount": 0, "txhash": "08711d45d4867d7834b133a425da065b252eb6a9b206d57e2bbb226a344c5d13", "is_internal": false, "confidential": false}, {"address_type": "p2wsh", "block_height": 1835681, "pointer": 3510, "pt_idx": 0, "satoshi": 5589415, "subaccount": 0, "txhash": "fbd00e5b9e8152c04214c72c791a78a65fdbab68b5c6164ff0d8b22a006c5221", "is_internal": false, "confidential": false}, {"address_type": "p2wsh", "block_height": 1835821, "pointer": 3511, "pt_idx": 0, "satoshi": 568158, "subaccount": 0, "txhash": "e5b358fb8366960130b97794062718d7f4fbe721bf274f47493a19326099b811", "is_internal": false, "confidential": false}]}"#;
        let json: GetUnspentOutputs = serde_json::from_str(json_str).unwrap();
        println!("{:#?}", json);
    }
}
