#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_json;

extern crate log;

use core::mem::transmute;
use serde_json::Value;
// use crate::network::Network;

pub mod constants;
pub mod network;
pub mod util;
pub mod wally;

#[derive(Debug)]
#[repr(C)]
pub struct GDKRUST_json(pub Value);

impl GDKRUST_json {
    pub fn new(data: Value) -> *const GDKRUST_json {
        unsafe { transmute(Box::new(GDKRUST_json(data))) }
    }
}

pub struct BalanceResult(pub i64);

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
    pub created_at: u64,
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
    pub fee: i64,
    pub fee_rate: f64,
    pub addresses: Vec<String>,
    pub addressees: Vec<String>, // notice the extra "e" -- its intentional
    pub inputs: Vec<AddressIO>,  // tx.input.iter().map(format_gdk_input).collect(),
    pub outputs: Vec<AddressIO>, //tx.output.iter().map(format_gdk_output).collect(),
}

pub struct AddressResult(pub String);
pub struct TxsResult(pub Vec<TxListItem>);

pub trait Session<E> {
    // fn create_session(network: Network) -> Result<Self::Value, E>;
    fn destroy_session(&mut self) -> Result<(), E>;
    fn poll_session(&self) -> Result<(), E>;
    fn connect(&mut self, net_params: &Value) -> Result<(), E>;
    fn disconnect(&mut self) -> Result<(), E>;
    // fn register_user(&mut self, mnemonic: String) -> Result<(), E>;
    fn login(&mut self, mnemonic: String, password: Option<String>) -> Result<(), E>;
    fn get_subaccounts(&self) -> Result<Value, E>;
    fn get_subaccount(&self, index: u32) -> Result<Value, E>;
    fn get_transactions(&self, details: &Value) -> Result<TxsResult, E>;
    fn get_transaction_details(&self, txid: &str) -> Result<Value, E>;
    fn get_balance(&self, details: &Value) -> Result<i64, E>;
    fn set_transaction_memo(&self, txid: &str, memo: &str, memo_type: u32) -> Result<(), E>;
    fn create_transaction(&self, details: &Value) -> Result<String, E>;
    fn sign_transaction(&self, tx_detail_unsigned: &Value) -> Result<Value, E>;
    fn send_transaction(&self, tx_detail_signed: &Value) -> Result<String, E>;
    fn broadcast_transaction(&self, tx_hex: &str) -> Result<String, E>;
    fn get_receive_address(&self, addr_details: &Value) -> Result<AddressResult, E>;
    fn get_mnemonic_passphrase(&self, _password: &str) -> Result<String, E>;
    // fn get_available_currencies(&self) -> Result<Value, E>;
    // fn convert_amount(&self, value_details: &Value) -> Result<Value, E>;
    fn get_fee_estimates(&self) -> Result<Value, E>;
    fn get_settings(&self) -> Result<Value, E>;
    fn change_settings(&mut self, settings: &Value) -> Result<(), E>;
}
