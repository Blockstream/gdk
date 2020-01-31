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

#[derive(Debug)]
#[repr(C)]
pub struct GDKRUST_json(pub Value);

impl GDKRUST_json {
    pub fn new(data: Value) -> *const GDKRUST_json {
        unsafe { transmute(Box::new(GDKRUST_json(data))) }
    }
}

pub trait Session<E> {
    // fn create_session(network: Network) -> Result<Self::Value, E>;
    fn destroy_session(&self) -> Result<(), E>;
    fn poll_session(&self) -> Result<(), E>;
    fn connect(&mut self, net_params: &Value) -> Result<(), E>;
    fn disconnect(&mut self) -> Result<(), E>;
    // fn register_user(&mut self, mnemonic: String) -> Result<(), E>;
    fn login(&mut self, mnemonic: String, password: Option<String>) -> Result<(), E>;
    fn get_subaccounts(&self) -> Result<Vec<Value>, E>;
    fn get_subaccount(&self, index: u32) -> Result<Value, E>;
    fn get_transactions(&self, details: &Value) -> Result<Value, E>;
    fn get_transaction_details(&self, txid: &str) -> Result<Value, E>;
    fn get_balance(&self, details: &Value) -> Result<Value, E>;
    fn set_transaction_memo(&self, txid: &str, memo: &str, memo_type: u32) -> Result<(), E>;
    fn create_transaction(&self, details: &Value) -> Result<String, E>;
    fn sign_transaction(&self, tx_detail_unsigned: &Value) -> Result<Value, E>;
    fn send_transaction(&self, tx_detail_signed: &Value) -> Result<String, E>;
    fn broadcast_transaction(&self, tx_hex: &str) -> Result<String, E>;
    fn get_receive_address(&self, addr_details: &Value) -> Result<Value, E>;
    fn get_mnemonic_passphrase(&self, _password: &str) -> Result<String, E>;
    // fn get_available_currencies(&self) -> Result<Value, E>;
    // fn convert_amount(&self, value_details: &Value) -> Result<Value, E>;
    fn get_fee_estimates(&self) -> Result<Value, E>;
    fn get_settings(&self) -> Result<Value, E>;
    fn change_settings(&mut self, settings: &Value) -> Result<(), E>;
}
