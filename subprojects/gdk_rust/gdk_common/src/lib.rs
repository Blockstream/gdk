#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate serde_json;

#[macro_use]
extern crate serde;

#[macro_use]
extern crate log;

use core::mem::transmute;
use serde_json::Value;
use crate::network::Network;

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

pub trait Session<E: std::fmt::Debug>: std::marker::Sized {

    fn create_session(network: Network) -> Result<Self, Self::Error>;
    fn destroy_session(self) -> Result<(), Self::Error>;
    fn poll_session(&self) -> Result<(), Self::Error>;
    fn connect(&mut self, net_params: &Value) -> Result<(), Self::Error>;
    fn disconnect(&mut self) -> Result<(), Self::Error>;
    // fn register_user(&mut self, mnemonic: String) -> Result<(), Self::Error>;
    fn login(&mut self, mnemonic: String, password: Option<String>) -> Result<(), Self::Error>;
    fn get_subaccounts(&self) -> Result<Vec<Value>, Self::Error>;
    fn get_subaccount(&self, index: u32) -> Result<Value, Self::Error>;
    fn get_transactions(&self, details: &Value) -> Result<Value, Self::Error>;
    fn get_transaction_details(&self, txid: String) -> Result<Value, Self::Error>;
    fn get_balance(&self, details: &Value) -> Result<Value, Self::Error>;
    fn set_transaction_memo(&self, txid: String, memo: String, memo_type: u32) -> Result<(), Self::Error>;
    fn create_transaction(&self, details: &Value) -> Result<String, Self::Error>;
    fn sign_transaction(&self, tx_detail_unsigned: &Value) -> Result<Value, Self::Error>;
    fn send_transaction(&self, tx_detail_signed: &Value) -> Result<String, Self::Error>;
    fn broadcast_transaction(&self, tx_hex: String) -> Result<String, Self::Error>;
    fn get_receive_address(&self, addr_details: &Value) -> Result<Value, Self::Error>;
    fn get_mnemonic_passphrase(&self, _password: String) -> Result<String, Self::Error>;
    // fn get_available_currencies(&self) -> Result<Value, Self::Error>;
    // fn convert_amount(&self, value_details: &Value) -> Result<Value, Self::Error>;
    fn get_fee_estimates(&self) -> Result<Value, Self::Error>;
    fn get_settings(&self) -> Result<Value, Self::Error>;
    fn change_settings(&mut self, settings: &Value) -> Result<(), Self::Error>;
}
