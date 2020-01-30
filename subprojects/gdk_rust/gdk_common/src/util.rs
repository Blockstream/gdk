use crate::constants::{GA_DEBUG, GA_INFO, GA_NONE, SAT_PER_BTC};
use crate::model::ExchangeRate;
use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use log::debug;

use backtrace::Backtrace;
use bitcoin::{Address, Amount, Network, PublicKey, Script};
use chrono::NaiveDateTime;
use log::LevelFilter;
use serde_json::Value;

lazy_static! {
    pub static ref SECP: bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All> =
        bitcoin::secp256k1::Secp256k1::new();
}

pub fn make_str<'a, S: Into<Cow<'a, str>>>(data: S) -> *const c_char {
    CString::new(data.into().into_owned()).unwrap().into_raw()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn read_str(s: *const c_char) -> String {
    unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_string()
}

pub fn f64_from_val(val: &Value) -> Option<f64> {
    val.as_f64().or_else(|| val.as_str().and_then(|x| x.parse().ok()))
}

pub fn extend(mut dest: Value, mut src: Value) -> Result<Value, String> {
    let dest = dest.as_object_mut().req()?;
    for (k, v) in src.as_object_mut().req()? {
        dest.insert(k.to_string(), v.take());
    }
    Ok(json!(dest))
}

pub fn fmt_time(unix_ts: u64) -> String {
    NaiveDateTime::from_timestamp(unix_ts as i64, 0).to_string()
}

pub fn parse_outs(details: &Value) -> Result<HashMap<String, Amount>, String> {
    debug!("parse_addresses {:?}", details);

    Ok(details["addressees"]
        .as_array()
        .req()?
        .iter()
        .map(|desc| {
            let mut address = desc["address"].as_str().req()?;
            let raw_sats = desc.get("satoshi").and_then(|s| s.as_u64()).unwrap_or(0);
            let amount = Amount::from_sat(raw_sats);

            if address.to_lowercase().starts_with("bitcoin:") {
                address = address.split(':').nth(1).req()?;
            }
            // TODO: support BIP21 amount

            Ok((address.to_string(), amount))
        })
        .collect::<Result<HashMap<String, Amount>, String>>()?)
}

pub fn btc_to_usat(amount: f64) -> u64 {
    (amount * SAT_PER_BTC) as u64
}

pub fn btc_to_isat(amount: f64) -> i64 {
    (amount * SAT_PER_BTC) as i64
}

pub fn usat_to_fbtc(sat: u64) -> f64 {
    (sat as f64) / SAT_PER_BTC
}

pub fn fiat_to_sat(fiat_amount: f64, exchange_rate: &ExchangeRate) -> i64 {
    btc_to_isat(fiat_amount / exchange_rate.rate)
}

#[allow(non_snake_case)]
pub fn log_filter(level: u32) -> LevelFilter {
    match level {
        GA_NONE => LevelFilter::Error,
        GA_INFO => LevelFilter::Info,
        GA_DEBUG => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
}

pub trait OptionExt<T> {
    fn or_err<E: Into<Cow<'static, str>>>(self, err: E) -> Result<T, String>;

    fn req(self) -> Result<T, String>;
}

impl<T> OptionExt<T> for Option<T> {
    fn or_err<E: Into<Cow<'static, str>>>(self, err: E) -> Result<T, String> {
        self.ok_or_else(|| {
            debug!("backtrace OptionExt::or_else: {:?}", Backtrace::new());
            err.into().to_string()
        })
    }

    fn req(self) -> Result<T, String> {
        self.ok_or_else(|| {
            debug!("backtrace OptionExt::req: {:?}", Backtrace::new());
            "missing required option".into()
        })
    }
}

pub fn p2shwpkh_script(pk: &PublicKey) -> Script {
    // using regtest is always ok because I am not interested in the address just in the script
    Address::p2shwpkh(pk, Network::Regtest).script_pubkey()
}
