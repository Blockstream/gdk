use std::borrow::Cow;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

use bitcoin::Amount;
use chrono::NaiveDateTime;
use log::LevelFilter;
use serde_json::Value;

use crate::constants::{GA_DEBUG, GA_INFO, GA_NONE, SAT_PER_BTC};
use crate::errors::{Error, OptionExt};

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

pub fn log_filter(level: u32) -> LevelFilter {
    match level {
        GA_NONE => LevelFilter::Error,
        GA_INFO => LevelFilter::Info,
        GA_DEBUG => LevelFilter::Debug,
        _ => LevelFilter::Trace,
    }
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

pub fn f64_from_val(val: &Value) -> Option<f64> {
    val.as_f64().or_else(|| val.as_str().and_then(|x| x.parse().ok()))
}

pub fn extend(mut dest: Value, mut src: Value) -> Result<Value, Error> {
    let dest = dest.as_object_mut().req()?;
    for (k, v) in src.as_object_mut().req()? {
        dest.insert(k.to_string(), v.take());
    }
    Ok(json!(dest))
}

pub fn fmt_time(unix_ts: u64) -> String {
    NaiveDateTime::from_timestamp(unix_ts as i64, 0).to_string()
}

// nuclear option, if we need to convert an error without From or Display
pub fn into_err<A, E>(err: E) -> Result<A, Error>
where
    E: std::fmt::Debug,
{
    Err(Error::Other(From::from(format!("{:?}", err))))
}

pub fn parse_outs(details: &Value) -> Result<HashMap<String, Amount>, Error> {
    debug!("parse_addresses {:?}", details);

    Ok(details["addressees"]
        .as_array()
        .req()?
        .iter()
        .map(|desc| {
            let mut address = desc["address"].as_str().req()?;
            let raw_sats = desc["satoshi"].as_u64().or_err("id_no_amount_specified")?;
            let amount = Amount::from_sat(raw_sats);

            if address.to_lowercase().starts_with("bitcoin:") {
                address = address.split(':').nth(1).req()?;
            }
            // TODO: support BIP21 amount

            Ok((address.to_string(), amount))
        })
        .collect::<Result<HashMap<String, Amount>, Error>>()?)
}
