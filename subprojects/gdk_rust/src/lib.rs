#![recursion_limit = "128"]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate lazy_static;
extern crate failure;
#[macro_use]
extern crate log;
#[cfg(feature = "android_log")]
extern crate android_logger;
#[cfg(feature = "stderr_logger")]
extern crate stderrlog;

// Liquid
#[cfg(feature = "liquid")]
extern crate elements;
#[cfg(feature = "liquid")]
extern crate liquid_rpc;

use serde_json::{from_value, Value};

#[cfg(feature = "android_log")]
use android_logger::{Config, FilterBuilder};
use bitcoincore_rpc::RpcApi;
use gdk_common::util::OptionExt;
use gdk_rpc::wally;
use log::Level;
use std::collections::HashMap;
use std::ffi::CString;
use std::mem::transmute;
use std::os::raw::c_char;

#[cfg(feature = "android_log")]
use std::sync::{Once, ONCE_INIT};

use gdk_common::constants::{GA_ERROR, GA_MEMO_USER, GA_NOT_AUTHORIZED, GA_OK, GA_RECONNECT};
use gdk_common::network::Network;
use gdk_common::util::{extend, log_filter, make_str, read_str};
use gdk_common::GDKRUST_json;
use gdk_common::Session;

use gdk_electrum::GDKELECTRUM_session;
use gdk_rpc::session::GDKRPC_session;

pub mod session;
pub mod network;

#[derive(Debug)]
pub enum GDKRUST_session {
    Rpc(GDKRPC_session),
    //Electrum(GDKELECTRUM_session),
}



#[derive(Debug)]
#[repr(C)]
pub enum GA_auth_handler {
    Error(String),
    Done(Value),
}

impl GA_auth_handler {
    fn done(res: Value) -> *const GA_auth_handler {
        debug!("GA_auth_handler::done() {:?}", res);
        let handler = GA_auth_handler::Done(res);
        unsafe { transmute(Box::new(handler)) }
    }
    fn success() -> *const GA_auth_handler {
        GA_auth_handler::done(Value::Null)
    }

    fn to_json(&self) -> Value {
        match self {
            GA_auth_handler::Error(err) => json!({ "status": "error", "error": err }),
            GA_auth_handler::Done(res) => json!({ "status": "done", "result": res }),
        }
    }
}

//
// Macros
//

macro_rules! tryit {
    ($x:expr) => {
        match $x {
            Err(err) => {
                println!("error: {:?}", err);
                return GA_ERROR;
            }
            Ok(x) => {
                // can't easily print x because bitcoincore_rpc::Client is not serializable :(
                // should be fixed with https://github.com/rust-bitcoin/rust-bitcoincore-rpc/pull/51
                x
            }
        }
    };
}

macro_rules! ok {
    ($t:expr, $x:expr) => {
        unsafe {
            let x = $x;
            debug!("ok!() {:?}", x);
            *$t = x;
            GA_OK
        }
    };
}

macro_rules! ok_json {
    ($t:expr, $x:expr) => {{
        let x = json!($x);
        debug!("ok_json!() {:?}", x);
        ok!($t, GDKRUST_json::new(x))
    }};
}

macro_rules! safe_ref {
    ($t:expr) => {{
        if $t.is_null() {
            return GA_ERROR;
        }
        unsafe { &*$t }
    }};
}

macro_rules! safe_mut_ref {
    ($t:expr) => {{
        if $t.is_null() {
            return GA_ERROR;
        }
        unsafe { &mut *$t }
    }};
}

macro_rules! safe_own {
    ($t:expr) => {{
        if $t.is_null() {
            return GA_ERROR;
        }
        unsafe { Box::from_raw($t) }
    }};
}

//
// Session & account management
//

#[cfg(feature = "android_log")]
static INIT_LOGGER: Once = ONCE_INIT;

#[no_mangle]
pub extern "C" fn GDKRUST_create_session(
    ret: *mut *const GDKRUST_session,
    network: *const GDKRUST_json,
) -> i32 {
    debug!("GA_create_session()");

    #[cfg(feature = "android_log")]
    INIT_LOGGER.call_once(|| {
        android_logger::init_once(
            Config::default()
                .with_min_level(Level::Trace)
                .with_filter(FilterBuilder::new().parse("debug,hello::crate=gdk_rust").build()),
        )
    });

    let network = &safe_ref!(network).0;
    //let mut rpc_networks: HashMap<String, Network> = HashMap::new();

    if !network.is_object() || !network.as_object().unwrap().contains_key("server_type") {
        println!("Expected network to be an object with a server_type key");
        return GA_ERROR;
    }

    println!("Error parsing network {:?}", network);

    let parsed_network = serde_json::from_value(network.clone());
    if let Err(msg) = parsed_network {
        println!("Error parsing network {}", msg);
        return GA_ERROR;
    }

    /*
    for (k, network) in networks.as_object().unwrap().iter() {
        if network.get("server_type").map(|v| v.as_str() == Some("rpc")).unwrap_or(false) {
            let parsed_network = serde_json::from_value(network.clone());
            if let Err(msg) = parsed_network {
                println!("Error parsing network '{}': {}", k, msg);
                return GA_ERROR;
            }
            rpc_networks.insert(k.into(), parsed_network.unwrap());
        }
    }
    */

    let sess = match network.get("server_type").unwrap().as_str() {
        Some("rpc") => GDKRUST_session::Rpc( GDKRPC_session::create_session(parsed_network.unwrap()).unwrap() ),
        //Some("electrum") => GDKELECTRUM_session::create_session(parsed_network.unwrap()),
        _ => {
            println!("server_type invalid");
            return GA_ERROR;
        }
    };
    let sess = unsafe { transmute(Box::new(sess)) };

    ok!(ret, sess)
}

#[no_mangle]
pub extern "C" fn GDKRUST_destroy_session(sess: *mut GDKRUST_session) -> i32 {
    let sess = safe_own!(sess);

    sess.destroy_session();

    GA_OK
}

#[no_mangle]
pub extern "C" fn GDKRUST_poll_session(sess: *mut GDKRUST_session) -> i32 {
    let sess = safe_mut_ref!(sess);
    sess.poll_session();
    GA_OK
}

#[no_mangle]
pub extern "C" fn GDKRUST_connect(
    sess: *mut GDKRUST_session,
    net_params: *const GDKRUST_json,
    log_level: u32,
) -> i32 {
    log::set_max_level(log_filter(log_level));
    let sess = safe_mut_ref!(sess);
    let net_params = &safe_ref!(net_params).0;
    sess.connect(net_params.clone(), log_level);

    GA_OK
}

#[no_mangle]
pub extern "C" fn GDKRUST_disconnect(sess: *mut GDKRUST_session) -> i32 {
    let sess = safe_mut_ref!(sess);

    sess.disconnect();

    GA_OK
}

#[no_mangle]
pub extern "C" fn GDKRUST_register_user(
    sess: *mut GDKRUST_session,
    _hw_device: *const GDKRUST_json,
    mnemonic: *const c_char,
    ret: *mut *const GA_auth_handler,
) -> i32 {
    let sess = safe_mut_ref!(sess);
    let mnemonic = read_str(mnemonic);
    sess.register_user(mnemonic);
    // sess.wallet = Some(tryit!(Wallet::register(network, &mnemonic)));

    ok!(ret, GA_auth_handler::success())
}

#[no_mangle]
pub extern "C" fn GDKRUST_login(
    sess: *mut GDKRUST_session,
    _hw_device: *const GDKRUST_json,
    mnemonic: *const c_char,
    password: *const c_char,
) -> i32 {
    let sess = safe_mut_ref!(sess);

    let mnemonic = read_str(mnemonic);

    if !read_str(password).is_empty() {
        println!("password-encrypted mnemonics are unsupported");
        return GA_ERROR;
    }
    sess.login(mnemonic, None); // TODO support password-encrypted

    GA_OK
}

//
// Subaccounts
//

#[no_mangle]
pub extern "C" fn GDKRUST_get_subaccounts(
    sess: *const GDKRUST_session,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let sess = safe_ref!(sess);
    let subaccounts = sess.get_subaccounts().unwrap();

    ok_json!(ret, subaccounts)
}

#[no_mangle]
pub extern "C" fn GDKRUST_get_subaccount(
    sess: *const GDKRUST_session,
    index: u32, // Ignored atm
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let sess = safe_ref!(sess);
    let subaccount = sess.get_subaccount(index).unwrap();

    ok_json!(ret, subaccount)
}

//
// Transactions & Coins
//

#[no_mangle]
pub extern "C" fn GDKRUST_get_transactions(
    sess: *const GDKRUST_session,
    details: *const GDKRUST_json,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let sess = safe_ref!(sess);

    let details = &unsafe { &*details }.0;
    let txs = sess.get_transactions(details.clone()).unwrap();

    ok_json!(ret, txs)
}

#[no_mangle]
pub extern "C" fn GDKRUST_get_transaction_details(
    sess: *const GDKRUST_session,
    txid: *const c_char,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let sess = safe_ref!(sess);
    let txid = read_str(txid);
    let tx = sess.get_transaction_details(txid).unwrap();

    ok_json!(ret, tx)
}

#[no_mangle]
pub extern "C" fn GDKRUST_get_balance(
    sess: *const GDKRUST_session,
    details: *const GDKRUST_json,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let sess = safe_ref!(sess);

    let details = &unsafe { &*details }.0;
    let balance = sess.get_balance(details.clone()).unwrap();

    ok_json!(ret, balance)
}

#[no_mangle]
pub extern "C" fn GDKRUST_set_transaction_memo(
    sess: *const GDKRUST_session,
    txid: *const c_char,
    memo: *const c_char,
    memo_type: u32,
) -> i32 {
    let sess = safe_ref!(sess);

    if memo_type != GA_MEMO_USER {
        warn!("unsupported memo type");
        return GA_ERROR;
    }

    let txid = read_str(txid);
    let memo = read_str(memo);
    sess.set_transaction_memo(txid, memo, memo_type);

    GA_OK
}

//
// Creating transactions
//

#[no_mangle]
pub extern "C" fn GDKRUST_create_transaction(
    sess: *const GDKRUST_session,
    details: *const GDKRUST_json,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let sess = safe_ref!(sess);
    let details = &unsafe { &*details }.0;
    let res = json!({
    "addressees": &details["addressees"],
    "is_sweep": false,
    "memo": "",
    "subaccount": 0,
    "change_subaccount": 0,
    "fee": 100, // FIXME
    "satoshi": 500, // FIXME
    });
    match sess.create_transaction(details.clone()) {
        Ok(tx_unsigned) => {
            ok_json!(ret, extend(res, json!({ "error": "", "hex": tx_unsigned })).unwrap())
        }
        Err(err) => {
            // errors are returned as a GA_OK with "error" in the returned object
            debug!("GA_create_transaction error: {:?}", err);
            ok_json!(
                ret,
                extend(res, json!({"error": GA_ERROR,"error_msg": err.to_string()})).unwrap()
            )
        }
    }
}

#[no_mangle]
pub extern "C" fn GDKRUST_sign_transaction(
    sess: *mut GDKRUST_session,
    tx_detail_unsigned: *mut GDKRUST_json,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let sess = safe_mut_ref!(sess);
    let tx_detail_unsigned = &mut safe_mut_ref!(tx_detail_unsigned).0;
    sess.sign_transaction(tx_detail_unsigned.clone()).unwrap();

    ok_json!(ret, tx_detail_unsigned)
}

#[no_mangle]
pub extern "C" fn GDKRUST_send_transaction(
    sess: *const GDKRUST_session,
    tx_detail_signed: *const GDKRUST_json,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let sess = safe_ref!(sess);
    debug!("GDKRUST_send_transaction deref");
    let tx_detail_signed = &safe_ref!(tx_detail_signed).0;
    let txid = sess.send_transaction(tx_detail_signed.clone()).unwrap();

    ok_json!(ret, json!({ "error": "", "txid": txid }))
}

#[no_mangle]
pub extern "C" fn GDKRUST_broadcast_transaction(
    sess: *const GDKRUST_session,
    tx_hex: *const c_char,
    ret: *mut *const c_char,
) -> i32 {
    let sess = safe_ref!(sess);
    let tx_hex = read_str(tx_hex);
    let txid = sess.broadcast_transaction(tx_hex).unwrap();

    ok!(ret, make_str(txid))
}

//
// Addresses
//

#[no_mangle]
pub extern "C" fn GDKRUST_get_receive_address(
    sess: *const GDKRUST_session,
    addr_details: *const GDKRUST_json,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let sess = safe_ref!(sess);
    let addr_details = &unsafe { &*addr_details }.0;
    let address = sess.get_receive_address(addr_details.clone()).unwrap();

    ok_json!(ret, address)
}

//
// Mnemonic
//

#[no_mangle]
pub extern "C" fn GDKRUST_get_mnemonic_passphrase(
    sess: *const GDKRUST_session,
    password: *const c_char,
    ret: *mut *const c_char,
) -> i32 {
    let sess = safe_ref!(sess);
    let password = read_str(password);
    let mnemonic = sess.get_mnemonic_passphrase(password).unwrap();

    ok!(ret, make_str(mnemonic))
}

//
// Auth handler
//

#[no_mangle]
pub extern "C" fn GDKRUST_auth_handler_get_status(
    auth_handler: *const GA_auth_handler,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let auth_handler = safe_ref!(auth_handler);
    let status = auth_handler.to_json();

    ok_json!(ret, status)
}

//
// Currency conversion & fees
//

#[no_mangle]
pub extern "C" fn GDKRUST_get_available_currencies(
    sess: *const GDKRUST_session,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let sess = safe_ref!(sess);
    let currencies = sess.get_available_currencies().unwrap();

    ok_json!(ret, currencies)
}

#[no_mangle]
pub extern "C" fn GDKRUST_convert_amount(
    sess: *const GDKRUST_session,
    value_details: *const GDKRUST_json,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let sess = safe_ref!(sess);
    let value_details = &unsafe { &*value_details }.0;
    let units = sess.convert_amount(value_details.clone()).unwrap();

    ok_json!(ret, units)
}
#[no_mangle]
pub extern "C" fn GDKRUST_get_fee_estimates(
    sess: *const GDKRUST_session,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let sess = safe_ref!(sess);
    let estimates = sess.get_fee_estimates().unwrap();

    ok_json!(ret, json!({ "fees": estimates }))
}

//
// Push notifications
//

#[no_mangle]
pub extern "C" fn GDKRUST_set_notification_handler(
    sess: *mut GDKRUST_session,
    handler: extern "C" fn(*const libc::c_void, *const GDKRUST_json),
    self_context: *const libc::c_void,
) -> i32 {
    let sess = safe_mut_ref!(sess);
    //sess.notify = Some((handler, self_context));  //TODO handle notify

    println!("set notification handler");

    GA_OK
}

//
// Settings
//

#[no_mangle]
pub extern "C" fn GDKRUST_get_settings(
    sess: *const GDKRUST_session,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let sess = safe_ref!(sess);

    ok_json!(ret, json!(sess.get_settings().unwrap()))
}

#[no_mangle]
pub extern "C" fn GDKRUST_change_settings(
    sess: *mut GDKRUST_session,
    settings: *const GDKRUST_json,
    ret: *mut *const GA_auth_handler,
) -> i32 {
    let sess = safe_mut_ref!(sess);
    let new_settings = &unsafe { &*settings }.0;
    sess.change_settings(new_settings.clone()).unwrap();

    ok!(ret, GA_auth_handler::success())
}

//
// JSON utilities
//

#[no_mangle]
pub extern "C" fn GDKRUST_convert_json_to_string(
    json: *const GDKRUST_json,
    ret: *mut *const c_char,
) -> i32 {
    let json = &unsafe { &*json }.0;
    let res = json.to_string();
    ok!(ret, make_str(res))
}

#[no_mangle]
pub extern "C" fn GDKRUST_convert_string_to_json(
    jstr: *const c_char,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let jstr = read_str(jstr);
    let json: Value = tryit!(serde_json::from_str(&jstr));
    ok_json!(ret, json)
}

#[no_mangle]
pub extern "C" fn GDKRUST_convert_json_value_to_string(
    json: *const GDKRUST_json,
    path: *const c_char,
    ret: *mut *const c_char,
) -> i32 {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let res = tryit!(json[path].as_str().req());
    ok!(ret, make_str(res.to_string()))
}

#[no_mangle]
pub extern "C" fn GDKRUST_convert_json_value_to_uint32(
    json: *const GDKRUST_json,
    path: *const c_char,
    ret: *mut u32,
) -> i32 {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let res = tryit!(json[path].as_u64().req()) as u32;
    ok!(ret, res)
}

#[no_mangle]
pub extern "C" fn GDKRUST_convert_json_value_to_uint64(
    json: *const GDKRUST_json,
    path: *const c_char,
    ret: *mut u64,
) -> i32 {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let res = tryit!(json[path].as_u64().req());
    ok!(ret, res)
}

#[no_mangle]
pub extern "C" fn GDKRUST_convert_json_value_to_json(
    json: *const GDKRUST_json,
    path: *const c_char,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let json = &unsafe { &*json }.0;
    let path = read_str(path);
    let jstr = tryit!(json[path].as_str().req());
    let res: Value = tryit!(serde_json::from_str(jstr));
    ok_json!(ret, res)
}

#[no_mangle]
pub extern "C" fn GDKRUST_destroy_json(ptr: *mut GDKRUST_json) -> i32 {
    debug!("GA_destroy_json({:?})", ptr);
    // TODO make sure this works
    unsafe {
        drop(&*ptr);
    }
    GA_OK
}

#[no_mangle]
pub extern "C" fn GDKRUST_destroy_string(ptr: *mut c_char) -> i32 {
    unsafe {
        // retake pointer and drop
        let _ = CString::from_raw(ptr);
    }
    GA_OK
}

//
// Unimplemented, but gracefully degrades
//

#[no_mangle]
pub extern "C" fn GDKRUST_get_twofactor_config(
    // TODO: move in the cpp since it's hardcoded?
    _sess: *const GDKRUST_session,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    // 2FA is always off
    ok_json!(
        ret,
        json!({
            "any_enabled":false,
            "all_methods":[],
            "enabled_methods":[],
            "email":{"confirmed":false,"data":"","enabled":false},
            "limits":{"bits":"0.00","btc":"0.00000000","fiat":"0.00","fiat_currency":"USD","fiat_rate":"0","is_fiat":false,"mbtc":"0.00000","satoshi":0,"ubtc":"0.00"},
            "twofactor_reset":{"days_remaining":-1,"is_active":false,"is_disputed":false},
        })
    )
}

#[no_mangle]
pub extern "C" fn GDKRUST_set_pin(
    _sess: *const GDKRUST_session,
    mnemonic: *const c_char,
    _pin: *const c_char,
    device_id: *const c_char,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let mnemonic = read_str(mnemonic);
    let device_id = read_str(device_id);
    let mnemonic_hex = hex::encode(&tryit!(wally::bip39_mnemonic_to_bytes(&mnemonic)));

    // FIXME setting a PIN does not actually do anything, just a successful no-op
    ok_json!(
        ret,
        json!({
            "encrypted_data": mnemonic_hex,
            "salt": "IA==",
            "pin_identifier": device_id,
            "__unencrypted": true
        })
    )
}
//
// Unimplemented and GA_ERROR's
//

#[no_mangle]
pub extern "C" fn GDKRUST_connect_with_proxy(
    _sess: *const GDKRUST_session,
    _network: *const c_char,
    _proxy_uri: *const c_char,
    _use_tor: u32,
    _log_level: u32,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GDKRUST_get_unspent_outputs(
    _sess: *const GDKRUST_session,
    _details: *const GDKRUST_json,
    _ret: *mut *const GDKRUST_json,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GDKRUST_get_unspent_outputs_for_private_key(
    _sess: *const GDKRUST_session,
    _private_key: *const c_char,
    _password: *const c_char,
    _unused: u32,
    _ret: *mut *const GDKRUST_json,
) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GDKRUST_send_nlocktimes(_sess: *const GDKRUST_session) -> i32 {
    GA_ERROR
}

#[no_mangle]
pub extern "C" fn GDKRUST_register_network(
    _name: *const c_char,
    _network_details: *const GDKRUST_json,
) -> i32 {
    // let json : Value = safe_ref!(_network_details).0;
    // let name : String = read_str(_name);
    // let mnetwork : Result<Network, serde_json::Error> = serde_json::from_value(json);

    // if let Err(err) = mnetwork {
    //     println!("Error parsing network json in GDKRUST_register_network: {}", err);
    //     return GA_ERROR
    // }

    // let network = mnetwork.unwrap();

    // Network::list().insert(name, network);

    // GA_OK
    GA_ERROR
}

//
// Unit test helper methods
//

#[no_mangle]
pub extern "C" fn GDKRUST_test_tick(sess: *mut GDKRUST_session) -> i32 {
    debug!("GA_test_tick()");
    let sess = safe_mut_ref!(sess);
    //tryit!(sess.tick());  // TODO fixme
    GA_OK
}
