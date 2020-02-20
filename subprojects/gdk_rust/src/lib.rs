#![recursion_limit = "128"]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate serde_derive;
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

use serde_json::Value;

#[cfg(feature = "android_log")]
use android_logger::{Config, FilterBuilder};
#[cfg(feature = "android_log")]
use log::Level;
use std::ffi::CString;
use std::mem::transmute;
use std::os::raw::c_char;

#[cfg(feature = "android_log")]
use std::sync::{Once, ONCE_INIT};

use gdk_common::constants::{GA_ERROR, GA_OK};
use gdk_common::util::{make_str, read_str};
use gdk_common::*;
use gdk_common::{GDKRUST_json, Session};

use bitcoin::util::address::AddressType;
use gdk_electrum::interface::ElectrumUrl;
use gdk_electrum::{ElectrumPlaintextStream, ElectrumSession, ElectrumSslStream};
// use gdk_rpc::session::RpcSession;
use error::Error;

pub mod error;

pub enum GdkSession {
    // Rpc(RpcSession),
    Electrum(ElectrumSession<ElectrumPlaintextStream>),
    ElectrumTls(ElectrumSession<ElectrumSslStream>),
}

#[derive(Debug)]
#[repr(C)]
pub enum GA_auth_handler {
    Error(String),
    Done(Value),
}

impl GA_auth_handler {
    fn _done(res: Value) -> *const GA_auth_handler {
        debug!("GA_auth_handler::done() {:?}", res);
        let handler = GA_auth_handler::Done(res);
        unsafe { transmute(Box::new(handler)) }
    }
    fn _success() -> *const GA_auth_handler {
        GA_auth_handler::_done(Value::Null)
    }

    fn _to_json(&self) -> Value {
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
    ($t:expr, $x:expr, $ret:expr) => {
        unsafe {
            let x = $x;
            debug!("ok!() {:?}", x);
            *$t = x;
            $ret
        }
    };
}

macro_rules! json_res {
    ($t:expr, $x:expr, $ret:expr) => {{
        let x = json!($x);
        debug!("ok_json!() {:?}", x);
        ok!($t, GDKRUST_json::new(x), $ret)
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

//
// Session & account management
//

#[cfg(feature = "android_log")]
static INIT_LOGGER: Once = ONCE_INIT;

#[no_mangle]
pub extern "C" fn GDKRUST_create_session(
    ret: *mut *const GdkSession,
    network: *const GDKRUST_json,
) -> i32 {
    #[cfg(feature = "android_log")]
    INIT_LOGGER.call_once(|| {
        android_logger::init_once(
            Config::default()
                .with_min_level(Level::Trace)
                .with_filter(FilterBuilder::new().parse("debug,hello::crate=gdk_rust").build()),
        )
    });

    let network = &safe_ref!(network).0;
    let sess = create_session(&network);

    if let Err(err) = sess {
        println!("create_session error: {}", err);
        return GA_ERROR;
    }

    let sess = unsafe { transmute(Box::new(sess.unwrap())) };

    ok!(ret, sess, GA_OK)
}

fn address_result_value(addr: &AddressResult) -> Value {
    json!({"address": addr.0})
}

fn balance_result_value(bal: &BalanceResult) -> Value {
    json!({"btc": bal.0})
}

fn address_type_str(addr_type: &AddressType) -> &'static str {
    match addr_type {
        AddressType::P2pkh => "p2pkh",
        AddressType::P2sh => "p2sh",
        AddressType::P2wpkh => "p2wpkh",
        AddressType::P2wsh => "p2wsh",
    }
}

fn address_io_value(addr: &AddressIO) -> Value {
    json!({
        "address": addr.address,
        "address_type": address_type_str(&addr.address_type),
        "addressee": addr.addressee,
        "is_output": addr.is_output,
        "is_relevant": addr.is_relevant,
        "is_spent": addr.is_spent,
        "pointer": addr.pointer,
        "pt_idx": addr.pt_idx,
        "satoshi": addr.satoshi,
        "script_type": addr.script_type,
        "subaccount": addr.subaccount,
        "subtype": addr.subtype,
    })
}

fn txitem_value(tx: &TxListItem) -> Value {
    let inputs = Value::Array(tx.inputs.iter().map(address_io_value).collect());
    let outputs = Value::Array(tx.inputs.iter().map(address_io_value).collect());

    json!({
        "block_height": 1,
        "created_at": tx.created_at, // TODO: is this a unix timestmap?

        "type": tx.type_,
        "memo": tx.memo,

        "txhash": tx.txhash,
        "transaction": bitcoin::hashes::hex::ToHex::to_hex(tx.transaction.as_slice()),

        "satoshi": balance_result_value(&tx.satoshi),

        "rbf_optin": tx.rbf_optin,
        "cap_cpfp": tx.cap_cpfp, // TODO
        "can_rbf": tx.can_rbf, // TODO
        "has_payment_request": tx.has_payment_request, // TODO
        "server_signed": tx.server_signed,
        "user_signed": tx.user_signed,
        "instant": tx.instant,

        "fee": tx.fee,
        "fee_rate": tx.fee_rate,

        "addressees": tx.addressees, // notice the extra "e" -- its intentional
        "inputs": inputs, // tx.input.iter().map(format_gdk_input).collect(),
        "outputs": outputs, //tx.output.iter().map(format_gdk_output).collect(),
    })
}

fn txs_result_value(txs: &TxsResult) -> Value {
    Value::Array(txs.0.iter().map(txitem_value).collect())
}

fn create_session(network: &Value) -> Result<GdkSession, Value> {
    if !network.is_object() || !network.as_object().unwrap().contains_key("server_type") {
        println!("Expected network to be an object with a server_type key");
        return Err(GA_ERROR.into());
    }

    let parsed_network = serde_json::from_value(network.clone());
    if let Err(msg) = parsed_network {
        println!("Error parsing network {}", msg);
        return Err(GA_ERROR.into());
    }

    let parsed_network = parsed_network.unwrap();
    let db_root = network["db_root"].as_str().unwrap_or("");

    match network["server_type"].as_str() {
        // Some("rpc") => GDKRUST_session::Rpc( GDKRPC_session::create_session(parsed_network.unwrap()).unwrap() ),
        Some("electrum") => {
            let url = gdk_electrum::determine_electrum_url_from_net(&parsed_network)
                .map_err(|x| json!(x))?;

            let gdk_sess = match url {
                ElectrumUrl::Tls(_url) => {
                    let elec_tls_sess =
                        ElectrumSession::new_tls_session(parsed_network.clone(), db_root)
                            .map_err(|x| json!(x))?;
                    GdkSession::ElectrumTls(elec_tls_sess)
                }

                ElectrumUrl::Plaintext(_url) => {
                    let elec_sess =
                        ElectrumSession::new_plaintext_session(parsed_network.clone(), db_root)
                            .map_err(|x| json!(x))?;

                    GdkSession::Electrum(elec_sess)
                }
            };

            Ok(gdk_sess)
        }
        _ => Err(json!("server_type invalid")),
    }
}

#[no_mangle]
pub extern "C" fn GDKRUST_call_session(
    sess: *mut GdkSession,
    method: *const c_char,
    input: *const GDKRUST_json,
    output: *mut *const GDKRUST_json,
) -> i32 {
    let method = read_str(method);
    let input = &safe_ref!(input).0;

    let res = match safe_mut_ref!(sess) {
        GdkSession::Electrum(ref mut s) => handle_call(s, &method, &input),
        GdkSession::ElectrumTls(ref mut s) => handle_call(s, &method, &input),
        // GdkSession::Rpc(ref s) => handle_call(s, method),
    };

    println!("GDKRUST_call_session {} {:?}", method, res);

    match res {
        Ok(ref val) => json_res!(output, val, GA_OK),

        // TODO: should we return GA_ERROR here?
        Err(ref e) => json_res!(output, json!({ "error": e }), GA_ERROR),
    }
}

#[no_mangle]
pub extern "C" fn GDKRUST_set_notification_handler(
    _sess: *mut GdkSession,
    _handler: extern "C" fn(*const libc::c_void, *const GDKRUST_json),
    _self_context: *const libc::c_void,
) -> i32 {
    // let sess = safe_mut_ref!(sess);
    //sess.notify = Some((handler, self_context));  //TODO handle notify

    println!("set notification handler");

    GA_OK
}

fn login<S, E>(session: &mut S, input: &Value) -> Result<(), Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    let mnemonic = input["mnemonic"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Error::Other("login: missing mnemonic argument".into()))?;

    let pass = input["password"].as_str().map(|x| x.to_string());

    session.login(mnemonic, pass).map_err(Into::into)
}

fn get_subaccount<S, E>(session: &S, input: &Value) -> Result<Value, Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    let index = input["index"]
        .as_u64()
        .ok_or_else(|| Error::Other("get_subaccount: index argument not found".into()))?;

    session.get_subaccount(index as u32).map_err(Into::into)
}

fn get_transaction_details<S, E>(session: &S, input: &Value) -> Result<Value, Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    // TODO: parse txid?
    let txid = input
        .as_str()
        .ok_or_else(|| Error::Other("get_transaction_details: input is not a string".into()))?;

    session.get_transaction_details(txid).map_err(Into::into)
}

fn set_transaction_memo<S, E>(session: &S, input: &Value) -> Result<Value, Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    // TODO: parse txid?.
    let txid = input["txid"]
        .as_str()
        .ok_or_else(|| Error::Other("get_transaction_details: missing txid".into()))?;

    let memo = input["memo"]
        .as_str()
        .ok_or_else(|| Error::Other("get_transaction_details: missing memo".into()))?;

    let memo_type = input["memo_type"]
        .as_u64()
        .ok_or_else(|| Error::Other("get_transaction_details: missing memo_type".into()))?;

    session.set_transaction_memo(txid, memo, memo_type as u32).map(|v| json!(v)).map_err(Into::into)
}

fn send_transaction<S, E>(session: &S, input: &Value) -> Result<Value, Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    let txid = session.send_transaction(input).map_err(Into::into)?;
    Ok(json!({"error": "", "txid": txid}))
}

fn fee_estimate_values(estimates: &Vec<FeeEstimate>) -> Result<Value, Error> {
    if estimates.len() == 0 {
        // Current apps depend on this length
        return Err(Error::Other("Expected at least one feerate".into()));
    }

    Ok(json!({ "fees": estimates }))
}

// dynamic dispatch shenanigans
fn handle_call<S, E>(session: &mut S, method: &str, input: &Value) -> Result<Value, Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    match method {
        "poll_session" => session.poll_session().map(|v| json!(v)).map_err(Into::into),

        "destroy_session" => session.destroy_session().map(|v| json!(v)).map_err(Into::into),

        "connect" => session.connect(input).map(|v| json!(v)).map_err(Into::into),

        "disconnect" => session.disconnect().map(|v| json!(v)).map_err(Into::into),

        "login" => login(session, input).map(|v| json!(v)),

        "get_subaccounts" => session.get_subaccounts().map(|v| json!(v)).map_err(Into::into),

        "get_subaccount" => get_subaccount(session, input),

        "get_transactions" => {
            session.get_transactions(input).map(|x| txs_result_value(&x)).map_err(Into::into)
        }

        "get_transaction_details" => get_transaction_details(session, input),
        "get_balance" => session
            .get_balance(input)
            .map(|x| balance_result_value(&BalanceResult(x)))
            .map_err(Into::into),
        "set_transaction_memo" => set_transaction_memo(session, input),
        "create_transaction" => {
            session.create_transaction(input).map(|v| json!(v)).map_err(Into::into)
        }
        "sign_transaction" => session.sign_transaction(input).map_err(Into::into),
        "send_transaction" => send_transaction(session, input),
        "broadcast_transaction" => {
            session
                .broadcast_transaction(input.as_str().ok_or_else(|| {
                    Error::Other("broadcast_transaction: input not a string".into())
                })?)
                .map(|v| json!(v))
                .map_err(Into::into)
        }

        "get_receive_address" => {
            session.get_receive_address(input).map(|x| address_result_value(&x)).map_err(Into::into)
        }

        "get_mnemonic_passphrase" => session
            .get_mnemonic_passphrase(input.as_str().ok_or_else(|| {
                Error::Other("get_mnemonic_passphrase: input not a string".into())
            })?)
            .map(|v| json!(v))
            .map_err(Into::into),

        "get_fee_estimates" => {
            session.get_fee_estimates().map_err(Into::into).and_then(|x| fee_estimate_values(&x))
        }

        "get_settings" => session.get_settings().map_err(Into::into),
        "change_settings" => session.change_settings(input).map(|v| json!(v)).map_err(Into::into),

        // "auth_handler_get_status" => Ok(auth_handler.to_json()),
        _ => Err(Error::Other(format!("handle_call method not found: {}", method))),
    }
}

#[no_mangle]
pub extern "C" fn GDKRUST_convert_json_to_string(
    json: *const GDKRUST_json,
    ret: *mut *const c_char,
) -> i32 {
    let json = &unsafe { &*json }.0;
    let res = json.to_string();
    ok!(ret, make_str(res), GA_OK)
}

#[no_mangle]
pub extern "C" fn GDKRUST_convert_string_to_json(
    jstr: *const c_char,
    ret: *mut *const GDKRUST_json,
) -> i32 {
    let jstr = read_str(jstr);
    let json: Value = tryit!(serde_json::from_str(&jstr));
    json_res!(ret, json, GA_OK)
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
