#![recursion_limit = "128"]
#![allow(clippy::not_unsafe_ptr_arg_deref)]

#[macro_use]
extern crate serde_json;
extern crate failure;
extern crate serde_derive;
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

pub mod error;
mod serialize;

use crate::serialize::*;
use serde_json::Value;

#[cfg(feature = "android_log")]
use android_logger::{Config, FilterBuilder};
#[cfg(feature = "android_log")]
use log::Level;
use std::ffi::CString;
use std::mem::transmute;
use std::os::raw::c_char;
use std::sync::Once;
use std::time::{Duration, SystemTime};

use gdk_common::constants::{GA_ERROR, GA_OK};
use gdk_common::model::{GDKRUST_json, GetTransactionsOpt};
use gdk_common::session::Session;
use gdk_common::util::{make_str, read_str};

use bitcoin_exchange_rates::{hyper_fetch_requests, make_tls_hyper_client, prepare_requests};
use bitcoin_exchange_rates::{Bitfinex, Currency, Pair, Source, Ticker, Wasabi};

use gdk_electrum::{ElectrumSession, NativeNotif};
// use gdk_rpc::session::RpcSession;
use crate::error::Error;
use log::{LevelFilter, Metadata, Record};

pub struct GdkSession {
    pub backend: GdkBackend,
    pub last_xr_fetch: std::time::SystemTime,
    pub last_xr: Option<Vec<Ticker>>,
}

pub enum GdkBackend {
    // Rpc(RpcSession),
    Electrum(ElectrumSession),
}

#[derive(Debug)]
#[repr(C)]
pub enum GA_auth_handler {
    Error(String),
    Done(Value),
}

impl GA_auth_handler {
    fn _done(res: Value) -> *const GA_auth_handler {
        info!("GA_auth_handler::done() {:?}", res);
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
                error!("error: {:?}", err);
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
            trace!("ok!() {:?}", x);
            *$t = x;
            $ret
        }
    };
}

macro_rules! json_res {
    ($t:expr, $x:expr, $ret:expr) => {{
        let x = json!($x);
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

static INIT_LOGGER: Once = Once::new();

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

    #[cfg(not(feature = "android_log"))]
    INIT_LOGGER.call_once(|| {
        log::set_logger(&LOGGER)
            .map(|()| log::set_max_level(LevelFilter::Info))
            .expect("cannot initialize logging");
    });

    let network = &safe_ref!(network).0;
    let sess = create_session(&network);

    if let Err(err) = sess {
        error!("create_session error: {}", err);
        return GA_ERROR;
    }

    let sess = unsafe { transmute(Box::new(sess.unwrap())) };

    ok!(ret, sess, GA_OK)
}

fn create_session(network: &Value) -> Result<GdkSession, Value> {
    if !network.is_object() || !network.as_object().unwrap().contains_key("server_type") {
        error!("Expected network to be an object with a server_type key");
        return Err(GA_ERROR.into());
    }

    let parsed_network = serde_json::from_value(network.clone());
    if let Err(msg) = parsed_network {
        error!("Error parsing network {}", msg);
        return Err(GA_ERROR.into());
    }

    let parsed_network = parsed_network.unwrap();
    let db_root = network["db_root"].as_str().unwrap_or("");

    match network["server_type"].as_str() {
        // Some("rpc") => GDKRUST_session::Rpc( GDKRPC_session::create_session(parsed_network.unwrap()).unwrap() ),
        Some("electrum") => {
            let url = gdk_electrum::determine_electrum_url_from_net(&parsed_network)
                .map_err(|x| json!(x))?;
            let move_url = url.clone();

            let session = ElectrumSession::new_session(parsed_network.clone(),
                                                       db_root,
            move_url).map_err(|x| json!(x))?;
            let backend = GdkBackend::Electrum(session);

            // some time in the past
            let last_xr_fetch = SystemTime::now() - Duration::from_secs(1000);
            let gdk_session = GdkSession {
                backend,
                last_xr_fetch,
                last_xr: None,
            };
            Ok(gdk_session)
        }
        _ => Err(json!("server_type invalid")),
    }
}

fn fetch_cached_exchange_rates(sess: &mut GdkSession) -> Option<Vec<Ticker>> {
    if sess.last_xr.is_some()
        && (SystemTime::now() < (sess.last_xr_fetch + Duration::from_secs(60)))
    {
        info!("hit exchange rate cache");
    } else {
        info!("missed exchange rate cache");
        let rates = fetch_exchange_rates();
        // still record time even if we get no results
        sess.last_xr_fetch = SystemTime::now();
        if !rates.is_empty() {
            // only set last_xr if we got new non-empty rates
            sess.last_xr = Some(rates);
        }
    }

    return sess.last_xr.clone();
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

    // TODO let's do some kind of cached exchange rate fetching here
    // independent of the backends
    // let exchange_rate_res = Ok(ExchangeRateOk::ok("USD".into(), 1.2));

    let sess = safe_mut_ref!(sess);

    if method == "exchange_rates" {
        let rates = fetch_cached_exchange_rates(sess).unwrap_or(Vec::new());
        return json_res!(output, tickers_to_json(rates), GA_OK);
    }
    let input_redacted = if method == "login" {
        "redacted".to_string()
    } else {
        format!("{:?}", input)
    };

    info!("GDKRUST_call_session handle_call {} input {:?}", method, input_redacted);
    let res = match sess.backend {
        GdkBackend::Electrum(ref mut s) => handle_call(s, &method, &input),
        // GdkSession::Rpc(ref s) => handle_call(s, method),
    };

    let res_string = format!("{:?}", res).truncate(200);
    info!("GDKRUST_call_session {} {:?}", method, res_string);

    match res {
        Ok(ref val) => json_res!(output, val, GA_OK),

        Err(ref e) => {
            let code = e.to_gdk_code();
            let desc = e.gdk_display();

            info!("rust error {}: {}", code, desc);
            json_res!(output, json!({ "error": code, "message": desc }), GA_OK)
        }
    }
}

#[no_mangle]
pub extern "C" fn GDKRUST_set_notification_handler(
    sess: *mut GdkSession,
    handler: extern "C" fn(*const libc::c_void, *const GDKRUST_json),
    self_context: *const libc::c_void,
) -> i32 {
    let sess = safe_mut_ref!(sess);
    let backend = &mut sess.backend;

    match backend {
        GdkBackend::Electrum(ref mut s) => s.notify = NativeNotif(Some((handler, self_context))),
    };

    info!("set notification handler");

    GA_OK
}

fn fetch_exchange_rate_sources(sources: Vec<&dyn Source>) -> Vec<Ticker> {
    let reqs = prepare_requests(sources, Pair::new_btc(Currency::USD));
    let client = make_tls_hyper_client();
    let res = hyper_fetch_requests(&client, &reqs);

    // NOTE: we probably never want to error on empty sources. Just return nothing
    if res.is_none() {
        return Vec::new();
    }
    let okres = res.unwrap();

    okres.rates.get_vec().clone()
}

fn fetch_exchange_rates() -> Vec<Ticker> {
    let wasabi = Wasabi::new("https://wasabiwallet.io");
    let bitfinex = Bitfinex::new();

    let sources: Vec<&dyn Source> = vec![&bitfinex, &wasabi];
    // TODO (jb55): shuffle sources?

    fetch_exchange_rate_sources(sources)
}

fn tickers_to_json(tickers: Vec<Ticker>) -> Value {
    let empty_map = serde_json::map::Map::new();
    let currency_map = Value::Object(tickers.iter().fold(empty_map, |mut acc, ticker| {
        let currency = ticker.pair.second();
        acc.insert(currency.to_string(), ticker.rate.to_string().into());
        acc
    }));

    json!({ "currencies": currency_map })
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

        "get_subaccounts" => {
            session.get_subaccounts().map(|x| serialize::subaccounts_value(&x)).map_err(Into::into)
        }

        "get_subaccount" => get_subaccount(session, input),

        "get_transactions" => {
            let opt: GetTransactionsOpt = serde_json::from_value(input.clone())?;
            session.get_transactions(&opt).map(|x| txs_result_value(&x)).map_err(Into::into)
        }

        "get_transaction_details" => get_transaction_details(session, input),
        "get_balance" => serialize::get_balance(session, input),
        "set_transaction_memo" => set_transaction_memo(session, input),
        "create_transaction" => serialize::create_transaction(session, input),
        "sign_transaction" => session
            .sign_transaction(&serde_json::from_value(input.clone())?)
            .map_err(Into::into)
            .map(|v| json!(v)),
        "send_transaction" => session
            .send_transaction(&serde_json::from_value(input.clone())?)
            .map(|v| json!(v))
            .map_err(Into::into),
        "broadcast_transaction" => {
            session
                .broadcast_transaction(input.as_str().ok_or_else(|| {
                    Error::Other("broadcast_transaction: input not a string".into())
                })?)
                .map(|v| json!(v))
                .map_err(Into::into)
        }

        "get_receive_address" => {
            let a = session
                .get_receive_address(input)
                .map(|x| serde_json::to_value(&x).unwrap())
                .map_err(Into::into);
            info!("gdk_rust get_receive_address returning {:?}", a);
            a
        }

        "get_mnemonic" => session
            .get_mnemonic()
            .map(|m| Value::String(m.clone().get_mnemonic_str()))
            .map_err(Into::into),

        "get_fee_estimates" => {
            session.get_fee_estimates().map_err(Into::into).and_then(|x| fee_estimate_values(&x))
        }

        "get_settings" => session.get_settings().map_err(Into::into).map(|s| json!(s)),
        "get_available_currencies" => session.get_available_currencies().map_err(Into::into),
        "change_settings" => session
            .change_settings(&serde_json::from_value(input.clone())?)
            .map(|v| json!(v))
            .map_err(Into::into),

        "refresh_assets" => session
            .refresh_assets(&serde_json::from_value(input.clone())?)
            .map(|v| json!(v))
            .map_err(Into::into),

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
    trace!("GA_destroy_json({:?})", ptr);
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

#[cfg(not(feature = "android_log"))]
static LOGGER: SimpleLogger = SimpleLogger;

pub struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            if record.level() <= LevelFilter::Warn {
                println!("{} - {}", record.level(), record.args());
            } else {
                println!("{}", record.args());
            }
        }
    }

    fn flush(&self) {}
}
