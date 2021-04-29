#[macro_use]
extern crate serde_json;

#[macro_use]
extern crate log;

pub mod error;
mod serialize;

use crate::serialize::*;
use gdk_common::wally::{make_str, read_str};
use serde_json::Value;

#[cfg(feature = "android_log")]
use android_logger::{Config, FilterBuilder};
#[cfg(feature = "android_log")]
use log::Level;
use std::ffi::CString;
use std::fmt;
use std::mem::transmute;
use std::os::raw::c_char;
use std::sync::Once;
use std::time::{Duration, SystemTime};

use gdk_common::model::{
    CreateAccountOpt, GDKRUST_json, GetNextAccountOpt, GetTransactionsOpt, RenameAccountOpt,
    SPVVerifyTx, SetAccountHiddenOpt, UpdateAccountOpt,
};
use gdk_common::session::Session;

use crate::error::Error;
use chrono::Utc;
use gdk_electrum::{ElectrumSession, NativeNotif};
use log::{LevelFilter, Metadata, Record};
use std::str::FromStr;

pub const GA_OK: i32 = 0;
pub const GA_ERROR: i32 = -1;
pub const GA_NOT_AUTHORIZED: i32 = -5;

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
    let network = &safe_ref!(network).0;
    let level = if network.is_object() {
        match network.as_object().unwrap().get("log_level") {
            Some(Value::String(val)) => LevelFilter::from_str(val).unwrap_or(LevelFilter::Info),
            _ => LevelFilter::Info,
        }
    } else {
        LevelFilter::Info
    };
    init_logging(level);
    debug!("init logging");

    let sess = create_session(&network);

    if let Err(err) = sess {
        error!("create_session error: {}", err);
        return GA_ERROR;
    }

    let sess = unsafe { transmute(Box::new(sess.unwrap())) };

    ok!(ret, sess, GA_OK)
}

/// Initialize the logging framework.
/// Note that once initialized it cannot be changed, only by reloading the library.
fn init_logging(level: LevelFilter) {
    #[cfg(feature = "android_log")]
    INIT_LOGGER.call_once(|| {
        android_logger::init_once(
            Config::default().with_min_level(level.to_level().unwrap_or(Level::Error)).with_filter(
                FilterBuilder::new().parse("warn,gdk_rust=debug,gdk_electrum=debug").build(),
            ),
        )
    });

    #[cfg(not(feature = "android_log"))]
    INIT_LOGGER.call_once(|| {
        log::set_logger(&LOGGER)
            .map(|()| log::set_max_level(level))
            .expect("cannot initialize logging");
    });
}

fn create_session(network: &Value) -> Result<GdkSession, Value> {
    info!("create_session {:?}", network);
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
    let proxy = network["proxy"].as_str();

    match network["server_type"].as_str() {
        // Some("rpc") => GDKRUST_session::Rpc( GDKRPC_session::create_session(parsed_network.unwrap()).unwrap() ),
        Some("electrum") => {
            let url = gdk_electrum::determine_electrum_url_from_net(&parsed_network)
                .map_err(|x| json!(x))?;

            let session = ElectrumSession::new_session(parsed_network, db_root, proxy, url)
                .map_err(|x| json!(x))?;
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
        debug!("hit exchange rate cache");
    } else {
        info!("missed exchange rate cache");
        let agent = match sess.backend {
            GdkBackend::Electrum(ref s) => s.build_request_agent(),
        };
        if let Ok(agent) = agent {
            let rates = fetch_exchange_rates(agent);
            // still record time even if we get no results
            sess.last_xr_fetch = SystemTime::now();
            if !rates.is_empty() {
                // only set last_xr if we got new non-empty rates
                sess.last_xr = Some(rates);
            }
        }
    }

    sess.last_xr.clone()
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

    let sess = safe_mut_ref!(sess);

    if method == "exchange_rates" {
        let rates = fetch_cached_exchange_rates(sess).unwrap_or_default();
        return json_res!(output, tickers_to_json(rates), GA_OK);
    }

    // Redact inputs containing private data
    let methods_to_redact = vec!["login", "register_user", "set_pin", "create_subaccount"];
    let input_str = format!("{:?}", &input);
    let input_redacted = if methods_to_redact.contains(&method.as_str())
        || input_str.contains("mnemonic")
        || input_str.contains("xprv")
    {
        "redacted".to_string()
    } else {
        input_str
    };

    info!("GDKRUST_call_session handle_call {} input {:?}", method, input_redacted);
    let res = match sess.backend {
        GdkBackend::Electrum(ref mut s) => handle_call(s, &method, &input),
        // GdkSession::Rpc(ref s) => handle_call(s, method),
    };

    let mut output_redacted = if method == "get_mnemonic" {
        "redacted".to_string()
    } else {
        format!("{:?}", res)
    };
    output_redacted.truncate(200);
    info!("GDKRUST_call_session {} output {:?}", method, output_redacted);

    match res {
        Ok(ref val) => json_res!(output, val, GA_OK),
        Err(ref e) => {
            let code = e.to_gdk_code();
            let desc = e.gdk_display();

            let ret_val = match e {
                Error::Electrum(gdk_electrum::error::Error::InvalidPin) => GA_NOT_AUTHORIZED,
                Error::Electrum(gdk_electrum::error::Error::PinError) => GA_ERROR,
                _ => GA_OK,
            };

            info!("rust error {}: {}", code, desc);
            json_res!(output, json!({ "error": code, "message": desc }), ret_val)
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

fn fetch_exchange_rates(agent: ureq::Agent) -> Vec<Ticker> {
    if let Ok(result) =
        agent.get("https://api-pub.bitfinex.com/v2/tickers?symbols=tBTCUSD").call().into_json()
    {
        if let Value::Array(array) = result {
            if let Some(Value::Array(array)) = array.get(0) {
                // using BIDPRICE https://docs.bitfinex.com/reference#rest-public-tickers
                if let Some(rate) = array.get(1).and_then(|e| e.as_f64()) {
                    let pair = Pair::new(Currency::BTC, Currency::USD);
                    let ticker = Ticker {
                        pair,
                        rate,
                    };
                    info!("got exchange rate {:?}", ticker);
                    return vec![ticker];
                }
            }
        }
    }
    vec![]
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
        "login_with_pin" => login_with_pin(session, input).map(|v| json!(v)),
        "set_pin" => session
            .set_pin(&serde_json::from_value(input.clone())?)
            .map(|v| json!(v))
            .map_err(Into::into),

        "get_subaccounts" => {
            session.get_subaccounts().map(|x| serialize::subaccounts_value(&x)).map_err(Into::into)
        }

        "get_subaccount" => get_subaccount(session, input),

        "create_subaccount" => {
            let opt: CreateAccountOpt = serde_json::from_value(input.clone())?;
            session
                .create_subaccount(opt)
                .map(|x| serialize::subaccount_value(&x))
                .map_err(Into::into)
        }
        "get_next_subaccount" => {
            let opt: GetNextAccountOpt = serde_json::from_value(input.clone())?;
            session
                .get_next_subaccount(opt)
                .map(|next_subaccount| json!(next_subaccount))
                .map_err(Into::into)
        }
        "rename_subaccount" => {
            let opt: RenameAccountOpt = serde_json::from_value(input.clone())?;
            session.rename_subaccount(opt).map(|_| json!(true)).map_err(Into::into)
        }
        "set_subaccount_hidden" => {
            let opt: SetAccountHiddenOpt = serde_json::from_value(input.clone())?;
            session.set_subaccount_hidden(opt).map(|_| json!(true)).map_err(Into::into)
        }
        "update_subaccount" => {
            let opt: UpdateAccountOpt = serde_json::from_value(input.clone())?;
            session.update_subaccount(opt).map(|_| json!(true)).map_err(Into::into)
        }

        "get_transactions" => {
            let opt: GetTransactionsOpt = serde_json::from_value(input.clone())?;
            session.get_transactions(&opt).map(|x| txs_result_value(&x)).map_err(Into::into)
        }

        "get_transaction_details" => get_transaction_details(session, input),
        "get_balance" => session
            .get_balance(&serde_json::from_value(input.clone())?)
            .map(|v| json!(v))
            .map_err(Into::into),
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
                .get_receive_address(&serde_json::from_value(input.clone())?)
                .map(|x| serde_json::to_value(&x).unwrap())
                .map_err(Into::into);
            info!("gdk_rust get_receive_address returning {:?}", a);
            a
        }

        "get_mnemonic" => {
            session.get_mnemonic().map(|m| Value::String(m.get_mnemonic_str())).map_err(Into::into)
        }

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
        "get_unspent_outputs" => session
            .get_unspent_outputs(&serde_json::from_value(input.clone())?)
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

#[no_mangle]
pub extern "C" fn GDKRUST_spv_verify_tx(input: *const GDKRUST_json) -> i32 {
    init_logging(LevelFilter::Info);
    info!("GDKRUST_spv_verify_tx");
    let input: &Value = &safe_ref!(input).0;
    let input: SPVVerifyTx = match serde_json::from_value(input.clone()) {
        Ok(val) => val,
        Err(e) => {
            warn!("{:?}", e);
            return -1;
        }
    };
    match gdk_electrum::headers::spv_verify_tx(&input) {
        Ok(res) => res.as_i32(),
        Err(e) => {
            warn!("{:?}", e);
            -1
        }
    }
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
            println!("{} {} - {}", Utc::now().format("%S%.3f"), record.level(), record.args());
        }
    }

    fn flush(&self) {}
}

#[derive(PartialEq, Eq, Debug, Clone)]
pub enum Currency {
    BTC,
    USD,
    CAD,
    // LBTC,
    Other(String),
}

impl std::str::FromStr for Currency {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Error> {
        // println!("currency from_str {}", s);
        if s.len() < 3 {
            return Err("ticker length less than 3".to_string().into());
        }

        // TODO: support harder to parse pairs (LBTC?)
        match s {
            "USD" => Ok(Currency::USD),
            "CAD" => Ok(Currency::CAD),
            "BTC" => Ok(Currency::BTC),
            "" => Err("empty ticker".to_string().into()),
            other => Ok(Currency::Other(other.into())),
        }
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Currency::USD => "USD",
            Currency::CAD => "CAD",
            Currency::BTC => "BTC",
            // Currency::LBTC => "LBTC",
            Currency::Other(ref s) => s,
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Pair((Currency, Currency));

impl Pair {
    pub fn new(c1: Currency, c2: Currency) -> Pair {
        Pair((c1, c2))
    }

    pub fn new_btc(c: Currency) -> Pair {
        Pair((Currency::BTC, c))
    }

    pub fn first(&self) -> &Currency {
        &(self.0).0
    }

    pub fn second(&self) -> &Currency {
        &(self.0).1
    }
}

impl fmt::Display for Pair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.first(), self.second())
    }
}

#[derive(Debug, Clone)]
pub struct Ticker {
    pub pair: Pair,
    pub rate: f64,
}
