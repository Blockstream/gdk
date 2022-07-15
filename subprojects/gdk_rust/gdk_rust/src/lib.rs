#[macro_use]
extern crate serde_json;

#[macro_use]
extern crate log;

pub mod error;

use gdk_common::wally::{make_str, read_str};
use serde_json::Value;

use std::ffi::CString;
use std::fmt;
use std::os::raw::c_char;
use std::sync::Once;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use gdk_common::model::{InitParam, SPVDownloadHeadersParams, SPVVerifyTxParams};

use crate::error::Error;
use gdk_common::session::Session;
use gdk_electrum::error::Error as ElectrumError;
use gdk_electrum::pset::{self, ExtractParam, FromTxParam, MergeTxParam};
use gdk_electrum::{determine_electrum_url, headers, ElectrumSession};
use log::{LevelFilter, Metadata, Record};
use serde::Serialize;
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
    Greenlight(GreenlightSession),
}

pub struct GreenlightSession {}

//
// Session & account management
//

static INIT_LOGGER: Once = Once::new();

#[no_mangle]
pub extern "C" fn GDKRUST_create_session(
    ret: *mut *const libc::c_void,
    network: *const c_char,
) -> i32 {
    let network: Value = match serde_json::from_str(&read_str(network)) {
        Ok(x) => x,
        Err(err) => {
            error!("error: {:?}", err);
            return GA_ERROR;
        }
    };

    match create_session(&network) {
        Err(err) => {
            error!("create_session error: {}", err);
            GA_ERROR
        }
        Ok(session) => {
            let session = Box::new(session);
            unsafe {
                *ret = Box::into_raw(session) as *mut libc::c_void;
            };
            GA_OK
        }
    }
}

/// Initialize the logging framework.
/// Note that once initialized it cannot be changed, only by reloading the library.
fn init_logging(level: LevelFilter) {
    #[cfg(target_os = "android")]
    INIT_LOGGER.call_once(|| {
        android_logger::init_once(
            android_logger::Config::default()
                .with_min_level(level.to_level().unwrap_or(log::Level::Error))
                .with_filter(
                    android_logger::FilterBuilder::new()
                        .parse("warn,gdk_rust=debug,gdk_electrum=debug")
                        .build(),
                ),
        )
    });

    #[cfg(not(target_os = "android"))]
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

    let proxy = network["proxy"].as_str();

    let backend = match network["server_type"].as_str() {
        // Some("rpc") => GDKRUST_session::Rpc( GDKRPC_session::create_session(parsed_network.unwrap()).unwrap() ),
        Some("greenlight") => GdkBackend::Greenlight(GreenlightSession {}),
        Some("electrum") => {
            let url = determine_electrum_url(&parsed_network).map_err(|x| json!(x))?;

            let session = ElectrumSession::create_session(parsed_network, proxy, url);
            GdkBackend::Electrum(session)
        }
        _ => return Err(json!("server_type invalid")),
    };
    // some time in the past
    let last_xr_fetch = SystemTime::now() - Duration::from_secs(1000);
    let gdk_session = GdkSession {
        backend,
        last_xr_fetch,
        last_xr: None,
    };
    Ok(gdk_session)
}

fn fetch_cached_exchange_rates(sess: &mut GdkSession) -> Option<Vec<Ticker>> {
    if SystemTime::now() < (sess.last_xr_fetch + Duration::from_secs(60)) {
        debug!("hit exchange rate cache");
    } else {
        info!("missed exchange rate cache");
        let (agent, is_mainnet) = match sess.backend {
            GdkBackend::Electrum(ref s) => (s.build_request_agent(), s.network.mainnet),
            GdkBackend::Greenlight(ref _s) => (
                Err(gdk_electrum::error::Error::Generic(
                    "build_request_agent not yet implemented".to_string(),
                )),
                false,
            ),
        };
        if let Ok(agent) = agent {
            let rates = if is_mainnet {
                fetch_exchange_rates(agent)
            } else {
                vec![Ticker {
                    pair: Pair::new(Currency::BTC, Currency::USD),
                    rate: 1.1,
                }]
            };
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
    ptr: *mut libc::c_void,
    method: *const c_char,
    input: *const c_char,
    output: *mut *const c_char,
) -> i32 {
    let method = read_str(method);
    let input: Value = match serde_json::from_str(&read_str(input)) {
        Ok(x) => x,
        Err(err) => {
            error!("error: {:?}", err);
            return GA_ERROR;
        }
    };

    if ptr.is_null() {
        return GA_ERROR;
    }
    let sess: &mut GdkSession = unsafe { &mut *(ptr as *mut GdkSession) };

    if method == "exchange_rates" {
        let rates = fetch_cached_exchange_rates(sess).unwrap_or_default();
        let s = make_str(tickers_to_json(rates).to_string());
        unsafe {
            *output = s;
        }
        return GA_OK;
    }

    // Redact inputs containing private data
    let methods_to_redact_in = vec![
        "login",
        "register_user",
        "encrypt_with_pin",
        "create_subaccount",
        "credentials_from_pin_data",
    ];
    let input_str = format!("{:?}", &input);
    let input_redacted = if methods_to_redact_in.contains(&method.as_str())
        || input_str.contains("pin")
        || input_str.contains("mnemonic")
        || input_str.contains("xprv")
    {
        "redacted".to_string()
    } else {
        input_str
    };

    info!("GDKRUST_call_session handle_call {} input {:?}", method, input_redacted);
    let res = match sess.backend {
        GdkBackend::Electrum(ref mut s) => s.handle_call(&method, input).map_err(Into::into),
        GdkBackend::Greenlight(ref mut s) => handle_gl_call(s, &method, input),
    };

    let methods_to_redact_out = vec!["credentials_from_pin_data"];
    let mut output_redacted = if methods_to_redact_out.contains(&method.as_str()) {
        "redacted".to_string()
    } else {
        format!("{:?}", res)
    };
    output_redacted.truncate(200);
    info!("GDKRUST_call_session {} output {:?}", method, output_redacted);

    let (s, ret) = match res {
        Ok(ref val) => (val.to_string(), GA_OK),
        Err(ref e) => {
            let ret_val = match e {
                Error::Electrum(ElectrumError::InvalidPin) => GA_NOT_AUTHORIZED,
                _ => GA_ERROR,
            };
            let json_error = build_error(&method, e);
            (json_error, ret_val)
        }
    };
    let s = make_str(s);
    unsafe {
        *output = s;
    }
    ret
}

#[no_mangle]
pub extern "C" fn GDKRUST_set_notification_handler(
    ptr: *mut libc::c_void,
    handler: extern "C" fn(*const libc::c_void, *const c_char),
    self_context: *const libc::c_void,
) -> i32 {
    if ptr.is_null() {
        return GA_ERROR;
    }
    let sess: &mut GdkSession = unsafe { &mut *(ptr as *mut GdkSession) };
    let backend = &mut sess.backend;

    match backend {
        GdkBackend::Electrum(ref mut s) => s.notify.set_native((handler, self_context)),
        GdkBackend::Greenlight(ref mut _s) => (), // TODO,
    };

    info!("set notification handler");

    GA_OK
}

fn fetch_exchange_rates(agent: ureq::Agent) -> Vec<Ticker> {
    if let Ok(result) = agent.get("https://api-pub.bitfinex.com/v2/tickers?symbols=tBTCUSD").call()
    {
        if let Ok(Value::Array(array)) = result.into_json() {
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
        acc.insert(currency.to_string(), format!("{:.8}", ticker.rate).into());
        acc
    }));

    json!({ "currencies": currency_map })
}

fn handle_gl_call(
    _session: &mut GreenlightSession,
    method: &str,
    _input: Value,
) -> Result<Value, Error> {
    match method {
        _ => Err(Error::GreenlightMethodNotFound(method.to_string())),
    }
}

#[no_mangle]
pub extern "C" fn GDKRUST_destroy_string(ptr: *mut c_char) {
    unsafe {
        // retake pointer and drop
        let _ = CString::from_raw(ptr);
    }
}

#[no_mangle]
pub extern "C" fn GDKRUST_destroy_session(ptr: *mut libc::c_void) {
    unsafe {
        // retake pointer and drop
        let _ = Box::from_raw(ptr as *mut GdkSession);
    }
}

#[derive(serde::Serialize)]
struct JsonError {
    message: String,
    error: String,
}

fn build_error(_method: &str, error: &Error) -> String {
    let message = error.to_string();
    let error = error.to_gdk_code();
    let json_error = JsonError {
        message,
        error,
    };
    to_string(&json_error)
}

fn to_string<T: Serialize>(value: &T) -> String {
    serde_json::to_string(&value)
        .expect("Default Serialize impl with maps containing only string keys")
}

#[no_mangle]
pub extern "C" fn GDKRUST_call(
    method: *const c_char,
    input: *const c_char,
    output: *mut *const c_char,
) -> i32 {
    let method = read_str(method);
    let input = read_str(input);
    debug!("GDKRUST_call {}", &method);

    let (error_value, result) = match handle_call(&method, &input) {
        Ok(value) => (GA_OK, value),
        Err(err) => (GA_ERROR, build_error(&method, &err)),
    };

    let result = make_str(result);
    unsafe {
        *output = result;
    }
    error_value
}

fn handle_call(method: &str, input: &str) -> Result<String, Error> {
    let start = Instant::now();

    let res = match method {
        "init" => {
            let param: InitParam = serde_json::from_str(input)?;
            init_logging(LevelFilter::from_str(&param.log_level).unwrap_or(LevelFilter::Off));
            gdk_registry::init(&param.registry_dir)?;
            // TODO: read more initialization params
            to_string(&json!("".to_string()))
        }
        "psbt_extract" => {
            let param: ExtractParam = serde_json::from_str(input)?;
            to_string(&pset::extract(&param)?)
        }
        "psbt_from_tx" => {
            let param: FromTxParam = serde_json::from_str(input)?;
            to_string(&pset::from_tx(&param)?)
        }
        "psbt_merge_tx" => {
            let param: MergeTxParam = serde_json::from_str(input)?;
            to_string(&pset::merge_tx(&param)?)
        }
        "spv_verify_tx" => {
            let param: SPVVerifyTxParams = serde_json::from_str(input)?;
            to_string(&headers::spv_verify_tx(&param)?.as_i32())
        }
        "spv_download_headers" => {
            let param: SPVDownloadHeadersParams = serde_json::from_str(input)?;
            to_string(&headers::download_headers(&param)?)
        }
        "refresh_assets" => {
            let param: gdk_registry::RefreshAssetsParams = serde_json::from_str(input)?;
            to_string(&gdk_registry::refresh_assets(param)?)
        }
        "get_assets" => {
            let params: gdk_registry::GetAssetsParams = serde_json::from_str(input)?;
            to_string(&gdk_registry::get_assets(params)?)
        }

        _ => {
            return Err(Error::MethodNotFound {
                method: method.to_string(),
                in_session: false,
            })
        }
    };

    info!("`{}` took {:?}", method, start.elapsed());

    Ok(res)
}

#[cfg(not(target_os = "android"))]
static LOGGER: SimpleLogger = SimpleLogger;

pub struct SimpleLogger;

impl log::Log for SimpleLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        let level = metadata.level();
        if level > log::Level::Debug {
            level <= log::max_level()
        } else {
            level <= log::max_level()
                && !metadata.target().starts_with("rustls")
                && !metadata.target().starts_with("electrum_client")
        }
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            let ts = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards");
            println!(
                "{:02}.{:03} {} - {}",
                ts.as_secs() % 60,
                ts.subsec_millis(),
                record.level(),
                record.args()
            );
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
