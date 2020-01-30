extern crate libc;
#[cfg(feature = "stderr_logger")]
extern crate stderrlog;
#[macro_use]
extern crate serde_json;
#[macro_use]
extern crate log;
#[macro_use]
extern crate lazy_static;

extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate bitcoincore_rpc;
extern crate rand;
extern crate url;

//extern crate gdk_rpc;

use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::path::Path;
use std::{env, fs, mem, ptr, sync};

use bitcoin::secp256k1;
use bitcoin_hashes::sha256d;
use bitcoincore_rpc::RpcApi;
use serde_json::Value;

const GA_OK: i32 = 0;
const GA_ERROR: i32 = -1;
const GA_TRUE: u32 = 1;
const GA_FALSE: u32 = 0;

#[repr(C)]
pub struct GDKRUST_json {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GDKRUST_session {
    _private: [u8; 0],
}

#[repr(C)]
pub struct GA_auth_handler {
    _private: [u8; 0],
}

#[link(name = "gdk_rust")]
extern "C" {
    fn GDKRUST_get_networks(ret: *mut *const GDKRUST_json) -> i32;
    fn GDKRUST_get_available_currencies(
        sess: *const GDKRUST_session,
        ret: *mut *const GDKRUST_json,
    ) -> i32;
    fn GDKRUST_get_fee_estimates(
        sess: *const GDKRUST_session,
        ret: *mut *const GDKRUST_json,
    ) -> i32;
    fn GDKRUST_get_mnemonic_passphrase(
        sess: *const GDKRUST_session,
        password: *const c_char,
        ret: *mut *const c_char,
    ) -> i32;
    fn GDKRUST_convert_amount(
        sess: *const GDKRUST_session,
        details: *const GDKRUST_json,
        ret: *mut *const GDKRUST_json,
    ) -> i32;

    fn GDKRUST_create_session(ret: *mut *mut GDKRUST_session) -> i32;
    fn GDKRUST_connect(sess: *mut GDKRUST_session, network: *const c_char, log_level: u32) -> i32;

    fn GDKRUST_get_settings(sess: *const GDKRUST_session, ret: *mut *const GDKRUST_json) -> i32;
    fn GDKRUST_change_settings(
        sess: *const GDKRUST_session,
        new_settings: *const GDKRUST_json,
        ret: *mut *const GA_auth_handler,
    ) -> i32;

    fn GDKRUST_get_receive_address(
        sess: *const GDKRUST_session,
        details: *const GDKRUST_json,
        ret: *mut *const GDKRUST_json,
    ) -> i32;

    fn GDKRUST_get_balance(
        sess: *const GDKRUST_session,
        details: *const GDKRUST_json,
        ret: *mut *const GDKRUST_json,
    ) -> i32;

    fn GDKRUST_register_user(
        sess: *mut GDKRUST_session,
        _hw_device: *const GDKRUST_json,
        mnemonic: *const c_char,
        auth_handler: *mut *const GA_auth_handler,
    ) -> i32;
    fn GDKRUST_login(
        sess: *mut GDKRUST_session,
        _hw_device: *const GDKRUST_json,
        mnemonic: *const c_char,
        password: *const c_char,
        auth_handler: *mut *const GA_auth_handler,
    ) -> i32;

    fn GDKRUST_get_transactions(
        sess: *mut GDKRUST_session,
        details: *const GDKRUST_json,
        ret: *mut *const GDKRUST_json,
    ) -> i32;

    fn GDKRUST_get_transaction_details(
        sess: *mut GDKRUST_session,
        txid: *const c_char,
        ret: *mut *const GDKRUST_json,
    ) -> i32;

    fn GDKRUST_create_transaction(
        sess: *const GDKRUST_session,
        details: *const GDKRUST_json,
        ret: *mut *const GDKRUST_json,
    ) -> i32;

    fn GDKRUST_sign_transaction(
        sess: *const GDKRUST_session,
        details: *const GDKRUST_json,
        ret: *mut *const GA_auth_handler,
    ) -> i32;

    fn GDKRUST_send_transaction(
        sess: *const GDKRUST_session,
        details: *const GDKRUST_json,
        ret: *mut *const GA_auth_handler,
    ) -> i32;

    fn GDKRUST_set_transaction_memo(
        sess: *const GDKRUST_session,
        txid: *const c_char,
        memo: *const c_char,
        memo_type: u32,
    ) -> i32;

    fn GDKRUST_set_pin(
        sess: *const GDKRUST_session,
        mnemonic: *const c_char,
        pin: *const c_char,
        device_id: *const c_char,
        ret: *mut *const GDKRUST_json,
    ) -> i32;
    fn GDKRUST_login_with_pin(
        sess: *const GDKRUST_session,
        device_id: *const c_char,
        pin_data: *const GDKRUST_json,
    ) -> i32;

    fn GDKRUST_auth_handler_get_status(
        handler: *const GA_auth_handler,
        ret: *mut *const GDKRUST_json,
    ) -> i32;

    fn GDKRUST_set_notification_handler(
        sess: *mut GDKRUST_session,
        handler: extern "C" fn(*const GDKRUST_json, *const GDKRUST_json),
        context: *const GDKRUST_json,
    ) -> i32;

    fn GDKRUST_destroy_session(sess: *const GDKRUST_session) -> i32;

    fn GDKRUST_convert_json_to_string(json: *const GDKRUST_json, ret: *mut *const c_char) -> i32;
    fn GDKRUST_convert_string_to_json(jstr: *const c_char, ret: *mut *const GDKRUST_json) -> i32;

    fn GDKRUST_destroy_auth_handler(handler: *const GA_auth_handler) -> i32;
    fn GDKRUST_destroy_json(json: *const GDKRUST_json) -> i32;
    fn GDKRUST_destroy_string(s: *const c_char) -> i32;

    // this method only exists for testing purposes
    fn GDKRUST_test_tick(sess: *mut GDKRUST_session) -> i32;
}

// TODO free up resources
// --test-threads=1

static LOGGER: sync::Once = sync::Once::new();
enum TestMode {
    BitcoinRegtest,
    ElementsRegtest,
}
lazy_static! {
    static ref TEST_MODE: TestMode = match ::std::env::var("TEST_MODE") {
        Ok(m) => match m.as_str() {
            "bitcoinregtest" | "" => TestMode::BitcoinRegtest,
            "elementsregtest" => TestMode::ElementsRegtest,
            _ => panic!("invalid TEST_MODE value: {}", m),
        },
        Err(::std::env::VarError::NotPresent) => TestMode::BitcoinRegtest,
        Err(e) => panic!("invalid TEST_MODE env var: {}", e),
    };
}

/// The test setup function.
fn setup_nologin() -> *mut GDKRUST_session {
    LOGGER.call_once(|| {
        #[cfg(feature = "stderr_logger")]
        stderrlog::new().verbosity(3).init().unwrap();
    });

    // create new session
    let mut sess: *mut GDKRUST_session = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_create_session(&mut sess) });

    // connect
    let network_str = env::var("GDK_RPC_NETWORK").unwrap_or("regtest-cookie".to_string());
    let network = CString::new(network_str).unwrap();
    assert_eq!(GA_OK, unsafe { GDKRUST_connect(sess, network.as_ptr(), 5) });
    debug!("connected");

    sess
}

/// Setup with login.
fn setup() -> *mut GDKRUST_session {
    let sess = setup_nologin();

    let hw_device = make_json(json!({ "type": "trezor" }));
    // generate a new mnemonic
    let mut mnemonic_ptr = generate_mnemonic();
    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_register_user(sess, hw_device, mnemonic_ptr, &mut auth_handler)
    });

    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    let password = CString::new("").unwrap();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_login(sess, hw_device, mnemonic_ptr, password.as_ptr(), &mut auth_handler)
    });

    sess
}

/// The test teardown function.
fn teardown(sess: *mut GDKRUST_session) {
    debug!("destroying session");
    assert_eq!(GA_OK, unsafe { GDKRUST_destroy_session(sess) })
}

lazy_static! {
    static ref SECP: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
    static ref BITCOIND: bitcoincore_rpc::Client = {
        let base_rpc_url =
            env::var("BITCOIND_URL").ok().unwrap_or_else(|| "http://127.0.0.1:18443".to_string());
        let rpc_url = url::Url::parse(&base_rpc_url).unwrap().join("/wallet/").unwrap().to_string();
        let rpc_cookie = env::var("BITCOIND_DIR")
            .ok()
            .map(|p| Path::new(&p).join(".cookie").to_string_lossy().into_owned());
        let contents = fs::read_to_string(rpc_cookie.unwrap()).unwrap();
        let parts: Vec<&str> = contents.split(":").collect();
        let auth = bitcoincore_rpc::Auth::UserPass(parts[0].to_string(), parts[1].to_string());
        bitcoincore_rpc::Client::new(rpc_url, auth).unwrap()
    };
}

fn tick(sess: *mut GDKRUST_session) {
    assert_eq!(GA_OK, unsafe { GDKRUST_test_tick(sess) });
}

fn mine_blocks(n: u64) -> Vec<sha256d::Hash> {
    let address: String = BITCOIND.call("getnewaddress", &[]).unwrap();
    BITCOIND.call("generatetoaddress", &[n.into(), address.into()]).unwrap()
}

fn send_coins(address: &str, amount: f64) -> sha256d::Hash {
    let txid = BITCOIND.call("sendtoaddress", &[address.into(), amount.into()]).unwrap();
    info!("send_coins(): Send {} BTC to {} in txid {}", amount, address, txid);
    txid
}

#[test]
fn test_notifications() {
    let sess = setup_nologin();

    let ctx = make_json(json!({ "test": "my ctx" }));
    assert_eq!(GA_OK, unsafe { GDKRUST_set_notification_handler(sess, notification_handler, ctx) });

    teardown(sess);
}

#[test]
fn test_account() {
    let sess = setup_nologin();

    let hw_device = make_json(json!({ "type": "trezor" }));
    let mnemonic =
        "guilt wheat author asset pledge element again humble six trouble pig write cigar ecology copy blanket tackle pupil doll one media lift ability episode".to_string();
    let mnemonic_c = CString::new(mnemonic.clone()).unwrap();
    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_register_user(sess, hw_device, mnemonic_c.as_ptr(), &mut auth_handler)
    });
    debug!("register status: {:?}", get_status(auth_handler));

    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    let password = CString::new("").unwrap();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_login(sess, hw_device, mnemonic_c.as_ptr(), password.as_ptr(), &mut auth_handler)
    });
    debug!("log in status: {:?}", get_status(auth_handler));

    let mut mnemonic_r: *const c_char = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_get_mnemonic_passphrase(sess, password.as_ptr(), &mut mnemonic_r)
    });
    let mnemonic_r = read_str(mnemonic_r);
    // FIXME turn off loggin of mnemonic (here and elsewhere)
    debug!("get_mnemonic_passphrase: {}", mnemonic_r);
    assert_eq!(mnemonic_r, mnemonic);

    teardown(sess);
}

#[test]
fn test_currencies() {
    let sess = setup();

    let mut currencies: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_available_currencies(sess, &mut currencies) });
    debug!("currencies: {:?}\n", read_json(currencies));

    let details = make_json(json!({ "satoshi": 1234567 }));
    let mut units: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_convert_amount(sess, details, &mut units) });
    debug!("converted units from satoshi: {:?}\n", read_json(units));

    let details = make_json(json!({ "btc": 0.1 }));
    let mut units: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_convert_amount(sess, details, &mut units) });
    debug!("converted units from btc: {:?}\n", read_json(units));

    let details = make_json(json!({ "fiat": 400 }));
    let mut units: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_convert_amount(sess, details, &mut units) });
    debug!("converted units from fiat: {:?}\n", read_json(units));

    teardown(sess);
}

#[test]
fn test_estimates() {
    let sess = setup();

    let mut estimates: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_fee_estimates(sess, &mut estimates) });
    info!("fee estimates: {:?}\n", read_json(estimates));

    teardown(sess);
}

#[test]
fn test_transactions() {
    let sess = setup();

    let details = make_json(json!({ "page_id": 0 }));
    let mut txs: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_transactions(sess, details, &mut txs) });
    debug!("txs: {:#?}\n", read_json(txs));

    teardown(sess);
}

#[test]
fn test_get_address() {
    let sess = setup();

    let details = make_json(json!({"subaccount": 0, "address_type": "csv"}));
    let mut recv_addr: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_receive_address(sess, details, &mut recv_addr) });
    debug!("recv addr: {:#?}\n", read_json(recv_addr));

    teardown(sess);
}

#[test]
fn test_balance() {
    let sess = setup();

    let details = make_json(json!({ "subaccount": 0, "num_confs": 0 }));
    let mut balance: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_balance(sess, details, &mut balance) });
    let balance_before = read_json(balance)["btc"].as_str().unwrap().to_owned();
    debug!("balance_before: {}\n", balance_before);
    assert_eq!("0", balance_before);

    // receive some coins
    let details = make_json(json!({"subaccount": 0, "address_type": "csv"}));
    let mut recv_addr: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_receive_address(sess, details, &mut recv_addr) });
    let address = read_json(recv_addr)["address"].as_str().unwrap().to_owned();
    debug!("Received coins to addr {} in txid {}", address, send_coins(&address, 50.0));
    mine_blocks(6);

    // balance now
    let details = make_json(json!({ "subaccount": 0, "num_confs": 0 }));
    let mut balance: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_balance(sess, details, &mut balance) });
    let balance_after = read_json(balance)["btc"].as_str().unwrap().to_owned();
    debug!("balance_after: {}\n", balance_after);
    assert_eq!("50", balance_after);

    teardown(sess);
}

#[test]
fn test_settings() {
    let sess = setup();

    let mut settings: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_settings(sess, &mut settings) });
    let mut settings = read_json(settings);
    debug!("get settings: {:#?}\n", settings);
    assert_eq!(settings.get("unit").unwrap().as_str().unwrap(), "btc");

    *settings.get_mut("unit").unwrap() = json!("satoshi");

    let settings = make_json(settings);
    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_change_settings(sess, settings, &mut auth_handler) });
    debug!("change settings status: {:#?}\n", get_status(auth_handler));

    let mut settings: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_settings(sess, &mut settings) });
    let settings = read_json(settings);
    debug!("get settings again: {:#?}\n", settings);
    assert_eq!(settings.get("unit").unwrap().as_str().unwrap(), "satoshi");

    teardown(sess);
}

#[test]
fn send_tx() {
    let sess = setup();

    // receive some coins first
    let details = make_json(json!({"subaccount": 0, "address_type": "csv"}));
    let mut recv_addr: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_receive_address(sess, details, &mut recv_addr) });
    let address = read_json(recv_addr)["address"].as_str().unwrap().to_owned();
    send_coins(&address, 500.0);
    mine_blocks(10);

    let addresses = match *TEST_MODE {
        TestMode::BitcoinRegtest => {
            ("mt9XjRweetsyCtc6HaXRohJSzvV9v796Ym", "mnQUxaPB6hXKV8aGvShvuUDuXbPzhfVCy1")
        }
        TestMode::ElementsRegtest => (
            "2dtJFrDafpVJWFQnJRxcnrFPjuX83iF9gwg",
            "Azpsob9eBh85ny2TKqHH3T69vmgMb9zMVh5ouk7ubwuduNFpAEXT9xY4zkgEsRuagCQi3NhY62fYAp3R",
        ),
    };
    let details = make_json(json!({
        "addressees": [
            {
                "address": addresses.0,
                "satoshi": 569000
            },
            {
                "address": format!("bitcoin:{}", addresses.1),
                "satoshi":1000
            }
        ]
    }));
    let mut tx_detail_unsigned_ptr: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_create_transaction(sess, details, &mut tx_detail_unsigned_ptr)
    });
    let tx_detail_unsigned = read_json(tx_detail_unsigned_ptr);
    info!("create_transaction: {:#?}\n", tx_detail_unsigned);
    let err = tx_detail_unsigned["error"].as_str().unwrap();
    let err_msg = tx_detail_unsigned["error_msg"].as_str();
    assert!(err.is_empty(), "create_transaction error: {} ({:?})", err, err_msg);

    // check balance
    let details = make_json(json!({ "subaccount": 0, "num_confs": 0 }));
    let mut balance: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_balance(sess, details, &mut balance) });
    let balance = read_json(balance)["btc"].as_str().unwrap().to_owned();
    assert_eq!("500", balance);

    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_sign_transaction(sess, tx_detail_unsigned_ptr, &mut auth_handler)
    });
    let sign_status = get_status(auth_handler);
    info!("sign_transaction status: {:#?}\n", sign_status);

    let tx_detail_signed = make_json(sign_status.get("result").unwrap().clone());
    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_send_transaction(sess, tx_detail_signed, &mut auth_handler)
    });
    let status = get_status(auth_handler);
    info!("send_transaction status: {:#?}\n", status);

    let txid = CString::new(status.pointer("/result/txid").unwrap().as_str().unwrap()).unwrap();

    let mut loaded_tx: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_get_transaction_details(sess, txid.as_ptr(), &mut loaded_tx)
    });
    info!("loaded broadcasted tx: {:#?}", read_json(loaded_tx));

    //warn!("xxxxxxx");
    //::std::thread::sleep(::std::time::Duration::from_secs(160));

    let memo = CString::new("hello world").unwrap();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_set_transaction_memo(sess, txid.as_ptr(), memo.as_ptr(), 0)
    });
    debug!("set memo");

    let mut loaded_tx: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_get_transaction_details(sess, txid.as_ptr(), &mut loaded_tx)
    });
    let details = read_json(loaded_tx);
    info!("loaded tx with memo: {:?}", details);
    assert_eq!(details["memo"].as_str().unwrap(), "hello world");

    teardown(sess);
}

#[test]
fn test_pin() {
    let sess = setup();

    let mnemonic =
        "guilt wheat author asset pledge element again humble six trouble pig write cigar ecology copy blanket tackle pupil doll one media lift ability episode".to_string();
    let mnemonic = CString::new(mnemonic).unwrap();
    let pin = CString::new("1234").unwrap();
    let device_id = CString::new("foo").unwrap();
    let mut pin_data: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_set_pin(sess, mnemonic.as_ptr(), pin.as_ptr(), device_id.as_ptr(), &mut pin_data)
    });

    let pin_data = read_json(pin_data);
    debug!("pin data: {:?}", pin_data);

    let pin_data = make_json(pin_data);
    assert_eq!(GA_OK, unsafe { GDKRUST_login_with_pin(sess, pin.as_ptr(), pin_data) });

    teardown(sess);
}

#[test]
fn test_networks() {
    let sess = setup();

    let mut nets: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_networks(&mut nets) });
    debug!("networks: {:?}\n", read_json(nets));

    teardown(sess);
}

#[test]
fn test_persist_wallet() {
    //! We're gonna login and request a new receive address twice in
    //! different sessions with the same account (mnemonic) and make sure
    //! they are not identical.
    let sess = setup_nologin();

    // Some variables that we reuse.
    let entropy: [u8; 32] = rand::random();
    let mut mnemonic_ptr = generate_mnemonic();
    let mnemonic = read_str(mnemonic_ptr);
    let mnemonic_c = CString::new(mnemonic.to_string()).unwrap();
    let hw_device = make_json(json!({ "type": "trezor" }));
    let password = CString::new("").unwrap();
    let details = make_json(json!({"subaccount": 0, "address_type": "csv"}));

    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_register_user(sess, hw_device, mnemonic_c.as_ptr(), &mut auth_handler)
    });

    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_login(sess, hw_device, mnemonic_c.as_ptr(), password.as_ptr(), &mut auth_handler)
    });

    let mut recv_addr: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_receive_address(sess, details, &mut recv_addr) });
    let first_addr = read_json(recv_addr);

    teardown(sess);
    let sess = setup_nologin();

    let mut auth_handler: *const GA_auth_handler = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe {
        GDKRUST_login(sess, hw_device, mnemonic_c.as_ptr(), password.as_ptr(), &mut auth_handler)
    });

    let mut recv_addr: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_get_receive_address(sess, details, &mut recv_addr) });
    let second_addr = read_json(recv_addr);

    assert_ne!(first_addr, second_addr);
    assert_ne!(first_addr["address"], second_addr["address"]);

    teardown(sess);
}

extern "C" fn notification_handler(ctx: *const GDKRUST_json, data: *const GDKRUST_json) {
    info!("notification handler called: {:?} -- {:?}", read_json(ctx), read_json(data));
}

mod wally {
    use libc::{c_char, c_int, c_uchar, c_void};
    #[allow(non_camel_case_types)]
    type size_t = usize;

    pub const WALLY_OK: libc::c_int = 0;
    extern "C" {
        //WALLY_CORE_API int bip39_mnemonic_from_bytes(
        //    const struct words *w,
        //    const unsigned char *bytes,
        //    size_t bytes_len,
        //    char **output);
        pub fn bip39_mnemonic_from_bytes(
            word_list: *const c_void,
            bytes: *const c_uchar,
            bytes_len: size_t,
            output: *mut *const c_char,
        ) -> c_int;
    }
}

fn generate_mnemonic() -> *const c_char {
    let entropy: [u8; 32] = rand::random();

    let mut out = ptr::null();
    let ret = unsafe {
        wally::bip39_mnemonic_from_bytes(ptr::null(), entropy.as_ptr(), entropy.len(), &mut out)
    };
    assert_eq!(ret, wally::WALLY_OK);
    out
}

#[repr(C)]
pub struct GDKRUST_json_upstream(Value);

fn read_json(json: *const GDKRUST_json) -> Value {
    let json_upstream: *const GDKRUST_json_upstream = unsafe { mem::transmute(json) };
    unsafe { &*json_upstream }.0.clone()
}

fn make_json(val: Value) -> *const GDKRUST_json {
    unsafe { mem::transmute(Box::new(GDKRUST_json_upstream(val))) }
}

fn get_status(auth_handler: *const GA_auth_handler) -> Value {
    let mut status: *const GDKRUST_json = std::ptr::null_mut();
    assert_eq!(GA_OK, unsafe { GDKRUST_auth_handler_get_status(auth_handler, &mut status) });
    read_json(status)
}

fn make_str<'a, S: Into<Cow<'a, str>>>(data: S) -> *const c_char {
    CString::new(data.into().into_owned()).unwrap().into_raw()
}

fn read_str(s: *const c_char) -> String {
    unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_string()
}
