mod store;

#[macro_use]
extern crate serde_json;

#[macro_use]
extern crate gdk_common;

use gdk_common::log::{debug, info, trace, warn};
use gdk_pin_client::{Pin, PinClient, PinData};
use headers::bitcoin::HEADERS_FILE_MUTEX;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub mod account;
pub mod error;
pub mod headers;
pub mod interface;
pub mod session;
pub mod spv;

use crate::account::{
    discover_account, get_account_derivation, get_account_script_purpose,
    get_last_next_account_nums, Account,
};
use crate::error::Error;
use crate::interface::ElectrumUrl;
use crate::store::*;

use gdk_common::bitcoin::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey, Fingerprint};
use gdk_common::bitcoin::hashes::hex::FromHex;
use gdk_common::{bitcoin, elements};

use gdk_common::model::*;
use gdk_common::network::NetworkParameters;
use gdk_common::wally::{
    self, asset_blinding_key_from_seed, asset_blinding_key_to_ec_private_key, MasterBlindingKey,
};
use gdk_common::{be::*, State};

use gdk_common::electrum_client::{self, ScriptStatus};
use gdk_common::elements::confidential::{self, Asset, Nonce};
use gdk_common::error::Error::{BtcEncodingError, ElementsEncodingError};
use gdk_common::exchange_rates::{Currency, ExchangeRatesCache};
use gdk_common::network;
use gdk_common::NetworkId;
use gdk_common::EC;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::path::PathBuf;
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime};
use std::{iter, thread};

use crate::headers::bitcoin::HeadersChain;
use crate::headers::liquid::Verifier;
use crate::headers::ChainOrVerifier;
use crate::spv::SpvCrossValidator;
use bitcoin_private::hex::display::DisplayHex;
use electrum_client::{Client, ElectrumApi};
use gdk_common::bitcoin::blockdata::constants::DIFFCHANGE_INTERVAL;
pub use gdk_common::notification::{NativeNotif, Notification, TransactionNotification};
use gdk_common::rand::seq::SliceRandom;
use gdk_common::rand::thread_rng;
use gdk_common::ureq;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::JoinHandle;

const CROSS_VALIDATION_RATE: u8 = 4; // Once every 4 thread loop runs, or roughly 28 seconds
pub const DEFAULT_GAP_LIMIT: u32 = 20;
const FEE_ESTIMATE_INTERVAL: Duration = Duration::from_secs(120);

type ScriptStatuses = HashMap<bitcoin::ScriptBuf, ScriptStatus>;

struct Syncer {
    accounts: Arc<RwLock<HashMap<u32, Account>>>,
    store: Store,
    master_blinding: Option<MasterBlindingKey>,
    network: NetworkParameters,
    recent_spent_utxos: Arc<RwLock<HashSet<BEOutPoint>>>,
    gap_limit: u32,
}

pub struct Tipper {
    pub store: Store,
    pub network: NetworkParameters,
}

pub struct Headers {
    pub store: Store,
    pub checker: ChainOrVerifier,
    pub cross_validator: Option<SpvCrossValidator>,
}

pub struct ElectrumSession {
    pub proxy: Option<String>,
    pub timeout: Option<u8>,
    pub network: NetworkParameters,
    pub url: ElectrumUrl,

    /// Accounts of the wallet
    pub accounts: Arc<RwLock<HashMap<u32, Account>>>,

    /// Master xpub of the signer associated to the session
    ///
    /// It is Some after wallet initialization
    pub master_xpub: Option<ExtendedPubKey>,

    /// The BIP32 fingerprint of the master xpub
    ///
    /// If watch-only `master_xpub` is `None`, thus we have this value here.
    /// If watch-only with slip132 exteneded keys, this value is not known, and we use the default value, i.e. `00000000`.
    master_xpub_fingerprint: Fingerprint,

    pub notify: NativeNotif,
    pub handles: Vec<JoinHandle<()>>,

    // True if the users wants the background threads to run
    pub user_wants_to_sync: Arc<AtomicBool>,

    // True if the last call (to the Electrum server) succeeded
    pub last_network_call_succeeded: Arc<AtomicBool>,

    pub store: Option<Store>,

    /// Master xprv of the signer associated to the session
    ///
    /// FIXME: remove this once we have fully migrated to the hw signer interface
    pub master_xprv: Option<ExtendedPrivKey>,

    /// Spent utxos
    ///
    /// Remember the spent utxos to avoid using them in transaction that are created after
    /// the previous send/broadcast tx, but before the next sync.
    ///
    /// This set it emptied after every sync.
    pub recent_spent_utxos: Arc<RwLock<HashSet<BEOutPoint>>>,

    xr_cache: ExchangeRatesCache,

    /// The keys are exchange names, the values are all the currencies that a
    /// given exchange has data for.
    available_currencies: Option<HashMap<String, Vec<Currency>>>,

    first_sync: Arc<AtomicBool>,

    /// Number of consecutive unused scripts/addresses to monitor.
    gap_limit: u32,

    /// Last time fees were asked to the server
    fee_fetched_at: Arc<Mutex<SystemTime>>,
}

#[derive(Clone)]
pub struct StateUpdater {
    current: Arc<AtomicBool>,
    notify: NativeNotif,
}

impl StateUpdater {
    fn update_if_needed(&self, new_network_call_succeeded: bool) {
        let last_network_call_succeeded =
            self.current.swap(new_network_call_succeeded, Ordering::Relaxed);
        if last_network_call_succeeded != new_network_call_succeeded {
            // The second parameter should be taken from the state of the threads, but the current state could
            // be changed only if threads are running so we use the constant `State::Connected`
            let state: State = new_network_call_succeeded.into();
            self.notify.network(state, State::Connected);
        }
    }
}

fn socksify(proxy: Option<&str>) -> Option<String> {
    const SOCKS5: &str = "socks5://";
    if let Some(proxy) = proxy {
        let trimmed = proxy.trim();
        if trimmed.is_empty() {
            None
        } else if trimmed.starts_with(SOCKS5) {
            Some(trimmed.to_string())
        } else {
            Some(format!("{}{}", SOCKS5, trimmed))
        }
    } else {
        None
    }
}

fn try_get_fee_estimates(client: &Client) -> Result<Vec<FeeEstimate>, Error> {
    let relay_fee = (client.relay_fee()? * 100_000_000.0) as u64;
    let blocks: Vec<usize> = (1..25).collect();
    // max is covering a rounding errors in production electrs which sometimes cause a fee
    // estimates lower than relay fee
    let mut estimates: Vec<FeeEstimate> = client
        .batch_estimate_fee(blocks)?
        .iter()
        .map(|e| FeeEstimate(relay_fee.max((*e * 100_000_000.0) as u64)))
        .collect();
    estimates.insert(0, FeeEstimate(relay_fee));
    Ok(estimates)
}

#[derive(Serialize, Deserialize)]
pub struct EncryptWithPinDetails {
    /// The PIN to protect the server-provided encryption key with.
    pin: Pin,

    /// The plaintext to encrypt.
    plaintext: serde_json::Value,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct DecryptWithPinDetails {
    /// The PIN used to encrypt the `PinData`.
    pin: Pin,

    /// The data containing the plaintext to decrypt. Can be obtained by
    /// calling [`encrypt_with_pin`](ElectrumSession::encrypt_with_pin) with
    /// the same PIN.
    pin_data: PinData,
}

impl ElectrumSession {
    pub fn get_accounts(&self) -> Result<Vec<Account>, Error> {
        // The Account struct is immutable and we don't allow account deletion.
        // Thus we can clone without the risk of having inconsistent data.
        let mut accounts = self.accounts.read()?.values().cloned().collect::<Vec<Account>>();
        accounts.sort_unstable_by(|a, b| a.num().cmp(&b.num()));
        Ok(accounts)
    }

    /// Get the Account if exists
    pub fn get_account(&self, account_num: u32) -> Result<Account, Error> {
        // The Account struct is immutable, things that mutate (e.g. name) are in the store.
        // Thus we can clone without the risk of having inconsistent data.
        self.accounts
            .read()?
            .get(&account_num)
            .cloned()
            .ok_or_else(|| Error::InvalidSubaccount(account_num))
    }

    pub fn build_request_agent(&self) -> Result<ureq::Agent, Error> {
        network::build_request_agent(self.proxy.as_deref()).map_err(Into::into)
    }

    pub fn poll_session(&self) -> Result<(), Error> {
        Err(Error::Generic("implementme: ElectrumSession poll_session".into()))
    }

    pub fn connect(&mut self, net_params: &Value) -> Result<(), Error> {
        // gdk tor session may change the proxy port after a restart, so we update the proxy here
        self.proxy = socksify(net_params.get("proxy").and_then(|p| p.as_str()));

        // A call to connect signals that the caller wants the background threads to start
        self.user_wants_to_sync.store(true, Ordering::Relaxed);

        let last_network_call_succeeded = if self.master_xpub.is_some() {
            // Wallet initialized, we can start the background threads.
            self.start_threads()?;
            // Use the last persisted network call result so we don't have to wait for a network roundtrip
            self.last_network_call_succeeded.load(Ordering::Relaxed)
        } else {
            // We can't call start_threads() here because not everything is loaded before login,
            // but we need to emit a network notification, to do so we test the electrum server
            // with a ping to emit a notification
            let electrum_url = self.url.clone();
            let proxy = self.proxy.clone();
            match electrum_url.build_client(proxy.as_deref(), None) {
                Ok(client) => match client.ping() {
                    Ok(_) => {
                        info!("succesfully pinged electrum server {:?}", electrum_url.url());
                        self.last_network_call_succeeded.store(true, Ordering::Relaxed);
                        true
                    }
                    Err(e) => {
                        warn!("failed to ping electrum server {:?}: {:?}", electrum_url.url(), e);
                        false
                    }
                },
                Err(e) => {
                    warn!("build client failed {:?}", e);
                    false
                }
            }
        };

        self.notify.network(last_network_call_succeeded.into(), State::Connected);
        Ok(())
    }

    pub fn disconnect(&mut self) -> Result<(), Error> {
        // A call to disconnect signals that the caller does to wants the background threads to run
        if self.user_wants_to_sync.swap(false, Ordering::Relaxed) {
            // This is an actual disconnect, stop the threads and send the notification
            self.join_threads();

            // The following flush is redundant since a flush is done when the store is dropped,
            // however it's safer to call it also here because some garbage collected caller could
            // postpone the object drop. Moreover, since we check the hash of what is written and
            // avoid touching disk if equivalent to last, it isn't a big performance penalty.
            // disconnect() may be called without login, so we check the store is loaded.
            if let Ok(store) = self.store() {
                store.write()?.flush()?;
            }
            self.notify.network(State::Disconnected, State::Disconnected);
        }
        Ok(())
    }

    fn inner_decrypt_with_pin(&self, details: &DecryptWithPinDetails) -> Result<Vec<u8>, Error> {
        let agent = self.build_request_agent()?;

        let pin_client = PinClient::new(
            agent,
            self.network.pin_server_url()?,
            self.network.pin_server_public_key()?,
        );

        pin_client.decrypt(&details.pin_data, &details.pin).map_err(Into::into)
    }

    pub fn decrypt_with_pin(
        &self,
        details: &DecryptWithPinDetails,
    ) -> Result<serde_json::Value, Error> {
        let decrypted = self.inner_decrypt_with_pin(details)?;
        if let Ok(plaintext) = serde_json::from_slice(&decrypted) {
            Ok(plaintext)
        } else {
            let credentials = bare_mnemonic_from_utf8(&decrypted)?;
            Ok(serde_json::to_value(credentials)?)
        }
    }

    pub fn credentials_from_pin_data(
        &self,
        details: &DecryptWithPinDetails,
    ) -> Result<Credentials, Error> {
        let decrypted = self.inner_decrypt_with_pin(details)?;
        if let Ok(credentials) = serde_json::from_slice(&decrypted) {
            Ok(credentials)
        } else {
            bare_mnemonic_from_utf8(&decrypted)
        }
    }

    /// Load store and cache from disk.
    pub fn load_store(&mut self, opt: &LoadStoreOpt) -> Result<(), Error> {
        if self.store.is_none() {
            let wallet_hash_id = self.network.wallet_hash_id(&opt.master_xpub);
            let mut path: PathBuf = self.network.state_dir.as_str().into();
            std::fs::create_dir_all(&path)?; // does nothing if path exists
            path.push(wallet_hash_id);

            info!("Store root path: {:?}", path);
            let store = StoreMeta::new(&path, &opt.master_xpub, self.network.id())?;
            let store = Arc::new(RwLock::new(store));
            self.store = Some(store);
        }
        self.master_xpub = Some(opt.master_xpub);
        self.master_xpub_fingerprint =
            opt.master_xpub_fingerprint.unwrap_or_else(|| opt.master_xpub.fingerprint());
        self.notify.settings(&self.get_settings().ok_or_else(|| Error::StoreNotLoaded)?);
        Ok(())
    }

    /// Remove the persisted cache and store
    ///
    /// The actual file removal will happen when the session will be dropped.
    pub fn remove_account(&mut self) -> Result<(), Error> {
        // Mark the store as to be removed when it will be dropped
        self.store()?.write()?.to_remove();
        Ok(())
    }

    /// Set the master key in the internal store, it needs to be called after `load_store`
    pub fn set_master_blinding_key(&mut self, opt: &SetMasterBlindingKeyOpt) -> Result<(), Error> {
        if let Some(master_blinding) = self.store()?.read()?.cache.master_blinding.as_ref() {
            assert_eq!(master_blinding, &opt.master_blinding_key);
        }
        self.store()?.write()?.cache.master_blinding = Some(opt.master_blinding_key.clone());
        Ok(())
    }

    /// Return the master blinding key if the cache contains it, it needs to be called after `load_store`
    pub fn get_master_blinding_key(&mut self) -> Result<GetMasterBlindingKeyResult, Error> {
        let master_blinding_key = self.store()?.read()?.cache.master_blinding.clone();
        Ok(GetMasterBlindingKeyResult {
            master_blinding_key,
        })
    }

    pub fn store(&self) -> Result<Store, Error> {
        Ok(self.store.as_ref().ok_or_else(|| Error::StoreNotLoaded)?.clone())
    }

    pub fn login_wo(&mut self, credentials: WatchOnlyCredentials) -> Result<LoginData, Error> {
        if self.network.liquid {
            return Err(Error::Generic("Watch-only login not implemented for Liquid".into()));
        }

        // Create a fake master xpub deriving it from the WatchOnlyCredentials
        let master_xpub = credentials.store_master_xpub(&self.network)?;
        let (accounts, master_xpub_fingerprint) = credentials.accounts(self.network.mainnet)?;
        self.load_store(&LoadStoreOpt {
            master_xpub,
            master_xpub_fingerprint: Some(master_xpub_fingerprint),
        })?;

        for account in accounts {
            self.create_subaccount(CreateAccountOpt {
                subaccount: account.account_num,
                name: "".to_string(),
                xpub: Some(account.xpub),
                discovered: false,
                is_already_created: true,
                allow_gaps: true,
            })?;
        }

        self.start_threads()?;
        self.get_wallet_hash_id()
    }

    pub fn login(&mut self, credentials: Credentials) -> Result<LoginData, Error> {
        info!(
            "login {:?} last network call succeeded {:?}",
            self.network, self.last_network_call_succeeded
        );

        // This check must be done before everything else to allow re-login
        if self.master_xpub.is_some() {
            // we consider login already done if wallet is some
            return self.get_wallet_hash_id();
        }

        let (master_xprv, master_xpub, master_blinding_key) =
            keys_from_credentials(&credentials, self.network.bip32_network())?;

        self.load_store(&LoadStoreOpt {
            master_xpub: master_xpub.clone(),
            master_xpub_fingerprint: None,
        })?;

        if self.network.liquid {
            if self.get_master_blinding_key()?.master_blinding_key.is_none() {
                self.set_master_blinding_key(&SetMasterBlindingKeyOpt {
                    master_blinding_key,
                })?;
            }
        }

        // Set the master xprv
        self.master_xprv = Some(master_xprv);

        // Get xpubs from signer and (re)create subaccounts
        for account_num in self.get_subaccount_nums()? {
            let path = self.get_subaccount_root_path(GetAccountPathOpt {
                subaccount: account_num,
            })?;
            let xprv = master_xprv.derive_priv(&crate::EC, &path.path).unwrap();
            let xpub = ExtendedPubKey::from_priv(&crate::EC, &xprv);

            self.create_subaccount(CreateAccountOpt {
                subaccount: account_num,
                name: "".to_string(),
                xpub: Some(xpub),
                discovered: false,
                is_already_created: true,
                allow_gaps: false,
            })?;
        }

        self.start_threads()?;
        self.get_wallet_hash_id()
    }

    pub fn join_threads(&mut self) {
        while let Some(handle) = self.handles.pop() {
            handle.join().expect("Couldn't join on the associated thread");
        }
    }

    pub fn state_updater(&self) -> Result<StateUpdater, Error> {
        Ok(StateUpdater {
            current: self.last_network_call_succeeded.clone(),
            notify: self.notify.clone(),
        })
    }

    pub fn start_threads(&mut self) -> Result<(), Error> {
        if !self.user_wants_to_sync.load(Ordering::Relaxed) {
            return Err(Error::Generic("connect must be called before start_threads".into()));
        }

        if self.handles.len() > 0 {
            // Threads are already running
            return Ok(());
        }

        let master_blinding = if self.network.liquid {
            let master_blinding = self.store()?.read()?.cache.master_blinding.clone();
            if master_blinding.is_none() {
                return Err(Error::MissingMasterBlindingKey);
            }
            master_blinding
        } else {
            None
        };

        {
            let store = self.store()?;
            let store_read = store.read()?;
            let tip_height = store_read.cache.tip_height();
            let tip_hash = store_read.cache.tip_block_hash();
            let tip_prev_hash = store_read.cache.tip_prev_block_hash();
            // Do not notify a block if we haven't fetched one yet
            if tip_hash != BEBlockHash::default() {
                self.notify.block_from_hashes(tip_height, &tip_hash, &tip_prev_hash);
            }
        };

        info!(
            "building client, url {}, proxy {}",
            self.url.url(),
            self.proxy.as_ref().unwrap_or(&"".to_string())
        );

        if let Ok(fee_client) = self.url.build_client(self.proxy.as_deref(), None) {
            info!("building built end");
            let fee_store = self.store()?;
            let fee_fetched_at = self.fee_fetched_at.clone();
            thread::spawn(move || {
                match try_get_fee_estimates(&fee_client) {
                    Ok(fee_estimates) => {
                        fee_store.write().unwrap().cache.fee_estimates = fee_estimates;
                        let mut fee_fetched_at = fee_fetched_at.lock().unwrap();
                        *fee_fetched_at = SystemTime::now();
                    }
                    Err(e) => {
                        warn!("can't update fee estimates {:?}", e)
                    }
                };
            });
        }

        let sync_interval = self.network.sync_interval.unwrap_or(1);

        if self.network.spv_enabled.unwrap_or(false) {
            let checker = match self.network.id() {
                NetworkId::Bitcoin(network) => {
                    ChainOrVerifier::Chain(HeadersChain::new(&self.network.state_dir, network)?)
                }
                NetworkId::Elements(network) => {
                    let verifier = Verifier::new(network);
                    ChainOrVerifier::Verifier(verifier)
                }
            };

            let cross_validator =
                SpvCrossValidator::from_network(&self.network, &self.proxy, self.timeout)?;

            let mut headers = Headers {
                store: self.store()?,
                checker,
                cross_validator,
            };

            let headers_url = self.url.clone();
            let proxy = self.proxy.clone();
            let notify_blocks = self.notify.clone();
            let chunk_size = DIFFCHANGE_INTERVAL as usize;
            let user_wants_to_sync = self.user_wants_to_sync.clone();
            let max_reorg_blocks = self.network.max_reorg_blocks.unwrap_or(144);

            let headers_handle = thread::spawn(move || {
                info!("starting headers thread");
                let mut round = 0u8;

                'outer: loop {
                    if wait_or_close(&user_wants_to_sync, 7) {
                        info!("closing headers thread");
                        break;
                    }
                    let mut _lock;
                    if let ChainOrVerifier::Chain(chain) = &headers.checker {
                        _lock = HEADERS_FILE_MUTEX
                            .get(&chain.network)
                            .expect("unreachable because map populate with every enum variants")
                            .lock()
                            .unwrap();
                    }

                    if let Ok(client) = headers_url.build_client(proxy.as_deref(), None) {
                        loop {
                            if !user_wants_to_sync.load(Ordering::Relaxed) {
                                info!("closing headers thread");
                                break 'outer;
                            }
                            match headers.ask(chunk_size, &client) {
                                Ok(headers_found) => {
                                    if headers_found < chunk_size {
                                        break;
                                    } else {
                                        info!("headers found: {}", headers_found);
                                    }
                                }
                                Err(Error::InvalidHeaders) => {
                                    warn!("invalid headers");
                                    // this should handle reorgs and also broke IO writes update
                                    headers.store.write().unwrap().cache.txs_verif.clear();
                                    if let Err(e) = headers.remove(max_reorg_blocks) {
                                        warn!("failed removing headers: {:?}", e);
                                        break;
                                    }
                                    // XXX clear affected blocks/txs more surgically?
                                }
                                Err(Error::Common(BtcEncodingError(_)))
                                | Err(Error::Common(ElementsEncodingError(_))) => {
                                    // We aren't able to decode the blockheaders returned by the server,
                                    // do not sync headers further.
                                    break 'outer;
                                }
                                Err(e) => {
                                    warn!("error while asking headers {}", e);
                                    thread::sleep(Duration::from_millis(500));
                                }
                            }
                        }

                        match headers.get_proofs(&client) {
                            Ok(found) => {
                                if found > 0 {
                                    info!("found proof {}", found)
                                }
                            }
                            Err(e) => warn!("error in getting proofs {:?}", e),
                        }

                        if round % CROSS_VALIDATION_RATE == 0 {
                            let status_changed = headers.cross_validate();
                            if status_changed {
                                // TODO: improve block notification
                                if let Ok(store_read) = headers.store.read() {
                                    let tip_height = store_read.cache.tip_height();
                                    let tip_hash = store_read.cache.tip_block_hash();
                                    let tip_prev_hash = store_read.cache.tip_prev_block_hash();
                                    notify_blocks.block_from_hashes(
                                        tip_height,
                                        &tip_hash,
                                        &tip_prev_hash,
                                    );
                                }
                            }
                        }

                        round = round.wrapping_add(1);
                    }
                }
            });
            self.handles.push(headers_handle);
        }

        let syncer = Syncer {
            accounts: self.accounts.clone(),
            store: self.store()?,
            master_blinding: master_blinding.clone(),
            network: self.network.clone(),
            recent_spent_utxos: self.recent_spent_utxos.clone(),
            gap_limit: self.gap_limit,
        };

        let tipper = Tipper {
            store: self.store()?,
            network: self.network.clone(),
        };

        info!("login STATUS block:{:?} tx:{}", self.block_status()?, self.tx_status()?);

        let user_wants_to_sync = self.user_wants_to_sync.clone();
        let notify = self.notify.clone();
        let url = self.url.clone();
        let proxy = self.proxy.clone();

        // Only the syncer thread is responsible to send network notification due for the state
        // of the electrum server. This is to avoid intermittent connect/disconnect if one endpoint
        // works while another don't. Once we categorize the disconnection by endpoint we can
        // monitor state of every network call.
        let state_updater = self.state_updater()?;
        let first_sync = self.first_sync.clone();

        let syncer_tipper_handle = thread::spawn(move || {
            info!("starting syncer & tipper thread");

            let mut txs_to_notify = vec![];

            // electrum_client::Client stores the last electrum_client::ScriptStatus
            // for each script it has subscribed to, however to access it we have
            // to use `script_pop` which removes the status from the Client internal
            // storage. OTOH we need to remember the last script status corresponding
            // to a script, since it is needed to determine if the script had a
            // transaction and if its status has changed w.r.t. to the cached one.
            // So we store the last statuses for each script in this map.
            let mut last_statuses = ScriptStatuses::new();

            let mut client = loop {
                // In theory this loop is superfluous, because the client is created at the
                // beginning of the next loop before being used, however, rust compiler thinks
                // it could be not initialized so we need to initialize it.
                match url.build_client(proxy.as_deref(), None) {
                    Ok(new_client) => break new_client,
                    Err(_) => {
                        if wait_or_close(&user_wants_to_sync, sync_interval) {
                            // The thread needs to stop when `user_wants_to_sync` is false.
                            // below this is done by just breaking from the main loop,
                            // but here we are out of the loop so we return.
                            // (If you start the threads without connection you are stuck in this
                            // loop so it must be handled)
                            info!(
                                "closing syncer & tipper thread by breaking build client attempts"
                            );
                            return;
                        }
                    }
                };
            };

            let mut avoid_first_wait = true;
            loop {
                let is_connected = state_updater.current.load(Ordering::Relaxed);
                debug!("loop start is_connected:{is_connected}");

                if avoid_first_wait {
                    avoid_first_wait = false;
                } else if wait_or_close(&user_wants_to_sync, sync_interval) {
                    info!("closing syncer & tipper thread");
                    break;
                }

                if !is_connected {
                    match url.build_client(proxy.as_deref(), None) {
                        Ok(new_client) => client = new_client,
                        Err(e) => {
                            warn!("cannot build client {e:?}");
                            continue;
                        }
                    };
                }

                let tip_before_sync = match tipper.server_tip(&client) {
                    Ok(height) => height,
                    Err(Error::Common(BtcEncodingError(_)))
                    | Err(Error::Common(ElementsEncodingError(_))) => {
                        // We aren't able to decode the blockheaders returned by the server,
                        // do not sync further.
                        break;
                    }
                    Err(e) => {
                        state_updater.update_if_needed(false);
                        warn!("exception in tipper {e:?}");
                        continue;
                    }
                };

                match syncer.sync(&client, &mut last_statuses, &user_wants_to_sync) {
                    Ok(tx_ntfs) => {
                        state_updater.update_if_needed(true);
                        // Skip sending transaction notifications if it's the
                        // first call to sync. This allows us to _not_ notify
                        // transactions that were sent or received before
                        // login.
                        if first_sync.load(Ordering::Relaxed) {
                            info!("first sync completed");
                        } else {
                            txs_to_notify.extend(tx_ntfs);
                        }
                        first_sync.store(false, Ordering::Relaxed);
                    }
                    Err(Error::UserDoesntWantToSync) => {
                        info!("{}", Error::UserDoesntWantToSync);
                        break;
                    }
                    Err(e) => {
                        state_updater.update_if_needed(false);
                        warn!("Error during sync, {:?}", e);
                        continue;
                    }
                }

                let tip_after_sync = match tipper.server_tip(&client) {
                    Ok(height) => height,
                    Err(_) => {
                        continue;
                    }
                };

                if tip_before_sync != tip_after_sync {
                    // If a block arrives while we are syncing
                    // transactions, transactions might be returned as
                    // unconfirmed even if they belong to the newly
                    // notified block. Sync again to ensure
                    // consistency.
                    continue;
                }
                if let Ok(Some((height, header))) =
                    tipper.update_cache_if_needed(tip_after_sync.0, tip_after_sync.1)
                {
                    notify.block_from_header(height, &header);
                }
                while let Some(ntf) = txs_to_notify.pop() {
                    info!("New tx notification: {}", ntf.txid);
                    notify.updated_txs(&ntf);
                }
            }
        });
        self.handles.push(syncer_tipper_handle);

        Ok(())
    }

    pub fn get_wallet_hash_id(&self) -> Result<LoginData, Error> {
        let master_xpub = self.master_xpub.ok_or_else(|| Error::WalletNotInitialized)?;
        Ok(LoginData {
            wallet_hash_id: self.network.wallet_hash_id(&master_xpub),
            xpub_hash_id: self.network.xpub_hash_id(&master_xpub),
        })
    }

    pub fn get_receive_address(&self, opt: &GetAddressOpt) -> Result<AddressPointer, Error> {
        debug!("get_receive_address {:?}", opt);
        let address = self.get_account(opt.subaccount)?.get_next_address(
            opt.is_internal.unwrap_or(false),
            opt.ignore_gap_limit.unwrap_or(false),
            self.gap_limit,
        )?;
        debug!("get_address {:?}", address);
        Ok(address)
    }

    pub fn get_previous_addresses(
        &self,
        opt: &GetPreviousAddressesOpt,
    ) -> Result<PreviousAddresses, Error> {
        self.get_account(opt.subaccount)?.get_previous_addresses(opt)
    }

    pub fn encrypt_with_pin(&self, details: &EncryptWithPinDetails) -> Result<PinData, Error> {
        let agent = self.build_request_agent()?;

        let pin_client = PinClient::new(
            agent,
            self.network.pin_server_url()?,
            self.network.pin_server_public_key()?,
        );

        let plaintext = serde_json::to_vec(&details.plaintext)?;
        pin_client.encrypt(&plaintext, &details.pin).map_err(Into::into)
    }

    /// Get the subaccount pointers/numbers from the store
    ///
    /// Multisig sessions receive the subaccount pointer from the server
    /// and then get the xpubs for them from the signer. We need to allow
    /// to do the same. So we fetch the subaccount pointers from the
    /// persisted store and return them here.
    pub fn get_subaccount_nums(&self) -> Result<Vec<u32>, Error> {
        let mut account_nums = self.store()?.read()?.account_nums();
        // For compatibility reason, account 0 must always be present
        if !account_nums.contains(&0) {
            // Insert it at the start to preserve sorting
            account_nums.insert(0, 0);
        }
        Ok(account_nums)
    }

    pub fn get_subaccounts(&mut self) -> Result<Vec<AccountInfoPruned>, Error> {
        self.get_accounts()?.iter().map(|a| a.info().map(|i| i.into())).collect()
    }

    pub fn get_subaccount(&self, account_num: u32) -> Result<AccountInfo, Error> {
        self.get_account(account_num)?.info()
    }

    pub fn get_subaccount_root_path(
        &mut self,
        opt: GetAccountPathOpt,
    ) -> Result<GetAccountPathResult, Error> {
        let (_, path) = get_account_derivation(opt.subaccount, self.network.id())?;
        Ok(GetAccountPathResult {
            path: path.into(),
        })
    }

    pub fn create_subaccount(&mut self, opt: CreateAccountOpt) -> Result<AccountInfo, Error> {
        let master_xprv = self.master_xprv.clone();
        let store = self.store()?.clone();
        let master_blinding = store.read()?.cache.master_blinding.clone();
        let network = self.network.clone();
        let mut accounts = self.accounts.write()?;

        // Allow discovery of already created subaccounts
        if opt.discovered {
            if let Entry::Occupied(entry) = accounts.entry(opt.subaccount) {
                store.write()?.account_cache_mut(opt.subaccount)?.bip44_discovered = opt.discovered;
                return entry.get().info();
            }
        }

        if !opt.allow_gaps {
            // Check that the given subaccount number is the next available one for its script type.
            let (script_type, _) = get_account_script_purpose(opt.subaccount)?;
            let (last_account, next_account) =
                get_last_next_account_nums(accounts.keys().copied().collect(), script_type);

            if opt.subaccount != next_account {
                // The subaccount already exists, or skips over the next available subaccount number
                bail!(Error::InvalidSubaccount(opt.subaccount));
            }
            if let Some(last_account) = last_account {
                // This is the next subaccount number, but the last one is still unused
                let account = accounts
                    .get(&last_account)
                    .ok_or_else(|| Error::InvalidSubaccount(last_account))?;
                if !opt.is_already_created && !account.has_transactions()? {
                    bail!(Error::AccountGapsDisallowed);
                }
            }
        }

        let account = match accounts.entry(opt.subaccount) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let account = entry.insert(Account::new(
                    network,
                    &master_xprv,
                    self.master_xpub_fingerprint,
                    &opt.xpub, // account xpub
                    master_blinding,
                    store,
                    opt.subaccount,
                    opt.discovered,
                )?);
                if !opt.name.is_empty() {
                    account.set_name(&opt.name)?;
                }
                account
            }
        };
        account.info()
    }

    pub fn discover_subaccount(&self, opt: DiscoverAccountOpt) -> Result<bool, Error> {
        discover_account(
            &self.url,
            self.proxy.as_deref(),
            &opt.xpub,
            opt.script_type,
            self.gap_limit,
        )
    }

    pub fn get_next_subaccount(&self, opt: GetNextAccountOpt) -> Result<u32, Error> {
        let (_, next_account) = get_last_next_account_nums(
            self.accounts.read()?.keys().copied().collect(),
            opt.script_type,
        );
        Ok(next_account)
    }

    pub fn get_last_empty_subaccount(&self, opt: GetLastEmptyAccountOpt) -> Result<u32, Error> {
        let (last_account, next_account) = get_last_next_account_nums(
            self.accounts.read()?.keys().copied().collect(),
            opt.script_type,
        );
        match last_account {
            Some(last_account) => {
                if self.get_account(last_account)?.info()?.bip44_discovered {
                    Ok(next_account)
                } else {
                    Ok(last_account)
                }
            }
            None => Ok(next_account),
        }
    }

    pub fn get_block_height(&self) -> Result<u32, Error> {
        Ok(self.store()?.read()?.cache.tip_height())
    }

    pub fn rename_subaccount(&mut self, opt: RenameAccountOpt) -> Result<bool, Error> {
        self.get_account(opt.subaccount)?.set_settings(UpdateAccountOpt {
            subaccount: opt.subaccount,
            name: Some(opt.new_name),
            hidden: None,
        })
    }

    pub fn set_subaccount_hidden(&mut self, opt: SetAccountHiddenOpt) -> Result<bool, Error> {
        self.get_account(opt.subaccount)?.set_settings(UpdateAccountOpt {
            subaccount: opt.subaccount,
            hidden: Some(opt.hidden),
            name: None,
        })
    }

    pub fn update_subaccount(&mut self, opt: UpdateAccountOpt) -> Result<bool, Error> {
        self.get_account(opt.subaccount)?.set_settings(opt)
    }

    pub fn get_transactions(&self, opt: &GetTransactionsOpt) -> Result<TxsResult, Error> {
        let mut txs = self.get_account(opt.subaccount)?.list_tx(opt)?;
        for tx in txs.iter_mut() {
            for output in tx.outputs.iter_mut() {
                if !output.is_relevant {
                    // Update the output with the information necessary for bumping
                    if let Ok(data) = self.get_scriptpubkey_data(&output.script_pubkey) {
                        // This is an output belonging to the wallet, but not to opt.subaccount
                        output.subaccount = data.subaccount;
                        output.pointer = data.pointer;
                        output.is_internal = data.is_internal;
                        output.address_type = data.address_type;
                    }
                }
            }
        }
        Ok(TxsResult(txs))
    }

    pub fn get_transaction_hex(&self, txid: &str) -> Result<String, Error> {
        let txid = BETxid::from_hex(txid, self.network.id())?;
        let store = self.store()?;
        let store = store.read()?;
        store.get_tx_entry(&txid).map(|e| e.tx.serialize().to_lower_hex_string())
    }

    pub fn get_transaction_details(&self, txid: &str) -> Result<TransactionDetails, Error> {
        let txid = BETxid::from_hex(txid, self.network.id())?;
        let store = self.store()?;
        let store = store.read()?;
        store.get_tx_entry(&txid).map(|e| e.into())
    }

    pub fn get_scriptpubkey_data(&self, script_pubkey: &str) -> Result<ScriptPubKeyData, Error> {
        let script = BEScript::from_hex(script_pubkey, self.network.id())?;
        let store = self.store()?;
        let store = store.read()?;
        let accounts = self.get_accounts()?;
        for account in accounts.iter() {
            let account_cache = store.account_cache(account.num())?;
            if let Ok(path) = account_cache.get_path(&script) {
                let (is_internal, pointer) = parse_path(path)?;
                return Ok(ScriptPubKeyData {
                    subaccount: account.num(),
                    branch: 1,
                    pointer: pointer,
                    subtype: 0,
                    is_internal: is_internal,
                    address_type: account.script_type().to_string(),
                });
            }
        }
        return Err(Error::ScriptPubkeyNotFound);
    }

    pub fn get_balance(&self, opt: &GetBalanceOpt) -> Result<Balances, Error> {
        let mut result = HashMap::new();
        // bitcoin balance is always set even if 0
        match self.network.id() {
            NetworkId::Bitcoin(_) => result.entry("btc".to_string()).or_insert(0),
            NetworkId::Elements(_) => {
                result.entry(self.network.policy_asset.as_ref().unwrap().clone()).or_insert(0)
            }
        };

        // Compute balance from get_unspent_outputs
        let opt = GetUnspentOpt {
            subaccount: opt.subaccount,
            num_confs: Some(opt.num_confs),
            confidential_utxos_only: opt.confidential_utxos_only,
            all_coins: None,
        };
        let unspent_outputs = self.get_unspent_outputs(&opt)?;
        for (asset, utxos) in unspent_outputs.0.iter() {
            let asset_balance = utxos.iter().map(|u| u.satoshi).sum::<u64>();
            *result.entry(asset.clone()).or_default() += asset_balance as i64;
        }

        Ok(result)
    }

    pub fn set_transaction_memo(&self, txid: &str, memo: &str) -> Result<(), Error> {
        let txid = BETxid::from_hex(txid, self.network.id())?;
        if memo.len() > 1024 {
            return Err(Error::Generic("Too long memo (max 1024)".into()));
        }
        self.store()?.write()?.insert_memo(txid, memo)?;

        Ok(())
    }

    fn remove_recent_spent_utxos(&self, tx_req: &mut CreateTransaction) -> Result<(), Error> {
        let id = self.network.id();
        let recent_spent_utxos = self.recent_spent_utxos.read()?;
        for asset_utxos in tx_req.utxos.values_mut() {
            asset_utxos.retain(|u| {
                u.outpoint(id).ok().map(|o| !(*recent_spent_utxos).contains(&o)).unwrap_or(false)
            });
        }
        Ok(())
    }

    pub fn create_transaction(
        &mut self,
        tx_req: &mut CreateTransaction,
    ) -> Result<TransactionMeta, Error> {
        info!("electrum create_transaction {:?}", tx_req);

        self.remove_recent_spent_utxos(tx_req)?;
        self.get_account(tx_req.subaccount)?.create_tx(tx_req)
    }

    pub fn sign_transaction(&self, create_tx: &TransactionMeta) -> Result<TransactionMeta, Error> {
        info!("electrum sign_transaction {:?}", create_tx);
        let account_num = create_tx
            .create_transaction
            .as_ref()
            .ok_or_else(|| Error::Generic("Cannot sign without tx data".into()))?
            .subaccount;
        self.get_account(account_num)?.sign(create_tx)
    }

    fn set_recent_spent_utxos(&self, tx: &BETransaction) -> Result<(), Error> {
        let mut recent_spent_utxos = self.recent_spent_utxos.write()?;
        (*recent_spent_utxos).extend(tx.previous_outputs());
        Ok(())
    }

    pub fn send_transaction(&mut self, tx: &TransactionMeta) -> Result<TransactionMeta, Error> {
        info!("electrum send_transaction {:#?}", tx);
        let client = self.url.build_client(self.proxy.as_deref(), None)?;
        let tx_bytes = Vec::<u8>::from_hex(&tx.hex)?;
        let txid = client.transaction_broadcast_raw(&tx_bytes)?;
        if let Some(memo) = tx.create_transaction.as_ref().and_then(|o| o.memo.as_ref()) {
            self.store()?.write()?.insert_memo(txid.into(), memo)?;
        }
        let mut tx = tx.clone();
        // If sign transaction happens externally txid might not have been updated
        tx.txid = txid.to_string();
        let betx = BETransaction::deserialize(&tx_bytes[..], self.network.id())?;
        self.set_recent_spent_utxos(&betx)?;
        Ok(tx)
    }

    pub fn broadcast_transaction(&mut self, tx_hex: &str) -> Result<String, Error> {
        let transaction = BETransaction::from_hex(&tx_hex, self.network.id())?;

        info!("broadcast_transaction {:#?}", transaction.txid());
        let client = self.url.build_client(self.proxy.as_deref(), None)?;
        let hex = Vec::<u8>::from_hex(tx_hex)?;
        let txid = client.transaction_broadcast_raw(&hex)?;
        self.set_recent_spent_utxos(&transaction)?;
        Ok(format!("{}", txid))
    }

    /// The estimates are returned as an array of 25 elements. Each element is
    /// an integer representing the fee estimate expressed as satoshi per 1000
    /// bytes. The first element is the minimum relay fee as returned by the
    /// network, while the remaining elements are the current estimates to use
    /// for a transaction to confirm from 1 to 24 blocks.
    pub fn get_fee_estimates(&mut self) -> Result<Vec<FeeEstimate>, Error> {
        let mut fee_fetched_at = self.fee_fetched_at.lock()?;
        if *fee_fetched_at + FEE_ESTIMATE_INTERVAL > SystemTime::now() {
            // Skip network call
            Ok(self.store()?.read()?.fee_estimates())
        } else {
            let min_fee = self.network.id().default_min_fee_rate();
            let fee_estimates =
                try_get_fee_estimates(&self.url.build_client(self.proxy.as_deref(), None)?)
                    .unwrap_or_else(|_| vec![FeeEstimate(min_fee); 25]);
            self.store()?.write()?.cache.fee_estimates = fee_estimates.clone();
            *fee_fetched_at = SystemTime::now();
            Ok(fee_estimates)
        }
        //TODO better implement default
    }

    pub fn get_min_fee_rate(&self) -> Result<u64, Error> {
        Ok(self.store()?.read()?.min_fee_rate())
    }

    /// Return the settings or None if the store is not loaded (not logged in)
    pub fn get_settings(&self) -> Option<Settings> {
        Some(self.store().ok()?.read().ok()?.get_settings().unwrap_or_default())
    }

    pub fn change_settings(&mut self, value: &Value) -> Result<(), Error> {
        let mut settings = self.get_settings().ok_or_else(|| Error::StoreNotLoaded)?;
        settings.update(value)?;
        self.store()?.write()?.insert_settings(Some(settings.clone()))?;
        self.notify.settings(&settings);
        Ok(())
    }

    pub fn get_available_currencies(
        &mut self,
        params: &GetAvailableCurrenciesParams,
    ) -> Result<Value, Error> {
        let currencies = match &self.available_currencies {
            Some(map) => map,

            None => self.available_currencies.get_or_insert(fetch_available_currencies(
                &self.build_request_agent()?,
                &params.url,
            )?),
        };

        let all = currencies.values().flatten().collect::<HashSet<_>>();

        Ok(json!({ "all": all, "per_exchange": &currencies }))
    }

    pub fn get_unspent_outputs(&self, opt: &GetUnspentOpt) -> Result<GetUnspentOutputs, Error> {
        let mut unspent_outputs: HashMap<String, Vec<UnspentOutput>> = HashMap::new();
        let account = self.get_account(opt.subaccount)?;

        let store = self.store()?;
        let store_read = store.read()?;
        let acc_store = store_read.account_cache(opt.subaccount)?;
        let height = store_read.cache.tip_height();

        let num_confs = opt.num_confs.unwrap_or(0);
        let confidential_utxos_only = opt.confidential_utxos_only.unwrap_or(false);

        for outpoint in account.unspents()? {
            let utxo = account.txo(&outpoint, acc_store)?;
            let confirmations = match utxo.height {
                None | Some(0) => 0,
                Some(h) => (height + 1).saturating_sub(h),
            };
            if num_confs > confirmations || (confidential_utxos_only && !utxo.is_confidential()) {
                continue;
            }
            let asset_id = match &utxo.txoutsecrets {
                None => "btc".to_string(),
                Some(s) => s.asset.to_string(),
            };
            (*unspent_outputs.entry(asset_id).or_insert(vec![])).push(utxo.try_into()?);
        }
        Ok(GetUnspentOutputs(unspent_outputs))
    }

    pub fn get_address_data(&self, opt: AddressDataRequest) -> Result<AddressDataResult, Error> {
        let address = match self.network.id() {
            NetworkId::Bitcoin(_) => {
                BEAddress::Bitcoin(bitcoin::Address::from_str(&opt.address)?.assume_checked())
            }
            NetworkId::Elements(_) => {
                BEAddress::Elements(elements::Address::from_str(&opt.address)?)
            }
        };
        self.get_accounts()?
            .into_iter()
            .filter_map(|a| a.get_address_data(&address).ok())
            .next()
            .ok_or(Error::ScriptPubkeyNotFound)
    }

    pub fn export_cache(&mut self) -> Result<RawCache, Error> {
        self.store()?.write()?.export_cache()
    }

    pub fn block_status(&self) -> Result<(u32, BEBlockHash), Error> {
        let store = self.store()?;
        let store_read = store.read()?;
        let tip = (store_read.cache.tip_height(), store_read.cache.tip_block_hash());
        info!("tip={:?}", tip);
        Ok(tip)
    }

    pub fn tx_status(&self) -> Result<u64, Error> {
        let mut opt = GetTransactionsOpt::default();
        opt.count = 100;
        let mut hasher = DefaultHasher::new();
        for account in self.get_accounts()? {
            opt.subaccount = account.num();
            let txs = self.get_transactions(&opt)?.0;
            for tx in txs.iter() {
                std::hash::Hash::hash(&tx.txhash, &mut hasher);
            }
        }
        let status = hasher.finish();
        info!("txs status={}", status);
        Ok(status)
    }
}

pub fn keys_from_credentials(
    credentials: &Credentials,
    network: bitcoin::Network,
) -> Result<(ExtendedPrivKey, ExtendedPubKey, MasterBlindingKey), Error> {
    let seed = wally::bip39_mnemonic_to_seed(&credentials.mnemonic, &credentials.bip39_passphrase)
        .ok_or(Error::InvalidMnemonic)?;
    let master_xprv = ExtendedPrivKey::new_master(network, &seed)?;
    let master_xpub = ExtendedPubKey::from_priv(&EC, &master_xprv);
    let master_blinding = asset_blinding_key_from_seed(&seed);
    Ok((master_xprv, master_xpub, master_blinding))
}

impl Tipper {
    pub fn server_tip(&self, client: &Client) -> Result<(u32, BEBlockHeader), Error> {
        let header = client.block_headers_subscribe_raw()?;
        let new_height = header.height as u32;
        let new_header = BEBlockHeader::deserialize(&header.header, self.network.id())?;
        Ok((new_height, new_header))
    }
    pub fn update_cache_if_needed(
        &self,
        new_height: u32,
        new_header: BEBlockHeader,
    ) -> Result<Option<(u32, BEBlockHeader)>, Error> {
        let do_update = match &self.store.read()?.cache.tip_ {
            None => true,
            Some((current_height, current_header)) => {
                &new_height != current_height || &new_header != current_header
            }
        };
        if do_update {
            info!("saving in store new tip {:?}", new_height);
            self.store.write()?.update_tip(new_height, new_header.clone())?;
            Ok(Some((new_height, new_header)))
        } else {
            Ok(None)
        }
    }
}

impl Headers {
    pub fn ask(&mut self, chunk_size: usize, client: &Client) -> Result<usize, Error> {
        if let ChainOrVerifier::Chain(chain) = &mut self.checker {
            info!("asking headers, current height:{} chunk_size:{} ", chain.height(), chunk_size);
            let headers = client.block_headers(chain.height() as usize + 1, chunk_size)?.headers;
            let len = headers.len();
            chain.push(headers)?;
            Ok(len)
        } else {
            // Liquid doesn't need to download the header's chain
            Ok(0)
        }
    }

    pub fn get_proofs(&mut self, client: &Client) -> Result<usize, Error> {
        let mut proofs_done = 0;
        let account_nums = self.store.read()?.account_nums();

        for account_num in account_nums {
            let store_read = self.store.read()?;
            let acc_store = store_read.account_cache(account_num)?;

            // find unconfirmed transactions that were previously confirmed and had
            // their SPV validation cached, to be cleared below
            let remove_proof: Vec<BETxid> = acc_store
                .heights
                .iter()
                .filter(|(t, h)| h.is_none() && store_read.cache.txs_verif.get(*t).is_some())
                .map(|(t, _)| t.clone())
                .collect();

            // find confirmed transactions with no SPV validation cache
            let needs_proof: Vec<(BETxid, u32)> = acc_store
                .heights
                .iter()
                .filter_map(|(t, h_opt)| Some((t, (*h_opt)?)))
                .filter(|(t, _)| store_read.cache.txs_verif.get(*t).is_none())
                .map(|(t, h)| (t.clone(), h))
                .collect();
            drop(store_read);

            let mut txs_verified = HashMap::new();
            for (txid, height) in needs_proof {
                let verified = match client
                    .transaction_get_merkle(&txid.into_bitcoin(), height as usize)
                {
                    Ok(proof) => match &self.checker {
                        ChainOrVerifier::Chain(chain) => chain
                            .verify_tx_proof(txid.ref_bitcoin().unwrap(), height, proof)
                            .is_ok(),
                        ChainOrVerifier::Verifier(verifier) => {
                            if let Some(BEBlockHeader::Elements(header)) =
                                self.store.read()?.cache.headers.get(&height)
                            {
                                verifier
                                    .verify_tx_proof(txid.ref_elements().unwrap(), proof, &header)
                                    .is_ok()
                            } else {
                                false
                            }
                        }
                    },
                    Err(e) => {
                        warn!("failed fetching merkle inclusion proof for {}: {:?}", txid, e);
                        false
                    }
                };

                if verified {
                    info!("proof for {} verified!", txid);
                    txs_verified.insert(txid, SPVVerifyTxResult::Verified);
                } else {
                    warn!("proof for {} not verified!", txid);
                    txs_verified.insert(txid, SPVVerifyTxResult::NotVerified);
                }
            }
            proofs_done += txs_verified.len();

            let mut store_write = self.store.write()?;

            store_write.cache.txs_verif.extend(txs_verified);
            for txid in remove_proof {
                store_write.cache.txs_verif.remove(&txid);
            }
        }

        Ok(proofs_done)
    }

    pub fn remove(&mut self, headers: u32) -> Result<(), Error> {
        if let ChainOrVerifier::Chain(chain) = &mut self.checker {
            chain.remove(headers)?;
        }
        Ok(())
    }

    pub fn cross_validate(&mut self) -> bool {
        if let (Some(cross_validator), ChainOrVerifier::Chain(chain)) =
            (&mut self.cross_validator, &self.checker)
        {
            let was_valid = {
                let store = self.store.read().unwrap();
                store.cache.cross_validation_result.as_ref().map(|r| r.is_valid())
            };

            let result = cross_validator.validate(chain);
            debug!("cross validation result: {:?}", result);

            let changed = was_valid.map_or(true, |was_valid| was_valid != result.is_valid());

            let mut store = self.store.write().unwrap();
            store.cache.cross_validation_result = Some(result);

            changed
        } else {
            false
        }
    }
}

#[derive(Default)]
struct DownloadTxResult {
    txs: Vec<(BETxid, BETransaction)>,
    unblinds: Vec<(elements::OutPoint, elements::TxOutSecrets)>,
    is_previous: HashSet<BETxid>,
}

impl Syncer {
    /// Sync the wallet, return the set of updated accounts
    pub fn sync(
        &self,
        client: &Client,
        last_statuses: &mut ScriptStatuses,
        user_wants_to_sync: &Arc<AtomicBool>,
    ) -> Result<Vec<TransactionNotification>, Error> {
        trace!("start sync");
        let start = Instant::now();

        let accounts = self.accounts.read().unwrap();
        let mut updated_txs: HashMap<BETxid, TransactionNotification> = HashMap::new();

        for account in accounts.values() {
            let mut new_statuses = ScriptStatuses::new();
            let cache_statuses = account.status()?;
            let mut history_txs_id = HashSet::<BETxid>::new();
            let mut heights_set = HashSet::new();
            let mut txid_height = HashMap::<BETxid, _>::new();
            let mut scripts = HashMap::new();

            let mut last_used = Indexes::default();
            let mut wallet_chains = vec![0, 1];
            wallet_chains.shuffle(&mut thread_rng());
            for i in wallet_chains {
                let is_internal = i == 1;
                let mut count_consecutive_empty = 0;
                for j in 0.. {
                    if !user_wants_to_sync.load(Ordering::Relaxed) {
                        return Err(Error::UserDoesntWantToSync);
                    }
                    let (cached, path, script) = account.get_script(is_internal, j)?;
                    if !cached {
                        scripts.insert(script.clone(), path);
                    }
                    let b_script = script.into_bitcoin();

                    match client.script_subscribe(&b_script) {
                        Ok(Some(status)) => {
                            // First time: script is subscribed, script contains at least 1 tx
                            last_statuses.insert(b_script.clone(), status);
                        }
                        Ok(None) => {
                            // First time: script is subscribed, script doesn't contain a tx yet
                            ()
                        }
                        Err(gdk_common::electrum_client::Error::AlreadySubscribed(_)) => {
                            // Second or following iteration
                            if let Some(status) = client.script_pop(&b_script)? {
                                // There is an update, new tx for this script
                                last_statuses.insert(b_script.clone(), status);
                            } else {
                                // There are no new transactions since last iteration
                            }
                        }
                        Err(e) => return Err(Error::ClientError(e)),
                    };
                    match last_statuses.get(&b_script) {
                        Some(last_status) => {
                            // Script has a tx
                            count_consecutive_empty = 0;
                            if is_internal {
                                last_used.internal = j;
                            } else {
                                last_used.external = j;
                            }
                            let cache_status = cache_statuses.get(&b_script);
                            if Some(last_status) == cache_status {
                                // No need to check this script since nothing has changed
                                continue;
                            }
                        }
                        None => {
                            // Script never had a tx, initially and neither via updates
                            count_consecutive_empty += 1;
                            if count_consecutive_empty >= self.gap_limit {
                                break;
                            } else {
                                continue;
                            }
                        }
                    }
                    let history = client.script_get_history(&b_script)?;

                    let txid_height_pairs =
                        history.iter().map(|tx| (BETxid::Bitcoin(tx.tx_hash), tx.height));
                    let status = account::compute_script_status(txid_height_pairs);
                    new_statuses.insert(b_script.clone(), status);

                    let net = self.network.id();
                    for el in history {
                        // el.height = -1 means unconfirmed with unconfirmed parents
                        // el.height =  0 means unconfirmed with confirmed parents
                        // but we threat those tx the same
                        let height = el.height.max(0);
                        heights_set.insert(height as u32);
                        if height == 0 {
                            txid_height.insert(el.tx_hash.into_net(net), None);
                        } else {
                            txid_height.insert(el.tx_hash.into_net(net), Some(height as u32));
                        }

                        history_txs_id.insert(el.tx_hash.into_net(net));
                    }
                }
            }

            let new_txs = self.download_txs(account.num(), &history_txs_id, &scripts, &client)?;
            let headers = self.download_headers(account.num(), &heights_set, &client)?;

            let store_read = self.store.read()?;
            let acc_store = store_read.account_cache(account.num())?;
            let store_last_used = acc_store.get_both_last_used();

            drop(store_read);

            let changed = if !new_txs.txs.is_empty()
                || !headers.is_empty()
                || store_last_used != last_used
                || !scripts.is_empty()
                || !txid_height.is_empty()
            {
                info!(
                    "There are changes in the store new_txs:{:?} headers:{:?} txid_height:{:?} scripts:{:?} store_last_used_changed:{}",
                    new_txs.txs.iter().map(|tx| tx.0).collect::<Vec<_>>(),
                    headers,
                    txid_height,
                    scripts,
                    store_last_used != last_used
                );
                let mut store_write = self.store.write()?;
                store_write.cache.headers.extend(headers);

                let acc_store = store_write.account_cache_mut(account.num())?;
                acc_store.set_both_last_used(last_used);
                acc_store
                    .all_txs
                    .extend(new_txs.txs.iter().cloned().map(|(txid, tx)| (txid, tx.into())));
                acc_store.unblinded.extend(new_txs.unblinds);

                // # Removing conflicting transactions
                // We have new transactions, but some of them could conflict (spend same outpoint)
                // with each other or with the ones in the cache. We can't rely on the server to
                // detect unconfirmed conflicting transactions.

                // ## Remove new transactions conflicting with each other
                // keeping the one having the greater fee.

                // fetch full transactions and their fee from txids
                let new_txs_fee: HashMap<BETxid, (BETransaction, u64)> = txid_height
                    .keys()
                    .map(|txid| {
                        let tx = acc_store.all_txs.get(&txid).expect("all txs must be in cache, the new ones in this loop are already inserted in previous extend").clone();
                        let fee = tx.tx.fee(&acc_store.all_txs, &acc_store.unblinded, &self.network.policy_asset_id().ok()).expect("all txs to compute the fee must be in the cache");
                        (*txid,(tx.tx, fee))
                    }
                ).collect();

                // build a reverse map so that I know which outpoint is spent by more than 1 tx,
                // meaning the transactions are conflicting
                let mut outpoints_to_tx: HashMap<BEOutPoint, Vec<BETxid>> = HashMap::new();
                for (txid, (tx, _)) in new_txs_fee.iter() {
                    for outpoint in tx.previous_outputs() {
                        let entry = outpoints_to_tx.entry(outpoint).or_insert(vec![]);
                        entry.push(*txid);
                    }
                }

                // We are going to keep the txids that have no conflicts with other new txs, in case
                // there are conflicts with another tx, we keep the one with greater fee.
                txid_height.retain(|txid, _| {
                    let (tx, fee) =
                        new_txs_fee.get(txid).expect("new_txs_fee built over txid_height");
                    for outpoint in tx.previous_outputs() {
                        let txs_spending_this_outpoint = outpoints_to_tx
                            .get(&outpoint)
                            .expect("for sure there is at least current txid");
                        for other_txid in txs_spending_this_outpoint.iter().filter(|t| *t != txid) {
                            // if the tx is not found in the new ones, it means it doesn't conflict with the new ones.
                            if let Some((_, other_fee)) = new_txs_fee.get(other_txid) {
                                // return false (remove the txid) only if the fee is lower than the other_fee
                                return fee > other_fee;
                            }
                        }
                    }
                    true
                });

                // ## search in existing transactions the ones that use a respent outpoint and
                // remove them. Here we don't have to bother to check the fee, because we are sure
                // they happened before.
                let existing_txids_height: Vec<_> = acc_store.heights.keys().cloned().collect();
                for txid in existing_txids_height.iter() {
                    let tx = acc_store.all_txs.get(&txid).expect("all txs must be in cache, the new ones in this loop are already inserted in previous extend").clone();
                    if tx.tx.previous_outputs().iter().any(|p| outpoints_to_tx.contains_key(p)) {
                        acc_store.heights.remove(&txid);
                    }
                }

                acc_store.heights.extend(txid_height.into_iter());
                acc_store.scripts.extend(scripts.clone().into_iter().map(|(a, b)| (b, a)));
                acc_store.paths.extend(scripts.into_iter());

                if acc_store.script_statuses.is_none() {
                    acc_store.script_statuses = Some(HashMap::new());
                }
                acc_store
                    .script_statuses
                    .as_mut()
                    .expect("always some because created if None in previous line")
                    .extend(new_statuses);

                for tx in new_txs.txs.iter() {
                    if new_txs.is_previous.contains(&tx.0) {
                        // This is a previous transaction that we fetched to compute the fee,
                        // do not emit a notification for it.
                        continue;
                    }
                    if let Some(ntf) = updated_txs.get_mut(&tx.0) {
                        // Make sure ntf.subaccounts is ordered and has no duplicates.
                        let subaccount = account.num();
                        match ntf.subaccounts.binary_search(&subaccount) {
                            Ok(_) => {} // already there
                            Err(pos) => {
                                ntf.subaccounts.insert(pos, subaccount);
                                if pos == 0 {
                                    // For transactions involving multiple subaccounts, the net effect for
                                    // the transaction is the one considering the first subaccount.
                                    // So replace it here.
                                    let (satoshi, type_) = self.ntf_satoshi_type(&tx.1, &acc_store);
                                    ntf.satoshi = satoshi;
                                    ntf.type_ = type_;
                                }
                            }
                        }
                    } else {
                        let (satoshi, type_) = self.ntf_satoshi_type(&tx.1, &acc_store);
                        let ntf = TransactionNotification {
                            subaccounts: vec![account.num()],
                            txid: tx.0.into_bitcoin(),
                            satoshi,
                            type_,
                        };
                        updated_txs.insert(tx.0, ntf);
                    }
                }

                store_write.flush()?;
                drop(store_write);

                // the transactions are first indexed into the db and then verified so that all the prevouts
                // and scripts are available for querying. invalid transactions will be removed by verify_own_txs.
                account.verify_own_txs(&new_txs.txs)?;
                true
            } else {
                false
            };
            trace!(
                "changes for {}: {} elapsed {}",
                account.num(),
                changed,
                start.elapsed().as_millis()
            );
        }

        self.empty_recent_spent_utxos()?;
        Ok(updated_txs.into_values().collect())
    }

    fn empty_recent_spent_utxos(&self) -> Result<(), Error> {
        let mut recent_spent_utxos = self.recent_spent_utxos.write()?;
        *recent_spent_utxos = HashSet::new();
        Ok(())
    }

    fn ntf_satoshi_type(
        &self,
        tx: &BETransaction,
        acc_store: &RawAccountCache,
    ) -> (Option<u64>, Option<TransactionType>) {
        if self.network.liquid {
            // For consistency with multisig do not set this
            (None, None)
        } else {
            let balances =
                tx.my_balance_changes(&acc_store.all_txs, &acc_store.paths, &acc_store.unblinded);
            let balance =
                balances.get(&"btc".to_string()).expect("bitcoin balance always has btc key");
            let is_redeposit = tx.is_redeposit(&acc_store.paths, &acc_store.all_txs);
            let type_ = tx.type_(&balances, is_redeposit);
            (Some(balance.abs() as u64), Some(type_))
        }
    }

    fn download_headers(
        &self,
        account_num: u32,
        heights_set: &HashSet<u32>,
        client: &Client,
    ) -> Result<Vec<(u32, BEBlockHeader)>, Error> {
        let heights_in_db: HashSet<u32> = {
            let store_read = self.store.read()?;
            let acc_store = store_read.account_cache(account_num)?;
            iter::once(0).chain(acc_store.heights.iter().filter_map(|(_, h)| *h)).collect()
        };

        let mut result = vec![];
        let heights_to_download: Vec<u32> =
            heights_set.difference(&heights_in_db).cloned().collect();
        if !heights_to_download.is_empty() {
            let headers_bytes_downloaded =
                client.batch_block_header_raw(heights_to_download.clone())?;
            let mut headers_downloaded: Vec<BEBlockHeader> = vec![];
            for vec in headers_bytes_downloaded {
                headers_downloaded.push(BEBlockHeader::deserialize(&vec, self.network.id())?);
            }
            debug!("headers_downloaded {:?}", &headers_downloaded);
            for (header, height) in
                headers_downloaded.into_iter().zip(heights_to_download.into_iter())
            {
                result.push((height, header));
            }
        }

        Ok(result)
    }

    fn download_txs(
        &self,
        account_num: u32,
        history_txs_id: &HashSet<BETxid>,
        scripts: &HashMap<BEScript, DerivationPath>,
        client: &Client,
    ) -> Result<DownloadTxResult, Error> {
        let mut txs = vec![];
        let mut unblinds = vec![];
        let mut is_previous = HashSet::new();

        let mut txs_in_db =
            self.store.read()?.account_cache(account_num)?.all_txs.keys().cloned().collect();
        // BETxid has to be converted into bitcoin::Txid for rust-electrum-client
        let txs_to_download: Vec<bitcoin::Txid> =
            history_txs_id.difference(&txs_in_db).map(BETxidConvert::into_bitcoin).collect();
        if !txs_to_download.is_empty() {
            let txs_bytes_downloaded = client.batch_transaction_get_raw(txs_to_download.iter())?;
            let mut txs_downloaded: Vec<BETransaction> = vec![];
            for vec in txs_bytes_downloaded {
                let tx = BETransaction::deserialize(&vec, self.network.id())?;
                txs_downloaded.push(tx);
            }
            info!("txs_downloaded {:?}", txs_downloaded.len());
            let mut previous_txs_to_download = HashSet::new();
            for tx in txs_downloaded.into_iter() {
                let txid = tx.txid();
                txs_in_db.insert(txid);

                if let BETransaction::Elements(tx) = &tx {
                    info!("compute OutPoint Unblinded");
                    for (i, output) in tx.output.iter().enumerate() {
                        let be_script = output.script_pubkey.clone().into_be();
                        let store_read = self.store.read()?;
                        let acc_store = store_read.account_cache(account_num)?;
                        // could be the searched script it's not yet in the store, because created in the current run, thus it's searched also in the `scripts`
                        if acc_store.paths.contains_key(&be_script)
                            || scripts.contains_key(&be_script)
                        {
                            let vout = i as u32;
                            let outpoint = elements::OutPoint {
                                txid: tx.txid(),
                                vout,
                            };

                            let unblinded = unblind_output(
                                output.clone(),
                                self.master_blinding.as_ref().unwrap(),
                                Some(outpoint),
                            );
                            match unblinded {
                                Ok(unblinded) => unblinds.push((outpoint, unblinded)),
                                Err(e) => warn!("{} cannot unblind, ignoring (could be sender messed up with the blinding process) {}", outpoint, e),
                            }
                        }
                    }
                } else {
                    // download all previous output only for bitcoin (to calculate fee of incoming tx)
                    for previous_txid in tx.previous_output_txids() {
                        previous_txs_to_download.insert(previous_txid);
                    }
                }
                txs.push((txid, tx));
            }

            let txs_to_download: Vec<bitcoin::Txid> = previous_txs_to_download
                .difference(&txs_in_db)
                .map(BETxidConvert::into_bitcoin)
                .collect();

            if !txs_to_download.is_empty() {
                let txs_bytes_downloaded =
                    client.batch_transaction_get_raw(txs_to_download.iter())?;
                for vec in txs_bytes_downloaded {
                    let tx = BETransaction::deserialize(&vec, self.network.id())?;
                    let txid = tx.txid();
                    if !txs.iter().any(|t| &t.0 == &txid) {
                        is_previous.insert(txid);
                    }
                    txs.push((txid, tx));
                }
            }
            Ok(DownloadTxResult {
                txs,
                unblinds,
                is_previous,
            })
        } else {
            Ok(DownloadTxResult::default())
        }
    }
}

fn fetch_available_currencies(
    agent: &ureq::Agent,
    url: &str,
) -> Result<HashMap<String, Vec<Currency>>, Error> {
    #[derive(serde::Deserialize)]
    struct ExchangeInfos {
        pairs: Vec<(Currency, Currency)>,
    }

    let endpoint = format!("{url}/v0/venues");

    let response = agent.get(&endpoint).call()?.into_json::<HashMap<String, ExchangeInfos>>()?;

    let map = response.into_iter().map(|(exchange, infos)| {
        let currencies = infos.pairs.into_iter().map(|(first, second)| {
            // Either the first or the second currency in the pair must be
            // fiat (but not both).
            if !(first.is_fiat() ^ second.is_fiat()) {
                panic!("Was expecting one currency in the pair to be Bitcoin, got {}-{} instead", first, second);
            }
            if first.is_fiat() { first } else { second }
        }).collect::<Vec<Currency>>();

        (exchange, currencies)
    }).collect();

    Ok(map)
}

fn unblind_output(
    output: elements::TxOut,
    master_blinding: &MasterBlindingKey,
    outpoint: Option<elements::OutPoint>,
) -> Result<elements::TxOutSecrets, Error> {
    match (output.asset, output.value, output.nonce) {
        (Asset::Confidential(_), confidential::Value::Confidential(_), Nonce::Confidential(_)) => {
            let script = output.script_pubkey.clone();
            let blinding_key = asset_blinding_key_to_ec_private_key(master_blinding, &script);
            let txout_secrets = output.unblind(&EC, blinding_key)?;
            info!(
                "Unblinded outpoint:{} asset:{} value:{}",
                outpoint.map(|out| out.to_string()).unwrap_or_default(),
                txout_secrets.asset.to_string(),
                txout_secrets.value
            );

            Ok(txout_secrets)
        }
        (Asset::Explicit(asset_id), confidential::Value::Explicit(satoshi), _) => {
            Ok(elements::TxOutSecrets {
                asset: asset_id,
                value: satoshi,
                asset_bf: elements::confidential::AssetBlindingFactor::zero(),
                value_bf: elements::confidential::ValueBlindingFactor::zero(),
            })
        }
        _ => Err(Error::Generic("Unexpected asset/value/nonce".into())),
    }
}

fn wait_or_close(user_wants_to_sync: &Arc<AtomicBool>, interval: u32) -> bool {
    for _ in 0..(interval * 2) {
        if !user_wants_to_sync.load(Ordering::Relaxed) {
            // Threads should stop, close
            return true;
        }
        thread::sleep(Duration::from_millis(500));
    }
    false
}

// Some pin_data encrypt the bare mnemonic, not a json.
// If we cannot deserialize the plaintext into a json,
// we attempt to deserialize it into a bare mnemonic.
// For old pin_data that does have the hmac,
// it could happen that the decryption is successfully even with a wrong key.
// However the chance that the pin_data does not have a hmac,
// decryption is successful with a wrong key and
// the plaintext it's a valid utf8 is practically negligible,
// so here we return an InvalidPin error.
fn bare_mnemonic_from_utf8(decrypted: &[u8]) -> Result<Credentials, Error> {
    let mnemonic = std::str::from_utf8(&decrypted)
        .map_err(|_| Error::PinClient(gdk_pin_client::Error::InvalidPin))?
        .to_string();
    if mnemonic.chars().any(|c| !c.is_ascii_alphabetic() && !c.is_whitespace()) {
        return Err(Error::PinClient(gdk_pin_client::Error::InvalidPin));
    }
    Ok(Credentials {
        mnemonic,
        bip39_passphrase: "".to_string(),
    })
}

#[cfg(feature = "testing")]
impl ElectrumSession {
    pub fn filter_events(&self, event: &str) -> Vec<Value> {
        self.notify.filter_events(event)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_passphrase() {
        // From bip39 passphrase
        let credentials = Credentials {
            mnemonic: "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about".to_string(),
            bip39_passphrase: "TREZOR".to_string(),
        };
        let (master_xprv, _, _) =
            keys_from_credentials(&credentials, bitcoin::Network::Bitcoin).unwrap();
        assert_eq!(master_xprv.to_string(), "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF");
    }

    #[test]
    fn fetch_available_currencies() {
        let map = super::fetch_available_currencies(
            &ureq::Agent::new(),
            "https://green-bitcoin-testnet.blockstream.com/prices",
        )
        .unwrap();

        assert!(map.len() > 0);
    }

    #[test]
    fn test_bare_mnemonic() {
        let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
        assert!(bare_mnemonic_from_utf8(&mnemonic.as_bytes()).is_ok());
        assert!(bare_mnemonic_from_utf8(&format!("{} ", mnemonic).as_bytes()).is_ok());
        assert!(bare_mnemonic_from_utf8(&format!("{}\n", mnemonic).as_bytes()).is_ok());
        assert!(bare_mnemonic_from_utf8(&format!("{}.", mnemonic).as_bytes()).is_err());
        assert!(bare_mnemonic_from_utf8(b"\x00\x9f\x92\x96").is_err());
    }
}
