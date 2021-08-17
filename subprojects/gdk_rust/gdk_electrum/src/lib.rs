mod store;

#[macro_use]
extern crate serde_json;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate gdk_common;

use headers::bitcoin::HEADERS_FILE_MUTEX;
use log::{debug, info, trace, warn};
use serde_json::Value;

pub mod account;
pub mod error;
pub mod headers;
pub mod interface;
mod notification;
pub mod pin;
pub mod pset;
mod registry;
pub mod spv;

use crate::account::{
    discover_account, get_account_derivation, get_account_script_purpose,
    get_last_next_account_nums, Account,
};
use crate::error::Error;
use crate::interface::ElectrumUrl;
use crate::store::*;

use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::secp256k1::{self, SecretKey};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};

use electrum_client::GetHistoryRes;
use gdk_common::be::*;
use gdk_common::mnemonic::Mnemonic;
use gdk_common::model::*;
use gdk_common::network::NetworkParameters;
use gdk_common::password::Password;
use gdk_common::wally::{
    self, asset_blinding_key_from_seed, asset_blinding_key_to_ec_private_key, MasterBlindingKey,
};

use elements::confidential::{self, Asset, Nonce};
use gdk_common::NetworkId;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::{iter, thread};

use crate::headers::bitcoin::HeadersChain;
use crate::headers::liquid::Verifier;
use crate::headers::ChainOrVerifier;
pub use crate::notification::{NativeNotif, Notification};
use crate::pin::PinManager;
use crate::spv::SpvCrossValidator;
use aes::Aes256;
use bitcoin::blockdata::constants::DIFFCHANGE_INTERVAL;
use block_modes::block_padding::Pkcs7;
use block_modes::BlockMode;
use block_modes::Cbc;
use electrum_client::{Client, ElectrumApi};
use rand::seq::SliceRandom;
use rand::thread_rng;
use rand::Rng;
pub use registry::AssetEntry;
use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::Hasher;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

const CROSS_VALIDATION_RATE: u8 = 4; // Once every 4 thread loop runs, or roughly 28 seconds

lazy_static! {
    static ref EC: secp256k1::Secp256k1<secp256k1::All> = {
        let mut ctx = secp256k1::Secp256k1::new();
        let mut rng = rand::thread_rng();
        ctx.randomize(&mut rng);
        ctx
    };
}

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

struct Syncer {
    accounts: Arc<RwLock<HashMap<u32, Account>>>,
    store: Store,
    master_blinding: Option<MasterBlindingKey>,
    network: NetworkParameters,
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
}

#[derive(Debug, PartialEq, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Disconnected,
    Connected,
}

impl From<bool> for State {
    fn from(b: bool) -> Self {
        if b {
            State::Connected
        } else {
            State::Disconnected
        }
    }
}

impl From<State> for bool {
    fn from(s: State) -> Self {
        match s {
            State::Connected => true,
            State::Disconnected => false,
        }
    }
}

impl fmt::Display for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> Result<(), fmt::Error> {
        match self {
            State::Disconnected => write!(f, "disconnected"),
            State::Connected => write!(f, "connected"),
        }
    }
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

pub fn determine_electrum_url(network: &NetworkParameters) -> Result<ElectrumUrl, Error> {
    if let Some(true) = network.use_tor {
        if let Some(electrum_onion_url) = network.electrum_onion_url.as_ref() {
            if !electrum_onion_url.is_empty() {
                return Ok(ElectrumUrl::Plaintext(electrum_onion_url.into()));
            }
        }
    }
    let electrum_url = network
        .electrum_url
        .as_ref()
        .ok_or_else(|| Error::Generic("network url is missing".into()))?;
    if electrum_url == "" {
        return Err(Error::Generic("network url is empty".into()));
    }

    if network.electrum_tls.unwrap_or(false) {
        Ok(ElectrumUrl::Tls(electrum_url.into(), network.validate_domain.unwrap_or(false)))
    } else {
        Ok(ElectrumUrl::Plaintext(electrum_url.into()))
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

impl ElectrumSession {
    pub fn create_session(
        network: NetworkParameters,
        proxy: Option<&str>,
        url: ElectrumUrl,
    ) -> Self {
        Self {
            proxy: socksify(proxy),
            network,
            url,
            accounts: Arc::new(RwLock::new(HashMap::<u32, Account>::new())),
            notify: NativeNotif::new(),
            handles: vec![],
            user_wants_to_sync: Arc::new(AtomicBool::new(false)),
            last_network_call_succeeded: Arc::new(AtomicBool::new(false)),
            timeout: None,
            store: None,
            master_xpub: None,
            master_xprv: None,
        }
    }

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
        match &self.proxy {
            Some(proxy) => {
                let proxy = ureq::Proxy::new(&proxy)?;
                Ok(ureq::AgentBuilder::new().proxy(proxy).build())
            }
            None => Ok(ureq::agent()),
        }
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
                        info!("connect succesfully ping the electrum server");
                        self.last_network_call_succeeded.store(true, Ordering::Relaxed);
                        true
                    }
                    Err(e) => {
                        warn!("ping failed {:?}", e);
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

    pub fn mnemonic_from_pin_data(
        &mut self,
        pin: String,
        details: PinGetDetails,
    ) -> Result<String, Error> {
        let agent = self.build_request_agent()?;
        let manager = PinManager::new(
            agent,
            self.network.pin_server_url(),
            &self.network.pin_manager_public_key()?,
        )?;
        let client_key = SecretKey::from_slice(&Vec::<u8>::from_hex(&details.pin_identifier)?)?;
        let server_key = manager.get_pin(pin.as_bytes(), &client_key)?;
        let iv = Vec::<u8>::from_hex(&details.salt)?;
        let decipher = Aes256Cbc::new_from_slices(&server_key[..], &iv).unwrap();
        // If the pin is wrong, pinserver returns a random key and decryption fails, return a
        // specific error to signal the caller to update its pin counter.
        let mnemonic = decipher
            .decrypt_vec(&Vec::<u8>::from_hex(&details.encrypted_data)?)
            .map_err(|_| Error::InvalidPin)?;
        let mnemonic = std::str::from_utf8(&mnemonic).unwrap().to_string();
        Ok(mnemonic)
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
        self.notify.settings(&self.get_settings()?);
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

    pub fn login(
        &mut self,
        mnemonic: &Mnemonic,
        password: Option<Password>,
    ) -> Result<LoginData, Error> {
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
            keys_from_mnemonic(mnemonic, password, self.network.bip32_network())?;

        self.load_store(&LoadStoreOpt {
            master_xpub: master_xpub.clone(),
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
            let xpub = ExtendedPubKey::from_private(&crate::EC, &xprv);

            self.create_subaccount(CreateAccountOpt {
                subaccount: account_num,
                name: "".to_string(),
                xpub: Some(xpub),
                discovered: false,
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

        let (mut tip_height, mut tip_hash) = self.store()?.read()?.cache.tip;
        self.notify.block(tip_height, tip_hash);

        info!(
            "building client, url {}, proxy {}",
            self.url.url(),
            self.proxy.as_ref().unwrap_or(&"".to_string())
        );

        if let Ok(fee_client) = self.url.build_client(self.proxy.as_deref(), None) {
            info!("building built end");
            let fee_store = self.store()?;
            thread::spawn(move || {
                match try_get_fee_estimates(&fee_client) {
                    Ok(fee_estimates) => {
                        fee_store.write().unwrap().cache.fee_estimates = fee_estimates
                    }
                    Err(e) => {
                        warn!("can't update fee estimates {:?}", e)
                    }
                };
            });
        }

        let sync_interval = self.network.sync_interval.unwrap_or(7);

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
                    if wait_or_close(&user_wants_to_sync, sync_interval) {
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
                                    let (tip_height, tip_hash) = store_read.cache.tip;
                                    notify_blocks.block(tip_height, tip_hash);
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
        };

        let tipper = Tipper {
            store: self.store()?,
            network: self.network.clone(),
        };

        info!("login STATUS block:{:?} tx:{}", self.block_status()?, self.tx_status()?);

        let notify_blocks = self.notify.clone();

        let user_wants_to_sync = self.user_wants_to_sync.clone();
        let tipper_url = self.url.clone();
        let proxy = self.proxy.clone();

        let tipper_handle = thread::spawn(move || {
            info!("starting tipper thread");
            loop {
                if let Ok(client) = tipper_url.build_client(proxy.as_deref(), None) {
                    match tipper.tip(&client) {
                        Ok((current_tip_height, current_tip_hash)) => {
                            if tip_height != current_tip_height || tip_hash != current_tip_hash {
                                tip_height = current_tip_height;
                                tip_hash = current_tip_hash;
                                info!("tip is {:?} {:?}", tip_height, tip_hash);
                                notify_blocks.block(tip_height, tip_hash);
                            }
                        }
                        Err(e) => {
                            warn!("exception in tipper {:?}", e);
                        }
                    }
                }
                if wait_or_close(&user_wants_to_sync, sync_interval) {
                    info!("closing tipper thread {:?}", tip_height);
                    break;
                }
            }
        });
        self.handles.push(tipper_handle);

        let user_wants_to_sync = self.user_wants_to_sync.clone();
        let notify_txs = self.notify.clone();
        let syncer_url = self.url.clone();
        let proxy = self.proxy.clone();

        // Only the syncer thread is responsible to send network notification due for the state
        // of the electrum server. This is to avoid intermittent connect/disconnect if one endpoint
        // works while another don't. Once we categorize the disconnection by endpoint we can
        // monitor state of every network call.
        let state_updater = self.state_updater()?;

        let syncer_handle = thread::spawn(move || {
            info!("starting syncer thread");
            loop {
                match syncer_url.build_client(proxy.as_deref(), None) {
                    Ok(client) => match syncer.sync(&client) {
                        Ok(updated_txs) => {
                            state_updater.update_if_needed(true);
                            for (txid, accounts) in updated_txs.iter() {
                                info!("there are new transactions");
                                // TODO: limit the number of notifications
                                notify_txs.updated_txs(txid.clone(), accounts);
                            }
                        }
                        Err(e) => {
                            state_updater.update_if_needed(false);
                            warn!("Error during sync, {:?}", e)
                        }
                    },
                    Err(e) => {
                        state_updater.update_if_needed(false);
                        warn!("Can't build client {:?}", e)
                    }
                }
                if wait_or_close(&user_wants_to_sync, sync_interval) {
                    info!("closing syncer thread");
                    break;
                }
            }
        });
        self.handles.push(syncer_handle);

        Ok(())
    }

    pub fn get_wallet_hash_id(&self) -> Result<LoginData, Error> {
        let master_xpub = self.master_xpub.ok_or_else(|| Error::WalletNotInitialized)?;
        Ok(LoginData {
            wallet_hash_id: self.network.wallet_hash_id(&master_xpub),
        })
    }

    pub fn get_receive_address(&self, opt: &GetAddressOpt) -> Result<AddressPointer, Error> {
        debug!("get_receive_address {:?}", opt);
        let address = self.get_account(opt.subaccount)?.get_next_address()?;
        debug!("get_address {:?}", address);
        Ok(address)
    }

    pub fn set_pin(&self, details: &PinSetDetails) -> Result<PinGetDetails, Error> {
        let agent = self.build_request_agent()?;
        let manager = PinManager::new(
            agent,
            self.network.pin_server_url(),
            &self.network.pin_manager_public_key()?,
        )?;
        let client_key = SecretKey::new(&mut thread_rng());
        let server_key = manager.set_pin(details.pin.as_bytes(), &client_key)?;
        let iv = thread_rng().gen::<[u8; 16]>();
        let cipher = Aes256Cbc::new_from_slices(&server_key[..], &iv).unwrap();
        let encrypted = cipher.encrypt_vec(details.mnemonic.as_bytes());

        let result = PinGetDetails {
            salt: iv.to_hex(),
            encrypted_data: encrypted.to_hex(),
            pin_identifier: client_key.to_hex(),
        };
        Ok(result)
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

    pub fn get_subaccounts(&mut self) -> Result<Vec<AccountInfo>, Error> {
        self.get_accounts()?.iter().map(|a| a.info()).collect()
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

    pub fn get_subaccount_xpub(
        &mut self,
        opt: GetAccountXpubOpt,
    ) -> Result<GetAccountXpubResult, Error> {
        // If the account cache is missing, we also return None
        let xpub = self.store()?.read()?.account_cache(opt.subaccount).map_or(None, |c| c.xpub);
        Ok(GetAccountXpubResult {
            xpub,
        })
    }

    pub fn create_subaccount(&mut self, opt: CreateAccountOpt) -> Result<AccountInfo, Error> {
        let master_xprv = self.master_xprv.clone();
        let store = self.store()?.clone();
        let master_blinding = store.read()?.cache.master_blinding.clone();
        let network = self.network.clone();
        let mut accounts = self.accounts.write()?;
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
            if !account.has_transactions() {
                bail!(Error::AccountGapsDisallowed);
            }
        }

        let account = match accounts.entry(opt.subaccount) {
            Entry::Occupied(entry) => (entry.into_mut()),
            Entry::Vacant(entry) => {
                let account = entry.insert(Account::new(
                    network,
                    &master_xprv,
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
        discover_account(&self.url, self.proxy.as_deref(), &opt.xpub, opt.script_type)
    }

    pub fn get_next_subaccount(&self, opt: GetNextAccountOpt) -> Result<u32, Error> {
        let (_, next_account) = get_last_next_account_nums(
            self.accounts.read()?.keys().copied().collect(),
            opt.script_type,
        );
        Ok(next_account)
    }

    pub fn rename_subaccount(&mut self, opt: RenameAccountOpt) -> Result<(), Error> {
        self.get_account(opt.subaccount)?.set_settings(UpdateAccountOpt {
            subaccount: opt.subaccount,
            name: Some(opt.new_name),
            hidden: None,
        })
    }

    pub fn set_subaccount_hidden(&mut self, opt: SetAccountHiddenOpt) -> Result<(), Error> {
        self.get_account(opt.subaccount)?.set_settings(UpdateAccountOpt {
            subaccount: opt.subaccount,
            hidden: Some(opt.hidden),
            name: None,
        })
    }

    pub fn update_subaccount(&mut self, opt: UpdateAccountOpt) -> Result<(), Error> {
        self.get_account(opt.subaccount)?.set_settings(opt)
    }

    pub fn get_transactions(&self, opt: &GetTransactionsOpt) -> Result<TxsResult, Error> {
        let txs = self.get_account(opt.subaccount)?.list_tx(opt)?;
        Ok(TxsResult(txs))
    }

    pub fn get_transaction_hex(&self, txid: &str) -> Result<String, Error> {
        let txid = BETxid::from_hex(txid, self.network.id())?;
        let store = self.store()?;
        let store = store.read()?;
        store.get_tx_entry(&txid).map(|e| e.tx.serialize().to_hex())
    }

    pub fn get_transaction_details(&self, txid: &str) -> Result<TransactionDetails, Error> {
        let txid = BETxid::from_hex(txid, self.network.id())?;
        let store = self.store()?;
        let store = store.read()?;
        store.get_tx_entry(&txid).map(|e| e.into())
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

    pub fn create_transaction(
        &mut self,
        tx_req: &mut CreateTransaction,
    ) -> Result<TransactionMeta, Error> {
        info!("electrum create_transaction {:?}", tx_req);

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
        Ok(tx)
    }

    pub fn broadcast_transaction(&mut self, tx_hex: &str) -> Result<String, Error> {
        let transaction = BETransaction::from_hex(&tx_hex, self.network.id())?;

        info!("broadcast_transaction {:#?}", transaction.txid());
        let client = self.url.build_client(self.proxy.as_deref(), None)?;
        let hex = Vec::<u8>::from_hex(tx_hex)?;
        let txid = client.transaction_broadcast_raw(&hex)?;
        Ok(format!("{}", txid))
    }

    /// The estimates are returned as an array of 25 elements. Each element is
    /// an integer representing the fee estimate expressed as satoshi per 1000
    /// bytes. The first element is the minimum relay fee as returned by the
    /// network, while the remaining elements are the current estimates to use
    /// for a transaction to confirm from 1 to 24 blocks.
    pub fn get_fee_estimates(&mut self) -> Result<Vec<FeeEstimate>, Error> {
        let min_fee = match self.network.id() {
            NetworkId::Bitcoin(_) => 1000,
            NetworkId::Elements(_) => 100,
        };
        let fee_estimates =
            try_get_fee_estimates(&self.url.build_client(self.proxy.as_deref(), None)?)
                .unwrap_or_else(|_| vec![FeeEstimate(min_fee); 25]);
        self.store()?.write()?.cache.fee_estimates = fee_estimates.clone();
        Ok(fee_estimates)
        //TODO better implement default
    }

    pub fn get_settings(&self) -> Result<Settings, Error> {
        Ok(self.store()?.read()?.get_settings().unwrap_or_default())
    }

    pub fn change_settings(&mut self, value: &Value) -> Result<(), Error> {
        let mut settings = self.get_settings()?;
        settings.update(value);
        self.store()?.write()?.insert_settings(Some(settings.clone()))?;
        self.notify.settings(&settings);
        Ok(())
    }

    pub fn get_available_currencies(&self) -> Result<Value, Error> {
        Ok(json!({ "all": [ "USD" ], "per_exchange": { "BITFINEX": [ "USD" ] } }))
        // TODO implement
    }

    pub fn refresh_assets(&self, details: &RefreshAssets) -> Result<Value, Error> {
        info!("refresh_assets {:?}", details);

        if !(details.icons || details.assets) {
            return Err(Error::Generic(
                "cannot call refresh assets with both icons and assets false".to_string(),
            ));
        }

        let mut assets = Value::Null;
        let mut icons = Value::Null;
        let mut assets_last_modified = String::new();
        let mut icons_last_modified = String::new();

        if details.refresh {
            let assets_handle = if details.assets {
                let registry_policy = self
                    .network
                    .policy_asset
                    .clone()
                    .ok_or_else(|| Error::Generic("policy assets not available".into()))?;
                let last_modified = self.store()?.read()?.cache.assets_last_modified.clone();
                let base_url = self.network.registry_base_url()?;
                let agent = self.build_request_agent()?;
                Some(thread::spawn(move || {
                    match call_assets(agent, base_url, registry_policy, last_modified) {
                        Ok(assets) => Some(assets),
                        Err(e) => {
                            warn!("call_assets error {:?}", e);
                            None
                        }
                    }
                }))
            } else {
                None
            };

            let icons_handle = if details.icons {
                let last_modified = self.store()?.read()?.cache.icons_last_modified.clone();
                let base_url = self.network.registry_base_url()?;
                let agent = self.build_request_agent()?;
                Some(thread::spawn(move || call_icons(agent, base_url, last_modified).ok()))
            } else {
                None
            };

            if let Some(assets_handle) = assets_handle {
                if let Ok(Some(assets_recv)) = assets_handle.join() {
                    assets = assets_recv.0;
                    assets_last_modified = assets_recv.1;
                }
            }

            if let Some(icons_handle) = icons_handle {
                if let Ok(Some(icons_recv)) = icons_handle.join() {
                    icons = icons_recv.0;
                    icons_last_modified = icons_recv.1;
                }
            }

            let store = self.store()?;
            let mut store_write = store.write()?;
            if let Value::Object(_) = icons {
                store_write.write_asset_icons(&icons)?;
                store_write.cache.icons_last_modified = icons_last_modified;
            }
            if let Value::Object(_) = assets {
                store_write.write_asset_registry(&assets)?;
                store_write.cache.assets_last_modified = assets_last_modified;
            }
        }

        let mut map = serde_json::Map::new();
        if details.assets {
            let assets_not_null = match assets {
                Value::Object(_) => assets,
                _ => self
                    .store()?
                    .read()?
                    .read_asset_registry()?
                    .unwrap_or_else(|| get_registry_sentinel()),
            };
            map.insert("assets".to_string(), assets_not_null);
        }

        if details.icons {
            let icons_not_null = match icons {
                Value::Object(_) => icons,
                _ => self
                    .store()?
                    .read()?
                    .read_asset_icons()?
                    .unwrap_or_else(|| get_registry_sentinel()),
            };
            map.insert("icons".to_string(), icons_not_null);
        }

        Ok(Value::Object(map))
    }

    pub fn get_unspent_outputs(&self, opt: &GetUnspentOpt) -> Result<GetUnspentOutputs, Error> {
        let mut unspent_outputs: HashMap<String, Vec<UnspentOutput>> = HashMap::new();
        let account = self.get_account(opt.subaccount)?;
        let tip = self.store()?.read()?.cache.tip.0;
        let num_confs = opt.num_confs.unwrap_or(0);
        let confidential_utxos_only = opt.confidential_utxos_only.unwrap_or(false);
        for outpoint in account.unspents()? {
            let utxo = account.txo(&outpoint)?;
            let confirmations = match utxo.height {
                None | Some(0) => 0,
                Some(h) => (tip + 1).saturating_sub(h),
            };
            if num_confs > confirmations || (confidential_utxos_only && !utxo.is_confidential()) {
                continue;
            }
            let asset_id = match &utxo.txoutsecrets {
                None => "btc".to_string(),
                Some(s) => s.asset.to_hex(),
            };
            (*unspent_outputs.entry(asset_id).or_insert(vec![])).push(utxo.try_into()?);
        }
        Ok(GetUnspentOutputs(unspent_outputs))
    }

    pub fn export_cache(&mut self) -> Result<RawCache, Error> {
        self.store()?.write()?.export_cache()
    }

    pub fn block_status(&self) -> Result<(u32, BEBlockHash), Error> {
        let tip = self.store()?.read()?.cache.tip;
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

pub fn keys_from_mnemonic(
    mnemonic: &Mnemonic,
    password: Option<Password>,
    network: bitcoin::Network,
) -> Result<(ExtendedPrivKey, ExtendedPubKey, MasterBlindingKey), Error> {
    let mnem_str = mnemonic.clone().get_mnemonic_str();
    let password = password.as_ref().map(|p| p.clone().get_password_str()).unwrap_or_default();
    let seed = wally::bip39_mnemonic_to_seed(&mnem_str, &password).ok_or(Error::InvalidMnemonic)?;
    let master_xprv = ExtendedPrivKey::new_master(network, &seed)?;
    let master_xpub = ExtendedPubKey::from_private(&EC, &master_xprv);
    let master_blinding = asset_blinding_key_from_seed(&seed);
    Ok((master_xprv, master_xpub, master_blinding))
}

fn call_icons(
    agent: ureq::Agent,
    base_url: String,
    last_modified: String,
) -> Result<(Value, String), Error> {
    let url = format!("{}/{}", base_url, "icons.json");
    info!("START call_icons {}", &url);
    let icons_response = agent
        .get(&url)
        .timeout(Duration::from_secs(30))
        .set("If-Modified-Since", &last_modified)
        .call()?;
    let status = icons_response.status();
    info!("call_icons {} returns {}", &url, status);
    let last_modified = icons_response.header("Last-Modified").unwrap_or_default().to_string();
    let value = icons_response.into_json()?;
    info!("END call_icons {} {}", &url, status);
    Ok((value, last_modified))
}

fn call_assets(
    agent: ureq::Agent,
    base_url: String,
    registry_policy: String,
    last_modified: String,
) -> Result<(Value, String), Error> {
    let url = format!("{}/{}", base_url, "index.json");
    info!("START call_assets {}", &url);
    let assets_response = agent
        .get(&url)
        .timeout(Duration::from_secs(30))
        .set("If-Modified-Since", &last_modified)
        .call()?;
    let status = assets_response.status();
    info!("call_assets {} returns {}", url, status);
    let last_modified = assets_response.header("Last-Modified").unwrap_or_default().to_string();
    let mut assets: HashMap<String, AssetEntry> = assets_response.into_json()?;
    info!("downloaded assets map contains {} elements", assets.len());

    let assets_len_before = assets.len();
    assets.retain(|_k, v| v.verify().unwrap_or(false));
    if assets_len_before != assets.len() {
        warn!("{} assets are not verified", assets_len_before - assets.len());
    }

    let asset_policy = AssetEntry::new_policy(&registry_policy)?;
    assets.insert(registry_policy, asset_policy);

    info!("END call_assets {} {}", &url, status);
    Ok((serde_json::to_value(&assets)?, last_modified))
}

impl Tipper {
    pub fn tip(&self, client: &Client) -> Result<(u32, BEBlockHash), Error> {
        let header = client.block_headers_subscribe_raw()?;
        let new_height = header.height as u32;
        let new_hash = BEBlockHeader::deserialize(&header.header, self.network.id())?.block_hash();
        let (current_height, current_hash) = self.store.read()?.cache.tip;
        if new_height != current_height || new_hash != current_hash {
            let new_tip = (new_height, new_hash);
            info!("saving in store new tip {:?}", new_tip);
            self.store.write()?.cache.tip = new_tip;
            Ok(new_tip)
        } else {
            Ok((current_height, current_hash))
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
            drop(acc_store);
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
}

impl Syncer {
    /// Sync the wallet, return the set of updated accounts
    pub fn sync(&self, client: &Client) -> Result<HashMap<BETxid, HashSet<u32>>, Error> {
        debug!("start sync");
        let start = Instant::now();

        let accounts = self.accounts.read().unwrap();
        let mut updated_txs: HashMap<BETxid, HashSet<u32>> = HashMap::new();

        for account in accounts.values() {
            let mut history_txs_id = HashSet::<BETxid>::new();
            let mut heights_set = HashSet::new();
            let mut txid_height = HashMap::<BETxid, _>::new();
            let mut scripts = HashMap::new();

            let mut last_used = Indexes::default();
            let mut wallet_chains = vec![0, 1];
            wallet_chains.shuffle(&mut thread_rng());
            for i in wallet_chains {
                let mut batch_count = 0;
                loop {
                    let batch = account.get_script_batch(i == 1, batch_count)?;
                    // convert the BEScript into bitcoin::Script for electrum-client
                    let b_scripts =
                        batch.value.iter().map(|e| e.0.clone().into_bitcoin()).collect::<Vec<_>>();
                    let result: Vec<Vec<GetHistoryRes>> =
                        client.batch_script_get_history(b_scripts.iter())?;
                    if !batch.cached {
                        scripts.extend(batch.value);
                    }
                    let max = result
                        .iter()
                        .enumerate()
                        .filter(|(_, v)| !v.is_empty())
                        .map(|(i, _)| i as u32)
                        .max();
                    if let Some(max) = max {
                        if i == 0 {
                            last_used.external = max + batch_count * BATCH_SIZE;
                        } else {
                            last_used.internal = max + batch_count * BATCH_SIZE;
                        }
                    };

                    let flattened: Vec<GetHistoryRes> = result.into_iter().flatten().collect();
                    trace!("{}/batch({}) {:?}", i, batch_count, flattened.len());

                    if flattened.is_empty() {
                        break;
                    }

                    let net = self.network.id();

                    for el in flattened {
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

                    batch_count += 1;
                }
            }

            let new_txs = self.download_txs(account.num(), &history_txs_id, &scripts, &client)?;
            let headers = self.download_headers(account.num(), &heights_set, &client)?;

            let store_read = self.store.read()?;
            let acc_store = store_read.account_cache(account.num())?;
            let store_indexes = acc_store.indexes.clone();
            let txs_heights_changed = txid_height
                .iter()
                .any(|(txid, height)| acc_store.heights.get(txid) != Some(height))
                || acc_store.heights.keys().any(|txid| txid_height.get(txid).is_none());
            drop(acc_store);
            drop(store_read);

            let changed = if !new_txs.txs.is_empty()
                || !headers.is_empty()
                || store_indexes != last_used
                || !scripts.is_empty()
                || txs_heights_changed
            {
                info!(
                    "There are changes in the store new_txs:{:?} headers:{:?} txid_height:{:?}",
                    new_txs.txs.iter().map(|tx| tx.0).collect::<Vec<_>>(),
                    headers,
                    txid_height
                );
                let mut store_write = self.store.write()?;
                store_write.cache.headers.extend(headers);

                let mut acc_store = store_write.account_cache_mut(account.num())?;
                acc_store.indexes = last_used;
                acc_store
                    .all_txs
                    .extend(new_txs.txs.iter().cloned().map(|(txid, tx)| (txid, tx.into())));
                acc_store.unblinded.extend(new_txs.unblinds);

                // height map is used for the live list of transactions, since due to reorg or rbf tx
                // could disappear from the list, we clear the list and keep only the last values returned by the server
                acc_store.heights.clear();
                acc_store.heights.extend(txid_height.into_iter());
                acc_store.scripts.extend(scripts.clone().into_iter().map(|(a, b)| (b, a)));
                acc_store.paths.extend(scripts.into_iter());

                store_write.flush()?;
                drop(store_write);

                for tx in new_txs.txs.iter() {
                    if let Some(accounts) = updated_txs.get_mut(&tx.0) {
                        accounts.insert(account.num());
                    } else {
                        let mut accounts = HashSet::new();
                        accounts.insert(account.num());
                        updated_txs.insert(tx.0, accounts);
                    }
                }

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

        Ok(updated_txs)
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
            info!("headers_downloaded {:?}", &headers_downloaded);
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

                            match self.try_unblind(outpoint, output.clone()) {
                                Ok(unblinded) => unblinds.push((outpoint, unblinded)),
                                Err(_) => info!("{} cannot unblind, ignoring (could be sender messed up with the blinding process)", outpoint),
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
                    let mut tx = BETransaction::deserialize(&vec, self.network.id())?;
                    tx.strip_witness();
                    txs.push((tx.txid(), tx));
                }
            }
            Ok(DownloadTxResult {
                txs,
                unblinds,
            })
        } else {
            Ok(DownloadTxResult::default())
        }
    }

    pub fn try_unblind(
        &self,
        outpoint: elements::OutPoint,
        output: elements::TxOut,
    ) -> Result<elements::TxOutSecrets, Error> {
        match (output.asset, output.value, output.nonce) {
            (
                Asset::Confidential(_),
                confidential::Value::Confidential(_),
                Nonce::Confidential(_),
            ) => {
                let master_blinding = self.master_blinding.as_ref().unwrap();

                let script = output.script_pubkey.clone();
                let blinding_key = asset_blinding_key_to_ec_private_key(master_blinding, &script);
                let txout_secrets = output.unblind(&EC, blinding_key)?;
                info!(
                    "Unblinded outpoint:{} asset:{} value:{}",
                    outpoint,
                    txout_secrets.asset.to_hex(),
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

// Return a sentinel value that the caller should interpret as "no cached data"
fn get_registry_sentinel() -> Value {
    json!({})
}

#[cfg(feature = "testing")]
impl ElectrumSession {
    pub fn filter_events(&self, event: &str) -> Vec<Value> {
        self.notify.filter_events(event)
    }
}
