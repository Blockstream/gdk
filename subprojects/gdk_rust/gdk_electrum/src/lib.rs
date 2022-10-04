mod store;

#[macro_use]
extern crate serde_json;

#[macro_use]
extern crate gdk_common;

use headers::bitcoin::HEADERS_FILE_MUTEX;
use log::{debug, info, trace, warn};
use serde_json::Value;

pub mod account;
pub mod error;
pub mod headers;
pub mod interface;
pub mod pin;
pub mod pset;
pub mod session;
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
use gdk_common::model::*;
use gdk_common::network::NetworkParameters;
use gdk_common::wally::{
    self, asset_blinding_key_from_seed, asset_blinding_key_to_ec_private_key, MasterBlindingKey,
};
use gdk_common::{be::*, State};

use elements::confidential::{self, Asset, Nonce};
use elements::encode;
use elements::pset::PartiallySignedTransaction;
use gdk_common::exchange_rates::ExchangeRatesCache;
use gdk_common::network;
use gdk_common::NetworkId;
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use std::{iter, thread};

use crate::headers::bitcoin::HeadersChain;
use crate::headers::liquid::Verifier;
use crate::headers::ChainOrVerifier;
use crate::pin::PinManager;
use crate::spv::SpvCrossValidator;
use aes::Aes256;
use bitcoin::blockdata::constants::DIFFCHANGE_INTERVAL;
use block_modes::block_padding::Pkcs7;
use block_modes::BlockMode;
use block_modes::Cbc;
use electrum_client::{Client, ElectrumApi};
pub use gdk_common::notification::{NativeNotif, Notification, TransactionNotification};
use once_cell::sync::Lazy;
use rand::seq::SliceRandom;
use rand::thread_rng;
use rand::Rng;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::thread::JoinHandle;

const CROSS_VALIDATION_RATE: u8 = 4; // Once every 4 thread loop runs, or roughly 28 seconds

static EC: Lazy<secp256k1::Secp256k1<secp256k1::All>> = Lazy::new(|| {
    let mut ctx = secp256k1::Secp256k1::new();
    let mut rng = rand::thread_rng();
    ctx.randomize(&mut rng);
    ctx
});

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

struct Syncer {
    accounts: Arc<RwLock<HashMap<u32, Account>>>,
    store: Store,
    master_blinding: Option<MasterBlindingKey>,
    network: NetworkParameters,
    recent_spent_utxos: Arc<RwLock<HashSet<BEOutPoint>>>,
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

    /// Spent utxos
    ///
    /// Remember the spent utxos to avoid using them in transaction that are created after
    /// the previous send/broadcast tx, but before the next sync.
    ///
    /// This set it emptied after every sync.
    pub recent_spent_utxos: Arc<RwLock<HashSet<BEOutPoint>>>,

    xr_cache: ExchangeRatesCache,
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

    fn inner_decrypt_with_pin(&mut self, details: PinGetDetails) -> Result<Vec<u8>, Error> {
        let agent = self.build_request_agent()?;
        let manager = PinManager::new(
            agent,
            self.network.pin_server_url(),
            &self.network.pin_manager_public_key()?,
        )?;
        let client_key =
            SecretKey::from_slice(&Vec::<u8>::from_hex(&details.pin_data.pin_identifier)?)?;
        let server_key = manager.get_pin(details.pin.as_bytes(), &client_key)?;
        let iv = Vec::<u8>::from_hex(&details.pin_data.salt)?;
        let decipher = Aes256Cbc::new_from_slices(&server_key[..], &iv).unwrap();
        // If the pin is wrong, pinserver returns a random key and decryption fails, return a
        // specific error to signal the caller to update its pin counter.
        decipher
            .decrypt_vec(&Vec::<u8>::from_hex(&details.pin_data.encrypted_data)?)
            .map_err(|_| Error::InvalidPin)
    }

    pub fn decrypt_with_pin(&mut self, details: PinGetDetails) -> Result<Value, Error> {
        let decrypted = self.inner_decrypt_with_pin(details)?;
        Ok(serde_json::from_slice(&decrypted[..])?)
    }

    pub fn credentials_from_pin_data(
        &mut self,
        details: PinGetDetails,
    ) -> Result<Credentials, Error> {
        let decrypted = self.inner_decrypt_with_pin(details)?;
        if let Ok(credentials) = serde_json::from_slice(&decrypted[..]) {
            Ok(credentials)
        } else {
            // Some pin_data encrypt the bare mnemonic, not a json
            Ok(Credentials {
                mnemonic: std::str::from_utf8(&decrypted)
                    .map_err(|_| Error::InvalidPin)?
                    .to_string(),
                bip39_passphrase: "".to_string(),
            })
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
            self.notify.block_from_hashes(tip_height, &tip_hash, &tip_prev_hash);
        };

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

        let syncer_tipper_handle = thread::spawn(move || {
            info!("starting syncer & tipper thread");

            let update_tip = |client: &Client, do_update: bool| match tipper.tip(&client, do_update)
            {
                Ok(Some((height, header))) => {
                    // This is a new block
                    if do_update {
                        notify.block_from_header(height, &header);
                    }
                    Ok(Some(height))
                }
                Ok(None) => Ok(None), // nothing to update
                Err(e) => {
                    warn!("exception in tipper {:?}", e);
                    Err(e)
                }
            };

            let mut first_sync = true;

            let mut sync = |client: &Client| {
                match syncer.sync(&client) {
                    Ok(tx_ntfs) => {
                        state_updater.update_if_needed(true);
                        // Skip sending transaction notifications if it's the
                        // first call to sync. This allows us to _not_ notify
                        // transactions that were sent or received before
                        // login.
                        if !first_sync {
                            for ntf in tx_ntfs.iter() {
                                info!("there are new transactions");
                                notify.updated_txs(ntf);
                            }
                        }
                        first_sync = false;
                    }
                    Err(e) => {
                        state_updater.update_if_needed(false);
                        warn!("Error during sync, {:?}", e)
                    }
                }
            };

            loop {
                match url.build_client(proxy.as_deref(), None) {
                    Ok(client) => {
                        let tip_before_sync = match update_tip(&client, false) {
                            Ok(height) => height,
                            Err(_) => {
                                continue;
                            }
                        };

                        sync(&client);

                        let tip_after_sync = match update_tip(&client, true) {
                            Ok(height) => height,
                            Err(_) => {
                                continue;
                            }
                        };

                        let should_resync = match (tip_before_sync, tip_after_sync) {
                            (None, Some(_)) => true,
                            (Some(before), Some(after)) if before != after => true,
                            _ => false,
                        };

                        if should_resync {
                            // If a block arrives while we are syncing
                            // transactions, transactions might be returned as
                            // unconfirmed even if they belong to the newly
                            // notified block. Sync again to ensure
                            // consistency.
                            continue;
                        }
                    }

                    Err(err) => {
                        state_updater.update_if_needed(false);
                        warn!("Can't build client {:?}", err);
                    }
                };

                if wait_or_close(&user_wants_to_sync, sync_interval) {
                    info!("closing syncer & tipper thread");
                    break;
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
        })
    }

    pub fn get_receive_address(&self, opt: &GetAddressOpt) -> Result<AddressPointer, Error> {
        debug!("get_receive_address {:?}", opt);
        let address =
            self.get_account(opt.subaccount)?.get_next_address(opt.is_internal.unwrap_or(false))?;
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
        let manager = PinManager::new(
            agent,
            self.network.pin_server_url(),
            &self.network.pin_manager_public_key()?,
        )?;
        let client_key = SecretKey::new(&mut thread_rng());
        let server_key = manager.set_pin(details.pin.as_bytes(), &client_key)?;
        let iv = thread_rng().gen::<[u8; 16]>();
        let cipher = Aes256Cbc::new_from_slices(&server_key[..], &iv).unwrap();
        let plaintext = serde_json::to_vec(&details.plaintext)?;
        let encrypted = cipher.encrypt_vec(&plaintext);

        let result = PinData {
            salt: iv.to_hex(),
            encrypted_data: encrypted.to_hex(),
            pin_identifier: client_key.secret_bytes().to_hex(),
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
            if !account.has_transactions()? {
                bail!(Error::AccountGapsDisallowed);
            }
        }

        let account = match accounts.entry(opt.subaccount) {
            Entry::Occupied(entry) => entry.into_mut(),
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

    pub fn psbt_get_details(
        &mut self,
        params: PsbtGetDetailsParams,
    ) -> Result<PsbtGetDetailsResult, Error> {
        if !self.network.liquid {
            return Err(Error::Generic(
                "`ElectrumSession::psbt_get_details` is currently only supported for Liquid"
                    .to_owned(),
            ));
        }

        let pset = {
            let pset_bytes = base64::decode(&params.psbt)?;
            encode::deserialize::<PartiallySignedTransaction>(&pset_bytes)?
        };

        let inputs = pset
            .inputs()
            .iter()
            .filter_map(|input| {
                params
                    .utxos
                    .iter()
                    .find(|utxo| {
                        utxo.txhash == input.previous_txid.to_string()
                            && utxo.pt_idx == input.previous_output_index
                    })
                    .cloned()
            })
            .map(|utxo| match utxo.asset_id {
                Some(_) => Ok(utxo),
                None => Err(Error::Generic("`asset_id` field not present".into())),
            })
            .collect::<Result<Vec<_>, _>>()?;

        let master_blinding = self
            .get_master_blinding_key()?
            .master_blinding_key
            .ok_or(Error::MissingMasterBlindingKey)?;

        let accounts = self.get_accounts()?;

        let outputs = pset
            .outputs()
            .iter()
            .map(|output| {
                let mut tx_out = output.to_txout();

                // the `nonce` field of `tx_out` would be `Nonce::Null` w/o
                // this
                tx_out.nonce = output
                    .ecdh_pubkey
                    .map(|pk| confidential::Nonce::from(pk.inner))
                    .unwrap_or_default();

                tx_out
            })
            .filter_map(|tx_out| {
                let script = BEScript::Elements(tx_out.script_pubkey.clone());

                let subaccount = accounts.iter().find_map(|account| {
                    self.store
                        .as_ref()?
                        .read()
                        .ok()?
                        .account_cache(account.num())
                        .ok()?
                        .get_path(&script)
                        .is_ok()
                        .then(|| account.num())
                })?;

                unblind_output(tx_out, &master_blinding, None)
                    .map(|secrets| PsbtGetDetailsOut::new(secrets.asset, secrets.value, subaccount))
                    .ok()
            })
            .collect::<Vec<_>>();

        Ok(PsbtGetDetailsResult::new(inputs, outputs))
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
        // TODO: use blockstream endpoint listing all available currencies when
        // it'll be available.
        Ok(json!({ "all": [ "USD" ], "per_exchange": { "Blockstream": [ "USD" ] } }))
    }

    pub fn get_unspent_outputs(&self, opt: &GetUnspentOpt) -> Result<GetUnspentOutputs, Error> {
        let mut unspent_outputs: HashMap<String, Vec<UnspentOutput>> = HashMap::new();
        let account = self.get_account(opt.subaccount)?;
        let height = self.store()?.read()?.cache.tip_height();
        let num_confs = opt.num_confs.unwrap_or(0);
        let confidential_utxos_only = opt.confidential_utxos_only.unwrap_or(false);
        for outpoint in account.unspents()? {
            let utxo = account.txo(&outpoint)?;
            let confirmations = match utxo.height {
                None | Some(0) => 0,
                Some(h) => (height + 1).saturating_sub(h),
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
    pub fn tip(
        &self,
        client: &Client,
        update_cache: bool,
    ) -> Result<Option<(u32, BEBlockHeader)>, Error> {
        let header = client.block_headers_subscribe_raw()?;
        let new_height = header.height as u32;
        let new_header = BEBlockHeader::deserialize(&header.header, self.network.id())?;
        if !update_cache {
            return Ok(Some((new_height, new_header)));
        }
        let do_update = match &self.store.read()?.cache.tip_ {
            None => true,
            Some((current_height, current_header)) => {
                &new_height != current_height || &new_header != current_header
            }
        };
        if do_update {
            info!("saving in store new tip {:?}", new_height);
            self.store.write()?.cache.tip_ = Some((new_height, new_header.clone()));
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
    pub fn sync(&self, client: &Client) -> Result<Vec<TransactionNotification>, Error> {
        trace!("start sync");
        let start = Instant::now();

        let accounts = self.accounts.read().unwrap();
        let mut updated_txs: HashMap<BETxid, TransactionNotification> = HashMap::new();

        for account in accounts.values() {
            let mut history_txs_id = HashSet::<BETxid>::new();
            let mut heights_set = HashSet::new();
            let mut txid_height = HashMap::<BETxid, _>::new();
            let mut scripts = HashMap::new();

            let mut last_used = Indexes::default();
            let mut wallet_chains = vec![0, 1];
            wallet_chains.shuffle(&mut thread_rng());
            for i in wallet_chains {
                let is_internal = i == 1;
                let mut batch_count = 0;
                loop {
                    let batch = account.get_script_batch(is_internal, batch_count)?;
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
                        if is_internal {
                            last_used.internal = max + batch_count * BATCH_SIZE;
                        } else {
                            last_used.external = max + batch_count * BATCH_SIZE;
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

                for tx in new_txs.txs.iter() {
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
                                Err(_) => warn!("{} cannot unblind, ignoring (could be sender messed up with the blinding process)", outpoint),
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
}
