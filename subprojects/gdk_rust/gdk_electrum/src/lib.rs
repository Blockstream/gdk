mod store;

#[macro_use]
extern crate serde_json;

#[macro_use]
extern crate lazy_static;

#[macro_use]
extern crate gdk_common;

use log::{debug, info, trace, warn};
use serde_json::Value;

pub mod account;
pub mod error;
pub mod headers;
pub mod interface;
pub mod pin;
pub mod pset;
pub mod spv;

use crate::error::Error;
use crate::interface::{ElectrumUrl, WalletCtx};
use crate::store::*;

use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::secp256k1::{self, Secp256k1, SecretKey};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};

use electrum_client::GetHistoryRes;
use gdk_common::be::*;
use gdk_common::mnemonic::Mnemonic;
use gdk_common::model::*;
use gdk_common::network::{aqua_unique_id_and_xpub, Network};
use gdk_common::password::Password;
use gdk_common::session::Session;
use gdk_common::wally::{
    self, asset_blinding_key_from_seed, asset_blinding_key_to_ec_private_key, make_str,
    MasterBlindingKey,
};

use elements::confidential::{self, Asset, Nonce};
use gdk_common::NetworkId;
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::time::{Duration, Instant};
use std::{iter, sync, thread};

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
use rand::seq::SliceRandom;
use rand::thread_rng;
use rand::Rng;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::sync::{mpsc, Arc, RwLock};
use std::thread::JoinHandle;

const CROSS_VALIDATION_RATE: u8 = 4; // Once every 4 thread loop runs, or roughly 28 seconds

lazy_static! {
    static ref EC: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

struct Syncer {
    wallet: Arc<RwLock<WalletCtx>>,
    store: Store,
    master_blinding: Option<MasterBlindingKey>,
    network: Network,
}

pub struct Tipper {
    pub store: Store,
    pub network: Network,
}

pub struct Headers {
    pub store: Store,
    pub checker: ChainOrVerifier,
    pub cross_validator: Option<SpvCrossValidator>,
}

#[derive(Clone)]
pub struct NativeNotif(
    pub Option<(extern "C" fn(*const libc::c_void, *const libc::c_char), *const libc::c_void)>,
);
unsafe impl Send for NativeNotif {}

pub struct Closer {
    pub senders: Vec<Sender<()>>,
    pub handles: Vec<JoinHandle<()>>,
}

impl Closer {
    pub fn close(&mut self) -> Result<(), Error> {
        while let Some(sender) = self.senders.pop() {
            sender.send(())?;
        }
        while let Some(handle) = self.handles.pop() {
            handle.join().expect("Couldn't join on the associated thread");
        }
        Ok(())
    }
}

pub struct ElectrumSession {
    pub data_root: String,
    pub proxy: Option<String>,
    pub network: Network,
    pub url: ElectrumUrl,
    pub wallet: Option<Arc<RwLock<WalletCtx>>>,
    pub notify: NativeNotif,
    pub closer: Closer,
    pub state: State,
}

#[derive(Debug, PartialEq)]
pub enum State {
    Disconnected,
    Connected,
    Logged,
}

fn notify(notif: NativeNotif, data: Value) {
    info!("push notification: {:?}", data);
    if let Some((handler, self_context)) = notif.0 {
        // TODO check the native pointer is still alive
        handler(self_context, make_str(data.to_string()));
    } else {
        warn!("no registered handler to receive notification");
    }
}

fn notify_block(notif: NativeNotif, height: u32) {
    let data = json!({"block":{"block_height":height},"event":"block"});
    notify(notif, data);
}

fn notify_settings(notif: NativeNotif, settings: &Settings) {
    let data = json!({"settings":settings,"event":"settings"});
    notify(notif, data);
}

fn notify_updated_txs(notif: NativeNotif, account_num: u32) {
    // This is used as a signal to trigger syncing via get_transactions, the transaction
    // list contained here is ignored and can be just a mock.
    let mockup_json = json!({"event":"transaction","transaction":{"subaccounts":[account_num]}});
    notify(notif, mockup_json);
}

fn determine_electrum_url(
    url: &Option<String>,
    tls: Option<bool>,
    validate_domain: Option<bool>,
) -> Result<ElectrumUrl, Error> {
    let url = url.as_ref().ok_or_else(|| Error::Generic("network url is missing".into()))?;
    if url == "" {
        return Err(Error::Generic("network url is empty".into()));
    }

    if tls.unwrap_or(false) {
        Ok(ElectrumUrl::Tls(url.into(), validate_domain.unwrap_or(false)))
    } else {
        Ok(ElectrumUrl::Plaintext(url.into()))
    }
}

pub fn determine_electrum_url_from_net(network: &Network) -> Result<ElectrumUrl, Error> {
    determine_electrum_url(&network.electrum_url, network.electrum_tls, network.validate_domain)
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

impl ElectrumSession {
    pub fn create_session(
        network: Network,
        db_root: &str,
        proxy: Option<&str>,
        url: ElectrumUrl,
    ) -> Self {
        Self {
            data_root: db_root.to_string(),
            proxy: socksify(proxy),
            network,
            url,
            wallet: None,
            notify: NativeNotif(None),
            closer: Closer {
                senders: vec![],
                handles: vec![],
            },
            state: State::Disconnected,
        }
    }

    pub fn get_wallet(&self) -> Result<sync::RwLockReadGuard<WalletCtx>, Error> {
        let wallet =
            self.wallet.as_ref().ok_or_else(|| Error::Generic("wallet not initialized".into()))?;
        Ok(wallet.read().unwrap())
    }

    pub fn get_wallet_mut(&mut self) -> Result<sync::RwLockWriteGuard<WalletCtx>, Error> {
        let wallet =
            self.wallet.as_mut().ok_or_else(|| Error::Generic("wallet not initialized".into()))?;
        Ok(wallet.write().unwrap())
    }

    pub fn build_request_agent(&self) -> Result<ureq::Agent, Error> {
        match &self.proxy {
            Some(proxy) => {
                let proxy = ureq::Proxy::new(&proxy)?;
                let mut agent = ureq::agent();
                agent.set_proxy(proxy);
                Ok(agent)
            }
            None => Ok(ureq::agent()),
        }
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

pub fn make_txlist_item(
    tx: &TransactionMeta,
    all_txs: &BETransactions,
    all_unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
    all_scripts: &HashMap<BEScript, DerivationPath>,
    network_id: NetworkId,
) -> TxListItem {
    let type_ = tx.type_.clone();
    let fee_rate = (tx.fee as f64 / tx.weight as f64 * 4000.0) as u64;
    let addressees = tx
        .create_transaction
        .as_ref()
        .unwrap()
        .addressees
        .iter()
        .map(|e| e.address.clone())
        .collect();
    let can_rbf =
        tx.height.is_none() && tx.rbf_optin && type_ != "incoming" && type_ != "unblindable";

    let transaction = BETransaction::from_hex(&tx.hex, network_id).expect("inconsistent network");
    let inputs = transaction
        .previous_outputs()
        .iter()
        .enumerate()
        .map(|(vin, i)| {
            let mut a = AddressIO::default();
            a.is_output = false;
            a.is_spent = true;
            a.pt_idx = vin as u32;
            a.satoshi = all_txs.get_previous_output_value(i, all_unblinded).unwrap_or_default();
            if let BEOutPoint::Elements(outpoint) = i {
                a.asset_id = all_txs
                    .get_previous_output_asset(*outpoint, all_unblinded)
                    .map_or("".to_string(), |a| a.to_hex());
                a.assetblinder = all_txs
                    .get_previous_output_assetblinder_hex(*outpoint, all_unblinded)
                    .unwrap_or_default();
                a.amountblinder = all_txs
                    .get_previous_output_amountblinder_hex(*outpoint, all_unblinded)
                    .unwrap_or_default();
            }
            a.is_relevant = {
                if let Some(script) = all_txs.get_previous_output_script_pubkey(i) {
                    all_scripts.get(&script).is_some()
                } else {
                    false
                }
            };
            a
        })
        .collect();

    let outputs = (0..transaction.output_len() as u32)
        .map(|vout| {
            let mut a = AddressIO::default();
            a.is_output = true;
            // FIXME: this can be wrong, however setting this value correctly might be quite
            // expensive: involing db hits and potentially network calls; postponing it for now.
            a.is_spent = false;
            a.pt_idx = vout;
            a.satoshi = transaction.output_value(vout, all_unblinded).unwrap_or_default();
            if let BETransaction::Elements(_) = transaction {
                a.asset_id = transaction
                    .output_asset(vout, all_unblinded)
                    .map_or("".to_string(), |a| a.to_hex());
                a.assetblinder =
                    transaction.output_assetblinder_hex(vout, all_unblinded).unwrap_or_default();
                a.amountblinder =
                    transaction.output_amountblinder_hex(vout, all_unblinded).unwrap_or_default();
            }
            a.is_relevant = all_scripts.contains_key(&transaction.output_script(vout));
            a
        })
        .collect();

    TxListItem {
        block_height: tx.height.unwrap_or_default(),
        created_at_ts: tx.timestamp as u64,
        type_,
        memo: tx.create_transaction.as_ref().and_then(|c| c.memo.clone()).unwrap_or("".to_string()),
        txhash: tx.txid.clone(),
        transaction: tx.hex.clone(), // FIXME
        satoshi: tx.satoshi.clone(),
        rbf_optin: tx.rbf_optin, // TODO: TransactionMeta -> TxListItem rbf_optin
        can_cpfp: false,         // TODO: TransactionMeta -> TxListItem can_cpfp
        can_rbf,
        has_payment_request: false, // TODO: Remove
        server_signed: false,       // TODO: TransactionMeta -> TxListItem server_signed
        user_signed: tx.user_signed,
        spv_verified: tx.spv_verified.to_string(),
        instant: false, // TODO: Remove
        fee: tx.fee,
        fee_rate,
        addressees, // notice the extra "e" -- its intentional
        inputs,
        outputs,
        transaction_size: tx.size,
        transaction_vsize: tx.vsize,
        transaction_weight: tx.weight,
    }
}

impl Session<Error> for ElectrumSession {
    // type Value = ElectrumSession;

    fn poll_session(&self) -> Result<(), Error> {
        Err(Error::Generic("implementme: ElectrumSession poll_session".into()))
    }

    fn connect(&mut self, _net_params: &Value) -> Result<(), Error> {
        info!("connect network:{:?} state:{:?}", self.network, self.state);

        if self.state == State::Disconnected {
            let mnemonic = match self.get_mnemonic() {
                Ok(mnemonic) => Some(mnemonic.clone()),
                Err(_) => None,
            };
            match mnemonic {
                Some(mnemonic) => self.login(&mnemonic, None).map(|_| ())?,
                None => self.state = State::Connected,
            }
        }
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        info!("disconnect state:{:?}", self.state);
        if self.state == State::Logged {
            info!("disconnect STATUS block:{:?} tx:{}", self.block_status()?, self.tx_status()?);
        }
        if self.state != State::Disconnected {
            self.closer.close()?;
            self.state = State::Disconnected;
        }
        Ok(())
    }

    fn mnemonic_from_pin_data(
        &mut self,
        pin: String,
        details: PinGetDetails,
    ) -> Result<String, Error> {
        let agent = self.build_request_agent()?;
        let manager = PinManager::new(agent)?;
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

    fn login(
        &mut self,
        mnemonic: &Mnemonic,
        password: Option<Password>,
    ) -> Result<LoginData, Error> {
        info!("login {:?} {:?}", self.network, self.state);

        if self.state == State::Logged {
            return Ok(LoginData {
                wallet_hash_id: self.network.wallet_hash_id(&self.get_wallet()?.master_xpub),
            });
        }

        // TODO: passphrase?

        let mnem_str = mnemonic.clone().get_mnemonic_str();
        let seed = wally::bip39_mnemonic_to_seed(
            &mnem_str,
            &password.map(|p| p.get_password_str()).unwrap_or_default(),
        )
        .ok_or(Error::InvalidMnemonic)?;
        let secp = Secp256k1::new();

        let master_xprv = ExtendedPrivKey::new_master(self.network.bip32_network(), &seed)?;
        let master_xpub = ExtendedPubKey::from_private(&secp, &master_xprv);

        let master_blinding = if self.network.liquid {
            Some(asset_blinding_key_from_seed(&seed))
        } else {
            None
        };

        let wallet_hash_id = self.network.wallet_hash_id(&master_xpub);
        let (aqua_wallet_id, fallback_xpub) =
            match aqua_unique_id_and_xpub(&seed, self.network.id()) {
                Ok((id, xpub)) => (Some(id), Some(xpub)),
                Err(_) => (None, None),
            };

        let mut path: PathBuf = self.data_root.as_str().into();
        let mut fpath = path.clone();
        let mut fallback_path = None;
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
        } else {
            if let Some(id) = aqua_wallet_id {
                fpath.push(id.as_ref().to_hex());
                info!("Fallback store root path: {:?}", fpath);
                fallback_path = Some(fpath.as_path());
            }
        }
        path.push(wallet_hash_id);
        info!("Store root path: {:?}", path);
        let store = match self.get_wallet() {
            Ok(wallet) => wallet.store.clone(),
            Err(_) => Arc::new(RwLock::new(StoreMeta::new(
                &path,
                master_xpub,
                fallback_path,
                fallback_xpub,
                self.network.id(),
            )?)),
        };

        let mut tip_height = store.read()?.cache.tip.0;
        notify_block(self.notify.clone(), tip_height);

        info!(
            "building client, url {}, proxy {}",
            self.url.url(),
            self.proxy.as_ref().unwrap_or(&"".to_string())
        );
        if let Ok(fee_client) = self.url.build_client(self.proxy.as_deref()) {
            info!("building built end");
            let fee_store = store.clone();
            thread::spawn(move || {
                match try_get_fee_estimates(&fee_client) {
                    Ok(fee_estimates) => {
                        fee_store.write().unwrap().cache.fee_estimates = fee_estimates
                    }
                    Err(e) => warn!("can't update fee estimates {:?}", e),
                };
            });
        }

        let sync_interval = self.network.sync_interval.unwrap_or(7);

        if self.network.spv_enabled.unwrap_or(false) {
            let checker = match self.network.id() {
                NetworkId::Bitcoin(network) => {
                    let mut path: PathBuf = self.data_root.as_str().into();
                    path.push(format!("headers_chain_{}", network));
                    ChainOrVerifier::Chain(HeadersChain::new(path, network)?)
                }
                NetworkId::Elements(network) => {
                    let verifier = Verifier::new(network);
                    ChainOrVerifier::Verifier(verifier)
                }
            };

            let cross_validator = SpvCrossValidator::from_network(&self.network)?;

            let mut headers = Headers {
                store: store.clone(),
                checker,
                cross_validator,
            };

            let headers_url = self.url.clone();
            let proxy = self.proxy.clone();
            let (close_headers, r) = channel();
            self.closer.senders.push(close_headers);
            let notify_headers = self.notify.clone();
            let chunk_size = DIFFCHANGE_INTERVAL as usize;
            let headers_handle = thread::spawn(move || {
                info!("starting headers thread");
                let mut round = 0u8;

                'outer: loop {
                    if wait_or_close(&r, sync_interval) {
                        info!("closing headers thread");
                        break;
                    }

                    if let Ok(client) = headers_url.build_client(proxy.as_deref()) {
                        loop {
                            if r.try_recv().is_ok() {
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
                                    if let Err(e) = headers.remove(144) {
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
                                // TODO account number
                                notify_updated_txs(notify_headers.clone(), 0u32.into());
                            }
                        }

                        round = round.wrapping_add(1);
                    }
                }
            });
            self.closer.handles.push(headers_handle);
        }

        let wallet = match &self.wallet {
            Some(wallet) => wallet.clone(),
            None => {
                let wallet = Arc::new(RwLock::new(WalletCtx::new(
                    store.clone(),
                    mnemonic.clone(),
                    self.network.clone(),
                    master_xprv,
                    master_xpub,
                    master_blinding.clone(),
                )?));
                self.wallet = Some(wallet.clone());
                wallet
            }
        };

        // Recover BIP 44 accounts on the first login
        if !store.read().unwrap().cache.accounts_recovered {
            wallet.write().unwrap().recover_accounts(&self.url, self.proxy.as_deref())?;
            store.write().unwrap().cache.accounts_recovered = true;
        }

        let syncer = Syncer {
            wallet: wallet.clone(),
            store: store.clone(),
            master_blinding,
            network: self.network.clone(),
        };

        let tipper = Tipper {
            store: store.clone(),
            network: self.network.clone(),
        };

        info!("login STATUS block:{:?} tx:{}", self.block_status()?, self.tx_status()?);

        let notify_blocks = self.notify.clone();

        let (close_tipper, r) = channel();
        self.closer.senders.push(close_tipper);
        let tipper_url = self.url.clone();
        let proxy = self.proxy.clone();
        let tipper_handle = thread::spawn(move || {
            info!("starting tipper thread");
            loop {
                if let Ok(client) = tipper_url.build_client(proxy.as_deref()) {
                    match tipper.tip(&client) {
                        Ok(current_tip) => {
                            if tip_height != current_tip {
                                tip_height = current_tip;
                                info!("tip is {:?}", tip_height);
                                notify_block(notify_blocks.clone(), tip_height);
                            }
                        }
                        Err(e) => {
                            warn!("exception in tipper {:?}", e);
                        }
                    }
                }
                if wait_or_close(&r, sync_interval) {
                    info!("closing tipper thread {:?}", tip_height);
                    break;
                }
            }
        });
        self.closer.handles.push(tipper_handle);

        let (close_syncer, r) = channel();
        self.closer.senders.push(close_syncer);
        let notify_txs = self.notify.clone();
        let syncer_url = self.url.clone();
        let proxy = self.proxy.clone();
        let syncer_handle = thread::spawn(move || {
            info!("starting syncer thread");
            loop {
                match syncer_url.build_client(proxy.as_deref()) {
                    Ok(client) => match syncer.sync(&client) {
                        Ok(updated_accounts) => {
                            for account_num in updated_accounts {
                                info!("there are new transactions");
                                notify_updated_txs(notify_txs.clone(), account_num);
                            }
                        }
                        Err(e) => warn!("Error during sync, {:?}", e),
                    },
                    Err(e) => warn!("Can't build client {:?}", e),
                }
                if wait_or_close(&r, sync_interval) {
                    info!("closing syncer thread");
                    break;
                }
            }
        });
        self.closer.handles.push(syncer_handle);

        notify_settings(self.notify.clone(), &self.get_settings()?);

        self.state = State::Logged;
        Ok(LoginData {
            wallet_hash_id: self.network.wallet_hash_id(&master_xpub),
        })
    }

    fn get_receive_address(&self, opt: &GetAddressOpt) -> Result<AddressPointer, Error> {
        debug!("get_receive_address {:?}", opt);
        let address = self.get_wallet()?.get_next_address(opt.subaccount)?;
        debug!("get_address {:?}", address);
        Ok(address)
    }

    fn set_pin(&self, details: &PinSetDetails) -> Result<PinGetDetails, Error> {
        let agent = self.build_request_agent()?;
        let manager = PinManager::new(agent)?;
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

    fn get_subaccounts(&self) -> Result<Vec<AccountInfo>, Error> {
        let wallet = self.get_wallet()?;
        wallet.iter_accounts_sorted().map(|a| a.info()).collect()
    }

    fn get_subaccount(&self, account_num: u32) -> Result<AccountInfo, Error> {
        let wallet = self.get_wallet()?;
        wallet.get_account(account_num)?.info()
    }

    fn create_subaccount(&mut self, opt: CreateAccountOpt) -> Result<AccountInfo, Error> {
        let mut wallet = self.get_wallet_mut()?;
        let account = wallet.create_account(opt)?;
        account.info()
    }

    fn get_next_subaccount(&self, opt: GetNextAccountOpt) -> Result<u32, Error> {
        Ok(self.get_wallet()?.get_next_subaccount(opt.script_type))
    }

    fn rename_subaccount(&mut self, opt: RenameAccountOpt) -> Result<(), Error> {
        self.get_wallet_mut()?.update_account(UpdateAccountOpt {
            subaccount: opt.subaccount,
            name: Some(opt.new_name),
            hidden: None,
        })
    }

    fn set_subaccount_hidden(&mut self, opt: SetAccountHiddenOpt) -> Result<(), Error> {
        self.get_wallet_mut()?.update_account(UpdateAccountOpt {
            subaccount: opt.subaccount,
            hidden: Some(opt.hidden),
            name: None,
        })
    }

    fn update_subaccount(&mut self, opt: UpdateAccountOpt) -> Result<(), Error> {
        self.get_wallet_mut()?.update_account(opt)
    }

    fn get_transactions(&self, opt: &GetTransactionsOpt) -> Result<TxsResult, Error> {
        let wallet = self.get_wallet()?;
        let store = wallet.store.read()?;
        let acc_store = store.account_cache(opt.subaccount)?;
        let txs = self
            .get_wallet()?
            .list_tx(opt)?
            .iter()
            .map(|tx| {
                make_txlist_item(
                    tx,
                    &acc_store.all_txs,
                    &acc_store.unblinded,
                    &acc_store.paths,
                    self.network.id(),
                )
            })
            .collect();
        Ok(TxsResult(txs))
    }

    fn get_raw_transaction_details(&self, _txid: &str) -> Result<Value, Error> {
        Err(Error::Generic("implementme: ElectrumSession get_raw_transaction_details".into()))
    }

    fn get_balance(&self, opt: &GetBalanceOpt) -> Result<Balances, Error> {
        self.get_wallet()?.balance(opt)
    }

    fn set_transaction_memo(&self, txid: &str, memo: &str) -> Result<(), Error> {
        let txid = BETxid::from_hex(txid, self.network.id())?;
        if memo.len() > 1024 {
            return Err(Error::Generic("Too long memo (max 1024)".into()));
        }
        self.get_wallet()?.store.write()?.insert_memo(txid, memo)?;

        Ok(())
    }

    fn create_transaction(
        &mut self,
        tx_req: &mut CreateTransaction,
    ) -> Result<TransactionMeta, Error> {
        info!("electrum create_transaction {:#?}", tx_req);

        self.get_wallet()?.create_tx(tx_req)
    }

    fn sign_transaction(&self, create_tx: &TransactionMeta) -> Result<TransactionMeta, Error> {
        info!("electrum sign_transaction {:#?}", create_tx);
        self.get_wallet()?.sign(create_tx)
    }

    fn send_transaction(&mut self, tx: &TransactionMeta) -> Result<TransactionMeta, Error> {
        info!("electrum send_transaction {:#?}", tx);
        let client = self.url.build_client(self.proxy.as_deref())?;
        let tx_bytes = Vec::<u8>::from_hex(&tx.hex)?;
        let txid = client.transaction_broadcast_raw(&tx_bytes)?;
        if let Some(memo) = tx.create_transaction.as_ref().and_then(|o| o.memo.as_ref()) {
            self.get_wallet()?.store.write()?.insert_memo(txid.into(), memo)?;
        }
        Ok(tx.clone())
    }

    fn broadcast_transaction(&mut self, tx_hex: &str) -> Result<String, Error> {
        let transaction = BETransaction::from_hex(&tx_hex, self.network.id())?;

        info!("broadcast_transaction {:#?}", transaction.txid());
        let client = self.url.build_client(self.proxy.as_deref())?;
        let hex = Vec::<u8>::from_hex(tx_hex)?;
        let txid = client.transaction_broadcast_raw(&hex)?;
        Ok(format!("{}", txid))
    }

    /// The estimates are returned as an array of 25 elements. Each element is
    /// an integer representing the fee estimate expressed as satoshi per 1000
    /// bytes. The first element is the minimum relay fee as returned by the
    /// network, while the remaining elements are the current estimates to use
    /// for a transaction to confirm from 1 to 24 blocks.
    fn get_fee_estimates(&mut self) -> Result<Vec<FeeEstimate>, Error> {
        let min_fee = match self.network.id() {
            NetworkId::Bitcoin(_) => 1000,
            NetworkId::Elements(_) => 100,
        };
        let fee_estimates = try_get_fee_estimates(&self.url.build_client(self.proxy.as_deref())?)
            .unwrap_or_else(|_| vec![FeeEstimate(min_fee); 25]);
        self.get_wallet()?.store.write()?.cache.fee_estimates = fee_estimates.clone();
        Ok(fee_estimates)
        //TODO better implement default
    }

    fn get_mnemonic(&self) -> Result<Mnemonic, Error> {
        self.get_wallet().map(|wallet| wallet.get_mnemonic().clone())
    }

    fn get_settings(&self) -> Result<Settings, Error> {
        Ok(self.get_wallet()?.get_settings()?)
    }

    fn change_settings(&mut self, value: &Value) -> Result<(), Error> {
        let wallet = self.get_wallet()?;
        let mut settings = wallet.get_settings()?;
        settings.update(value);
        self.get_wallet()?.change_settings(&settings)?;
        notify_settings(self.notify.clone(), &settings);
        Ok(())
    }

    fn get_available_currencies(&self) -> Result<Value, Error> {
        Ok(json!({ "all": [ "USD" ], "per_exchange": { "BITFINEX": [ "USD" ] } }))
        // TODO implement
    }

    fn refresh_assets(&self, details: &RefreshAssets) -> Result<Value, Error> {
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
            let (tx_assets, rx_assets) = mpsc::channel();
            if details.assets {
                let registry_policy = self
                    .network
                    .policy_asset
                    .clone()
                    .ok_or_else(|| Error::Generic("policy assets not available".into()))?;
                let last_modified =
                    self.get_wallet()?.store.read()?.cache.assets_last_modified.clone();
                let base_url = self.network.registry_base_url()?;
                let agent = self.build_request_agent()?;
                thread::spawn(move || {
                    match call_assets(agent, base_url, registry_policy, last_modified) {
                        Ok(p) => tx_assets.send(Some(p)),
                        Err(_) => tx_assets.send(None),
                    }
                });
            }

            let (tx_icons, rx_icons) = mpsc::channel();
            if details.icons {
                let last_modified =
                    self.get_wallet()?.store.read()?.cache.icons_last_modified.clone();
                let base_url = self.network.registry_base_url()?;
                let agent = self.build_request_agent()?;
                thread::spawn(move || match call_icons(agent, base_url, last_modified) {
                    Ok(p) => tx_icons.send(Some(p)),
                    Err(_) => tx_icons.send(None),
                });
            }

            if details.assets {
                if let Ok(Some(assets_recv)) = rx_assets.recv() {
                    assets = assets_recv.0;
                    assets_last_modified = assets_recv.1;
                }
            }
            if details.icons {
                if let Ok(Some(icons_recv)) = rx_icons.recv() {
                    icons = icons_recv.0;
                    icons_last_modified = icons_recv.1;
                }
            }

            let wallet = self.get_wallet()?;
            let mut store_write = wallet.store.write()?;
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
                    .get_wallet()?
                    .store
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
                    .get_wallet()?
                    .store
                    .read()?
                    .read_asset_icons()?
                    .unwrap_or_else(|| get_registry_sentinel()),
            };
            map.insert("icons".to_string(), icons_not_null);
        }

        Ok(Value::Object(map))
    }

    fn block_status(&self) -> Result<(u32, BEBlockHash), Error> {
        let tip = self.get_wallet()?.get_tip()?;
        info!("tip={:?}", tip);
        Ok(tip)
    }

    fn tx_status(&self) -> Result<u64, Error> {
        let mut opt = GetTransactionsOpt::default();
        opt.count = 100;
        let mut hasher = DefaultHasher::new();
        let wallet = self.get_wallet()?;
        for account in wallet.iter_accounts_sorted() {
            let txs = account.list_tx(&opt)?;
            for tx in txs.iter() {
                std::hash::Hash::hash(&tx.txid, &mut hasher);
            }
        }
        let status = hasher.finish();
        info!("txs status={}", status);
        Ok(status)
    }

    fn get_unspent_outputs(&self, opt: &GetUnspentOpt) -> Result<GetUnspentOutputs, Error> {
        let mut unspent_outputs: HashMap<String, Vec<UnspentOutput>> = HashMap::new();
        for (outpoint, info) in self.get_wallet()?.utxos(opt)?.iter() {
            let cur = UnspentOutput::new(outpoint, info);
            (*unspent_outputs.entry(info.asset.clone()).or_insert(vec![])).push(cur);
        }

        Ok(GetUnspentOutputs(unspent_outputs))
    }
}

impl ElectrumSession {
    pub fn export_cache(&self) -> Result<RawCache, Error> {
        self.get_wallet()?.store.read()?.export_cache()
    }
}

fn call_icons(
    agent: ureq::Agent,
    base_url: String,
    last_modified: String,
) -> Result<(Value, String), Error> {
    // TODO gzip encoding
    let url = format!("{}/{}", base_url, "icons.json");
    info!("START call_icons {}", &url);
    let icons_response = agent
        .get(&url)
        .timeout_connect(15_000)
        .timeout_read(15_000)
        .set("If-Modified-Since", &last_modified)
        .call();
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
    // TODO add gzip encoding
    let url = format!("{}/{}", base_url, "index.json");
    info!("START call_assets {}", &url);
    let assets_response = agent
        .get(&url)
        .timeout_connect(15_000)
        .timeout_read(15_000)
        .set("If-Modified-Since", &last_modified)
        .call();
    let status = assets_response.status();
    info!("call_assets {} returns {}", url, status);
    let last_modified = assets_response.header("Last-Modified").unwrap_or_default().to_string();
    let mut assets = assets_response.into_json()?;
    assets[registry_policy] =
        json!({"asset_id": &registry_policy, "name": "Liquid Bitcoin", "ticker": "L-BTC"});
    info!("END call_assets {} {}", &url, status);
    Ok((assets, last_modified))
}

impl Tipper {
    pub fn tip(&self, client: &Client) -> Result<u32, Error> {
        let header = client.block_headers_subscribe_raw()?;
        let height = header.height as u32;
        let tip_height = self.store.read()?.cache.tip.0;
        if height != tip_height {
            let hash = BEBlockHeader::deserialize(&header.header, self.network.id())?.block_hash();
            info!("saving in store new tip {:?}", (height, hash));
            self.store.write()?.cache.tip = (height, hash);
        }
        Ok(height)
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
                    txs_verified.insert(txid, SPVVerifyResult::Verified);
                } else {
                    warn!("proof for {} not verified!", txid);
                    txs_verified.insert(txid, SPVVerifyResult::NotVerified);
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
    pub fn sync(&self, client: &Client) -> Result<HashSet<u32>, Error> {
        debug!("start sync");
        let start = Instant::now();

        let wallet = self.wallet.read().unwrap();
        let mut updated_accounts = HashSet::new();

        for account in wallet.iter_accounts() {
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

                updated_accounts.insert(account.num());

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

        Ok(updated_accounts)
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

fn wait_or_close(r: &Receiver<()>, interval: u32) -> bool {
    for _ in 0..(interval * 2) {
        thread::sleep(Duration::from_millis(500));
        if r.try_recv().is_ok() {
            return true;
        }
    }
    false
}

// Return a sentinel value that the caller should interpret as "no cached data"
fn get_registry_sentinel() -> Value {
    json!({})
}
