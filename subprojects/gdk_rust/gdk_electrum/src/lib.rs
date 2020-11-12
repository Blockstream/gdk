mod store;

#[macro_use]
extern crate serde_json;

#[macro_use]
extern crate lazy_static;

use log::{debug, info, trace, warn};
use serde_json::Value;

pub mod error;
pub mod headers;
pub mod interface;
pub mod pin;

use crate::error::Error;
use crate::interface::{ElectrumUrl, WalletCtx};
use crate::store::*;

use bitcoin::hashes::{hex::FromHex, sha256, Hash};
use bitcoin::secp256k1::{self, Secp256k1, SecretKey};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{BlockHash, Script, Txid};

use electrum_client::GetHistoryRes;
use gdk_common::be::*;
use gdk_common::mnemonic::Mnemonic;
use gdk_common::model::*;
use gdk_common::network::Network;
use gdk_common::password::Password;
use gdk_common::session::Session;
use gdk_common::wally::{
    self, asset_blinding_key_from_seed, asset_blinding_key_to_ec_private_key, asset_unblind,
    MasterBlindingKey,
};

use elements::confidential::{self, Asset, Nonce};
use gdk_common::{ElementsNetwork, NetworkId};
use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crate::headers::bitcoin::HeadersChain;
use crate::headers::liquid::Verifier;
use crate::headers::ChainOrVerifier;
use crate::pin::PinManager;
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

type Aes256Cbc = Cbc<Aes256, Pkcs7>;

pub struct Syncer {
    pub store: Store,
    pub master_blinding: Option<MasterBlindingKey>,
    pub network: Network,
}

pub struct Tipper {
    pub store: Store,
    pub network: Network,
}

pub struct Headers {
    pub store: Store,
    pub checker: ChainOrVerifier,
}

#[derive(Clone)]
pub struct NativeNotif(
    pub Option<(extern "C" fn(*const libc::c_void, *const GDKRUST_json), *const libc::c_void)>,
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
    pub network: Network,
    pub url: ElectrumUrl,
    pub wallet: Option<WalletCtx>,
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
        handler(self_context, GDKRUST_json::new(data));
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

fn notify_fee(notif: NativeNotif, fees: &[FeeEstimate]) {
    let data = json!({"fees":fees,"event":"fees"});
    notify(notif, data);
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
    determine_electrum_url(&network.electrum_url, network.tls, network.validate_domain)
}

impl ElectrumSession {
    pub fn new_session(network: Network, db_root: &str, url: ElectrumUrl) -> Result<Self, Error> {
        Ok(Self::create_session(network, db_root, url))
    }
}

impl ElectrumSession {
    pub fn create_session(network: Network, db_root: &str, url: ElectrumUrl) -> Self {
        Self {
            data_root: db_root.to_string(),
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

    pub fn get_wallet(&self) -> Result<&WalletCtx, Error> {
        self.wallet.as_ref().ok_or_else(|| Error::Generic("wallet not initialized".into()))
    }

    pub fn get_wallet_mut(&mut self) -> Result<&mut WalletCtx, Error> {
        self.wallet.as_mut().ok_or_else(|| Error::Generic("wallet not initialized".into()))
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

fn make_txlist_item(tx: &TransactionMeta) -> TxListItem {
    let type_ = tx.type_.clone();
    let len = tx.hex.len() / 2;
    let fee_rate = (tx.fee as f64 / len as f64) as u64;
    let addressees = tx
        .create_transaction
        .as_ref()
        .unwrap()
        .addressees
        .iter()
        .map(|e| e.address.clone())
        .collect();

    TxListItem {
        block_height: tx.height.unwrap_or_default(),
        created_at: tx.created_at.clone(),
        type_,
        memo: tx.create_transaction.as_ref().and_then(|c| c.memo.clone()).unwrap_or("".to_string()),
        txhash: tx.txid.clone(),
        transaction_size: len,
        transaction: tx.hex.clone(), // FIXME
        satoshi: tx.satoshi.clone(),
        rbf_optin: tx.rbf_optin, // TODO: TransactionMeta -> TxListItem rbf_optin
        cap_cpfp: false,         // TODO: TransactionMeta -> TxListItem cap_cpfp
        can_rbf: false,          // TODO: TransactionMeta -> TxListItem can_rbf
        has_payment_request: false, // TODO: TransactionMeta -> TxListItem has_payment_request
        server_signed: false,    // TODO: TransactionMeta -> TxListItem server_signed
        user_signed: tx.user_signed,
        spv_verified: tx.spv_verified.to_string(),
        instant: false,
        fee: tx.fee,
        fee_rate,
        addressees,              // notice the extra "e" -- its intentional
        inputs: vec![],          // tx.input.iter().map(format_gdk_input).collect(),
        outputs: vec![],         //tx.output.iter().map(format_gdk_output).collect(),
        transaction_vsize: len,  //TODO
        transaction_weight: len, //TODO
    }
}

impl Session<Error> for ElectrumSession {
    // type Value = ElectrumSession;

    fn destroy_session(&mut self) -> Result<(), Error> {
        self.wallet = None;
        Ok(())
    }

    fn poll_session(&self) -> Result<(), Error> {
        Err(Error::Generic("implementme: ElectrumSession poll_session".into()))
    }

    fn connect(&mut self, net_params: &Value) -> Result<(), Error> {
        info!("connect network:{:?} state:{:?}", self.network, self.state);

        if self.state == State::Disconnected {
            if self.data_root == "" {
                self.data_root = net_params["state_dir"]
                    .as_str()
                    .map(|x| x.to_string())
                    .unwrap_or_else(|| "".into());
                info!("setting db_root to {:?}", self.data_root);
            }

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
        info!("disconnect STATUS block:{:?} tx:{}", self.block_status()?, self.tx_status()?);
        if self.state != State::Disconnected {
            self.closer.close()?;
            self.state = State::Disconnected;
        }
        Ok(())
    }

    fn login_with_pin(
        &mut self,
        pin: String,
        details: PinGetDetails,
    ) -> Result<Vec<Notification>, Error> {
        let manager = PinManager::new()?;
        let client_key = SecretKey::from_slice(&hex::decode(&details.pin_identifier)?)?;
        let server_key = manager.get_pin(pin.as_bytes(), &client_key)?;
        let iv = hex::decode(&details.salt)?;
        let decipher = Aes256Cbc::new_var(&server_key[..], &iv).unwrap();
        let mnemonic = decipher.decrypt_vec(&hex::decode(&details.encrypted_data)?)?;
        let mnemonic = std::str::from_utf8(&mnemonic).unwrap().to_string();
        let mnemonic = Mnemonic::from(mnemonic);

        self.login(&mnemonic, None)
    }

    fn login(
        &mut self,
        mnemonic: &Mnemonic,
        password: Option<Password>,
    ) -> Result<Vec<Notification>, Error> {
        info!("login {:?} {:?}", self.network, self.state);

        if self.state == State::Logged {
            return Ok(vec![]);
        }

        // TODO: passphrase?

        let mnem_str = mnemonic.clone().get_mnemonic_str();
        let seed = wally::bip39_mnemonic_to_seed(
            &mnem_str,
            &password.map(|p| p.get_password_str()).unwrap_or_default(),
        )
        .ok_or(Error::InvalidMnemonic)?;
        let secp = Secp256k1::new();
        let xprv =
            ExtendedPrivKey::new_master(bitcoin::network::constants::Network::Testnet, &seed)?;

        // BIP44: m / purpose' / coin_type' / account' / change / address_index
        // coin_type = 0 bitcoin, 1 testnet, 1776 liquid bitcoin as defined in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
        // slip44 suggest 1 for every testnet, so we are using it also for regtest
        let coin_type: u32 = match self.network.id() {
            NetworkId::Bitcoin(bitcoin_network) => match bitcoin_network {
                bitcoin::Network::Bitcoin => 0,
                bitcoin::Network::Testnet => 1,
                bitcoin::Network::Regtest => 1,
            },
            NetworkId::Elements(elements_network) => match elements_network {
                ElementsNetwork::Liquid => 1776,
                ElementsNetwork::ElementsRegtest => 1,
            },
        };
        // since we use P2WPKH-nested-in-P2SH it is 49 https://github.com/bitcoin/bips/blob/master/bip-0049.mediawiki
        let path_string = format!("m/49'/{}'/0'", coin_type);
        info!("Using derivation path {}/0|1/*", path_string);
        let path = DerivationPath::from_str(&path_string)?;
        let xprv = xprv.derive_priv(&secp, &path)?;
        let xpub = ExtendedPubKey::from_private(&secp, &xprv);

        let wallet_desc = format!("{}{:?}", xpub, self.network);
        let wallet_id = hex::encode(sha256::Hash::hash(wallet_desc.as_bytes()));
        let sync_interval = self.network.sync_interval.unwrap_or(7);

        let master_blinding = if self.network.liquid {
            Some(asset_blinding_key_from_seed(&seed))
        } else {
            None
        };

        let mut path: PathBuf = self.data_root.as_str().into();
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
        }
        path.push(wallet_id);
        info!("Store root path: {:?}", path);
        let store = match self.get_wallet() {
            Ok(wallet) => wallet.store.clone(),
            Err(_) => Arc::new(RwLock::new(StoreMeta::new(
                &path,
                xpub,
                master_blinding.clone(),
                self.network.id(),
            )?)),
        };

        let estimates = store.read()?.fee_estimates().clone();
        notify_fee(self.notify.clone(), &estimates);
        let mut tip_height = store.read()?.cache.tip.0;
        notify_block(self.notify.clone(), tip_height);

        info!("building client");
        if let Ok(fee_client) = self.url.build_client() {
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

            let mut headers = Headers {
                store: store.clone(),
                checker,
            };

            let headers_url = self.url.clone();
            let (close_headers, r) = channel();
            self.closer.senders.push(close_headers);
            let mut chunk_size = DIFFCHANGE_INTERVAL as usize;
            let headers_handle = thread::spawn(move || {
                info!("starting headers thread");

                'outer: loop {
                    if wait_or_close(&r, sync_interval) {
                        info!("closing headers thread");
                        break;
                    }

                    if let Ok(client) = headers_url.build_client() {
                        loop {
                            if r.try_recv().is_ok() {
                                info!("closing headers thread");
                                break 'outer;
                            }
                            match headers.ask(chunk_size, &client) {
                                Ok(headers_found) => {
                                    if headers_found == 0 {
                                        chunk_size = 1
                                    } else {
                                        info!("headers found: {}", headers_found);
                                    }
                                }
                                Err(Error::InvalidHeaders) => {
                                    // this should handle reorgs and also broke IO writes update
                                    headers.store.write().unwrap().cache.txs_verif.clear();
                                    if let Err(e) = headers.remove(144) {
                                        warn!("failed removing headers: {:?}", e);
                                        break;
                                    }
                                    // XXX clear affected blocks/txs more surgically?
                                }
                                Err(e) => {
                                    // usual error is because I reached the tip, trying asking half
                                    //TODO this is due to an esplora electrs bug, according to spec it should
                                    // just return available headers, remove when fix is deployed and change previous
                                    // break condition to headers_found < chunk_size
                                    info!("error while asking headers {}", e);
                                    if chunk_size > 1 {
                                        chunk_size /= 2
                                    } else {
                                        break;
                                    }
                                }
                            }
                            if chunk_size == 1 {
                                break;
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
                    }
                }
            });
            self.closer.handles.push(headers_handle);
        }

        let syncer = Syncer {
            store: store.clone(),
            master_blinding: master_blinding.clone(),
            network: self.network.clone(),
        };

        let tipper = Tipper {
            store: store.clone(),
            network: self.network.clone(),
        };

        if self.wallet.is_none() {
            let wallet = WalletCtx::new(
                store,
                mnemonic.clone(),
                self.network.clone(),
                xprv,
                xpub,
                master_blinding,
            )?;

            self.wallet = Some(wallet);
        }
        info!("login STATUS block:{:?} tx:{}", self.block_status()?, self.tx_status()?);

        let notify_blocks = self.notify.clone();

        let (close_tipper, r) = channel();
        self.closer.senders.push(close_tipper);
        let tipper_url = self.url.clone();
        let tipper_handle = thread::spawn(move || {
            info!("starting tipper thread");
            loop {
                if let Ok(client) = tipper_url.build_client() {
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
        let syncer_handle = thread::spawn(move || {
            info!("starting syncer thread");
            loop {
                match syncer_url.build_client() {
                    Ok(client) => match syncer.sync(&client) {
                        Ok(new_txs) => {
                            if new_txs {
                                info!("there are new transactions");
                                let mockup_json = json!({"event":"transaction","transaction":{"subaccounts":[0]}});
                                notify(notify_txs.clone(), mockup_json);
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
        Ok(vec![])
    }

    fn get_receive_address(&self, addr_details: &Value) -> Result<AddressPointer, Error> {
        debug!("get_receive_address {:?}", addr_details);
        let w = self.get_wallet()?;
        let a = w.get_address()?;
        debug!("get_address {:?}", a);
        Ok(a)
    }

    fn set_pin(&self, details: &PinSetDetails) -> Result<PinGetDetails, Error> {
        let manager = PinManager::new()?;
        let client_key = SecretKey::new(&mut thread_rng());
        let server_key = manager.set_pin(details.pin.as_bytes(), &client_key)?;
        let iv = thread_rng().gen::<[u8; 16]>();
        let cipher = Aes256Cbc::new_var(&server_key[..], &iv).unwrap();
        let encrypted = cipher.encrypt_vec(details.mnemonic.as_bytes());

        let result = PinGetDetails {
            salt: hex::encode(&iv),
            encrypted_data: hex::encode(&encrypted),
            pin_identifier: hex::encode(&client_key[..]),
        };
        Ok(result)
    }

    fn get_subaccounts(&self) -> Result<Vec<Subaccount>, Error> {
        // TODO configurable confs?
        let index = 0;
        let confs = 0;
        let subaccount_fake = self.get_subaccount(index, confs)?;

        Ok(vec![subaccount_fake])
    }

    fn get_subaccount(&self, index: u32, num_confs: u32) -> Result<Subaccount, Error> {
        if index != 0 {
            return Err(Error::InvalidSubaccount(index));
        }
        let balance = self.get_balance(num_confs, Some(index))?;
        let mut opt = GetTransactionsOpt::default();
        opt.count = 1;
        let txs = self.get_transactions(&opt)?;

        let subaccounts_fake = Subaccount {
            type_: "electrum".into(),
            name: "Single sig wallet".into(),
            has_transactions: !txs.0.is_empty(),
            satoshi: balance,
        };

        Ok(subaccounts_fake)
    }

    fn get_transactions(&self, opt: &GetTransactionsOpt) -> Result<TxsResult, Error> {
        let txs = self.get_wallet()?.list_tx(opt)?.iter().map(make_txlist_item).collect();

        Ok(TxsResult(txs))
    }

    fn get_transaction_details(&self, _txid: &str) -> Result<Value, Error> {
        Err(Error::Generic("implementme: ElectrumSession get_transaction_details".into()))
    }

    fn get_balance(&self, _num_confs: u32, _subaccount: Option<u32>) -> Result<Balances, Error> {
        self.get_wallet()?.balance()
    }

    fn set_transaction_memo(&self, txid: &str, memo: &str, memo_type: u32) -> Result<(), Error> {
        if memo_type != 0 {
            // GA_MEMO_USER == 0
            return Err(Error::Generic("Only memo_type GA_MEMO_USER(0) is supported".into()));
        }
        let txid = Txid::from_hex(txid)?;
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

    fn send_transaction(&mut self, tx: &TransactionMeta) -> Result<String, Error> {
        info!("electrum send_transaction {:#?}", tx);
        let client = self.url.build_client()?;
        let tx_bytes = hex::decode(&tx.hex)?;
        let txid = client.transaction_broadcast_raw(&tx_bytes)?;
        Ok(format!("{}", txid))
    }

    fn broadcast_transaction(&mut self, tx_hex: &str) -> Result<String, Error> {
        let transaction = BETransaction::from_hex(&tx_hex, self.network.id())?;

        info!("broadcast_transaction {:#?}", transaction.txid());
        let client = self.url.build_client()?;
        let hex = hex::decode(tx_hex)?;
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
        let fee_estimates = try_get_fee_estimates(&self.url.build_client()?)
            .unwrap_or_else(|_| vec![FeeEstimate(min_fee); 25]);
        self.get_wallet()?.store.write()?.cache.fee_estimates = fee_estimates.clone();
        Ok(fee_estimates)
        //TODO better implement default
    }

    fn get_mnemonic(&self) -> Result<&Mnemonic, Error> {
        self.get_wallet().map(|wallet| wallet.get_mnemonic())
    }

    fn get_settings(&self) -> Result<Settings, Error> {
        Ok(self.get_wallet()?.get_settings()?)
    }

    fn change_settings(&mut self, settings: &Settings) -> Result<(), Error> {
        self.get_wallet()?.change_settings(settings)?;
        notify_settings(self.notify.clone(), settings);
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
                thread::spawn(move || {
                    match call_assets(base_url, registry_policy, last_modified) {
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
                thread::spawn(move || match call_icons(base_url, last_modified) {
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

            let mut store_write = self.get_wallet()?.store.write()?;
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
                    .ok_or_else(|| Error::Generic("assets registry not available".into()))?,
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
                    .ok_or_else(|| Error::Generic("icon registry not available".into()))?,
            };
            map.insert("icons".to_string(), icons_not_null);
        }

        Ok(Value::Object(map))
    }

    fn block_status(&self) -> Result<(u32, BlockHash), Error> {
        let tip = self.get_wallet()?.get_tip()?;
        info!("tip={:?}", tip);
        Ok(tip)
    }

    fn tx_status(&self) -> Result<u64, Error> {
        let mut opt = GetTransactionsOpt::default();
        opt.count = 100;
        let txs = self.get_wallet()?.list_tx(&opt)?;
        let mut hasher = DefaultHasher::new();
        for tx in txs.iter() {
            std::hash::Hash::hash(&tx.txid, &mut hasher);
        }
        let status = hasher.finish();
        info!("txs.len={} status={}", txs.len(), status);
        Ok(status)
    }

    fn get_unspent_outputs(&self, _details: &Value) -> Result<GetUnspentOutputs, Error> {
        let mut unspent_outputs: HashMap<String, Vec<UnspentOutput>> = HashMap::new();

        for (outpoint, info) in self.get_wallet()?.utxos()?.iter() {
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

fn call_icons(base_url: String, last_modified: String) -> Result<(Value, String), Error> {
    // TODO gzip encoding
    let url = format!("{}/{}", base_url, "icons.json");
    info!("START call_icons {}", &url);
    let icons_response = ureq::get(&url)
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
    base_url: String,
    registry_policy: String,
    last_modified: String,
) -> Result<(Value, String), Error> {
    // TODO add gzip encoding
    let url = format!("{}/{}", base_url, "index.json");
    info!("START call_assets {}", &url);
    let assets_response = ureq::get(&url)
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
        let store_read = self.store.read()?;

        // find unconfirmed transactions that were previously confirmed and had
        // their SPV validation cached, to be cleared below
        let remove_proof: Vec<Txid> = store_read
            .cache
            .heights
            .iter()
            .filter(|(t, h)| h.is_none() && store_read.cache.txs_verif.get(*t).is_some())
            .map(|(t, _)| t.clone())
            .collect();

        // find confirmed transactions with no SPV validation cache
        let needs_proof: Vec<(Txid, u32)> = store_read
            .cache
            .heights
            .iter()
            .filter_map(|(t, h_opt)| Some((t, (*h_opt)?)))
            .filter(|(t, _)| store_read.cache.txs_verif.get(*t).is_none())
            .map(|(t, h)| (t.clone(), h))
            .collect();
        drop(store_read);

        let mut txs_verified = HashMap::new();
        for (txid, height) in needs_proof {
            let verified = match client.transaction_get_merkle(&txid, height as usize) {
                Ok(proof) => match &self.checker {
                    ChainOrVerifier::Chain(chain) => {
                        chain.verify_tx_proof(&txid, height, proof).is_ok()
                    }
                    ChainOrVerifier::Verifier(verifier) => {
                        if let Some(BEBlockHeader::Elements(header)) =
                            self.store.read()?.cache.headers.get(&height)
                        {
                            verifier.verify_tx_proof(&txid, proof, &header).is_ok()
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
        let proofs_done = txs_verified.len();
        let mut store_write = self.store.write()?;
        store_write.cache.txs_verif.extend(txs_verified);
        for txid in remove_proof {
            store_write.cache.txs_verif.remove(&txid);
        }
        Ok(proofs_done)
    }

    pub fn remove(&mut self, headers: u32) -> Result<(), Error> {
        if let ChainOrVerifier::Chain(chain) = &mut self.checker {
            chain.remove(headers)?;
        }
        Ok(())
    }
}

#[derive(Default)]
struct DownloadTxResult {
    txs: Vec<(Txid, BETransaction)>,
    unblinds: Vec<(elements::OutPoint, Unblinded)>,
}

impl Syncer {
    pub fn sync(&self, client: &Client) -> Result<bool, Error> {
        debug!("start sync");
        let start = Instant::now();

        let mut history_txs_id = HashSet::new();
        let mut heights_set = HashSet::new();
        let mut txid_height = HashMap::new();
        let mut scripts = HashMap::new();

        let mut last_used = Indexes::default();
        let mut wallet_chains = vec![0, 1];
        wallet_chains.shuffle(&mut thread_rng());
        for i in wallet_chains {
            let mut batch_count = 0;
            loop {
                let batch = self.store.read()?.get_script_batch(i, batch_count)?;
                let result: Vec<Vec<GetHistoryRes>> =
                    client.batch_script_get_history(batch.value.iter().map(|e| &e.0))?;
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

                for el in flattened {
                    // el.height = -1 means unconfirmed with unconfirmed parents
                    // el.height =  0 means unconfirmed with confirmed parents
                    // but we threat those tx the same
                    let height = el.height.max(0);
                    heights_set.insert(height as u32);
                    if height == 0 {
                        txid_height.insert(el.tx_hash, None);
                    } else {
                        txid_height.insert(el.tx_hash, Some(height as u32));
                    }

                    history_txs_id.insert(el.tx_hash);
                }

                batch_count += 1;
            }
        }

        let new_txs = self.download_txs(&history_txs_id, &scripts, &client)?;
        let headers = self.download_headers(&heights_set, &client)?;

        let store_read = self.store.read()?;
        let store_indexes = store_read.cache.indexes.clone();
        let txs_heights_changed = txid_height
            .iter()
            .any(|(txid, height)| store_read.cache.heights.get(txid) != Some(height));
        drop(store_read);

        let changed = if !new_txs.txs.is_empty()
            || !headers.is_empty()
            || store_indexes != last_used
            || !scripts.is_empty()
            || txs_heights_changed
        {
            info!(
                "There are changes in the store new_txs:{:?} headers:{:?} txid_height:{:?}",
                new_txs.txs.iter().map(|tx| tx.0).collect::<Vec<Txid>>(),
                headers,
                txid_height
            );
            let mut store_write = self.store.write()?;
            store_write.cache.indexes = last_used;
            store_write.cache.all_txs.extend(new_txs.txs.into_iter());
            store_write.cache.unblinded.extend(new_txs.unblinds);
            store_write.cache.headers.extend(headers);

            // height map is used for the live list of transactions, since due to reorg or rbf tx
            // could disappear from the list, we clear the list and keep only the last values returned by the server
            store_write.cache.heights.clear();
            store_write.cache.heights.extend(txid_height.into_iter());

            store_write.cache.scripts.extend(scripts.clone().into_iter().map(|(a, b)| (b, a)));
            store_write.cache.paths.extend(scripts.into_iter());
            store_write.flush()?;
            true
        } else {
            false
        };
        trace!("changes:{} elapsed {}", changed, start.elapsed().as_millis());

        Ok(changed)
    }

    fn download_headers(
        &self,
        heights_set: &HashSet<u32>,
        client: &Client,
    ) -> Result<Vec<(u32, BEBlockHeader)>, Error> {
        let mut result = vec![];
        let mut heights_in_db: HashSet<u32> =
            self.store.read()?.cache.heights.iter().filter_map(|(_, h)| *h).collect();
        heights_in_db.insert(0);
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
        history_txs_id: &HashSet<Txid>,
        scripts: &HashMap<Script, DerivationPath>,
        client: &Client,
    ) -> Result<DownloadTxResult, Error> {
        let mut txs = vec![];
        let mut unblinds = vec![];

        let mut txs_in_db = self.store.read()?.cache.all_txs.keys().cloned().collect();
        let txs_to_download: Vec<&Txid> = history_txs_id.difference(&txs_in_db).collect();
        if !txs_to_download.is_empty() {
            let txs_bytes_downloaded = client.batch_transaction_get_raw(txs_to_download)?;
            let mut txs_downloaded: Vec<BETransaction> = vec![];
            for vec in txs_bytes_downloaded {
                let tx = BETransaction::deserialize(&vec, self.network.id())?;
                txs_downloaded.push(tx);
            }
            info!("txs_downloaded {:?}", txs_downloaded.len());
            let mut previous_txs_to_download = HashSet::new();
            for mut tx in txs_downloaded.into_iter() {
                let txid = tx.txid();
                txs_in_db.insert(txid);

                if let BETransaction::Elements(tx) = &tx {
                    info!("compute OutPoint Unblinded");
                    for (i, output) in tx.output.iter().enumerate() {
                        // could be the searched script it's not yet in the store, because created in the current run, thus it's searched also in the `scripts`
                        if self.store.read()?.cache.paths.contains_key(&output.script_pubkey)
                            || scripts.contains_key(&output.script_pubkey)
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
                tx.strip_witness();
                txs.push((txid, tx));
            }

            let txs_to_download: Vec<&Txid> =
                previous_txs_to_download.difference(&txs_in_db).collect();
            if !txs_to_download.is_empty() {
                let txs_bytes_downloaded = client.batch_transaction_get_raw(txs_to_download)?;
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
    ) -> Result<Unblinded, Error> {
        match (output.asset, output.value, output.nonce) {
            (
                Asset::Confidential(_, _),
                confidential::Value::Confidential(_, _),
                Nonce::Confidential(_, _),
            ) => {
                let master_blinding = self.master_blinding.as_ref().unwrap();

                let script = output.script_pubkey.clone();
                let blinding_key = asset_blinding_key_to_ec_private_key(master_blinding, &script);
                let rangeproof = output.witness.rangeproof.clone();
                let value_commitment = elements::encode::serialize(&output.value);
                let asset_commitment = elements::encode::serialize(&output.asset);
                let nonce_commitment = elements::encode::serialize(&output.nonce);
                info!(
                    "commitments len {} {} {}",
                    value_commitment.len(),
                    asset_commitment.len(),
                    nonce_commitment.len()
                );
                let sender_pk = secp256k1::PublicKey::from_slice(&nonce_commitment).unwrap();

                let (asset, abf, vbf, value) = asset_unblind(
                    sender_pk,
                    blinding_key,
                    rangeproof,
                    value_commitment,
                    script,
                    asset_commitment,
                )?;

                info!(
                    "Unblinded outpoint:{} asset:{} value:{}",
                    outpoint,
                    hex::encode(&asset),
                    value
                );

                let unblinded = Unblinded {
                    asset,
                    value,
                    abf,
                    vbf,
                };
                Ok(unblinded)
            }
            _ => Err(Error::Generic("received unconfidential or null asset/value/nonce".into())),
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
