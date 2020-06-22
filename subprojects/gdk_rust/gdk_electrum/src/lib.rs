#[macro_use]
extern crate serde_json;

use log::{debug, info, trace, warn};
use serde_json::Value;

pub mod db;
pub mod error;
pub mod headers;
pub mod interface;

use crate::db::{Forest, Index, BATCH_SIZE, DB_VERSION};
use crate::error::Error;
use crate::interface::{ElectrumUrl, WalletCtx};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::Txid;
pub use electrum_client::client::{ElectrumPlaintextStream, ElectrumSslStream};
use sled::Batch;

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
use std::io::{Read, Write};
use std::path::PathBuf;
use std::str::FromStr;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::thread;
use std::time::{Duration, Instant};

use crate::headers::bitcoin::HeadersChain;
use crate::headers::liquid::Verifier;
use crate::headers::ChainOrVerifier;
use bitcoin::blockdata::constants::DIFFCHANGE_INTERVAL;
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;

pub enum SyncerKind {
    Plain(Syncer<ElectrumPlaintextStream>, String),
    Tls(Syncer<ElectrumSslStream>, String, bool),
}

pub enum TipperKind {
    Plain(Tipper<ElectrumPlaintextStream>, String),
    Tls(Tipper<ElectrumSslStream>, String, bool),
}

pub enum HeadersKind {
    Plain(Headers<ElectrumPlaintextStream>, String),
    Tls(Headers<ElectrumSslStream>, String, bool),
}

impl TipperKind {
    pub fn tip(&mut self) -> Result<usize, Error> {
        match self {
            TipperKind::Plain(s, _) => s.tip(),
            TipperKind::Tls(s, _, _) => s.tip(),
        }
    }
}

impl SyncerKind {
    pub fn sync(&mut self) -> Result<bool, Error> {
        match self {
            SyncerKind::Plain(s, _) => s.sync(),
            SyncerKind::Tls(s, _, _) => s.sync(),
        }
    }
}

impl HeadersKind {
    pub fn ask(&mut self, chunk_size: usize) -> Result<usize, Error> {
        match self {
            HeadersKind::Plain(s, _) => s.ask(chunk_size),
            HeadersKind::Tls(s, _, _) => s.ask(chunk_size),
        }
    }
    pub fn get_proofs(&mut self) -> Result<usize, Error> {
        match self {
            HeadersKind::Plain(s, _) => s.get_proofs(),
            HeadersKind::Tls(s, _, _) => s.get_proofs(),
        }
    }
    pub fn remove(&mut self, headers: u32) -> Result<(), Error> {
        match self {
            HeadersKind::Plain(s, _) => s.remove(headers),
            HeadersKind::Tls(s, _, _) => s.remove(headers),
        }
    }
}

pub enum ClientWrap {
    Plain(electrum_client::Client<ElectrumPlaintextStream>),
    Tls(electrum_client::Client<ElectrumSslStream>),
}

impl ClientWrap {
    pub fn new(url: ElectrumUrl) -> Result<Self, Error> {
        match url {
            ElectrumUrl::Tls(url, validate) => {
                let client = electrum_client::Client::new_ssl(url.as_str(), validate)?;
                Ok(ClientWrap::Tls(client))
            }
            ElectrumUrl::Plaintext(url) => {
                let client = electrum_client::Client::new(&url)?;
                Ok(ClientWrap::Plain(client))
            }
        }
    }

    pub fn batch_estimate_fee<I>(&mut self, numbers: I) -> Result<Vec<f64>, Error>
    where
        I: IntoIterator<Item = usize>,
    {
        Ok(match self {
            ClientWrap::Plain(client) => client.batch_estimate_fee(numbers)?,
            ClientWrap::Tls(client) => client.batch_estimate_fee(numbers)?,
        })
    }

    pub fn relay_fee(&mut self) -> Result<f64, Error> {
        Ok(match self {
            ClientWrap::Plain(client) => client.relay_fee()?,
            ClientWrap::Tls(client) => client.relay_fee()?,
        })
    }

    pub fn transaction_broadcast_raw(&mut self, raw_tx: &[u8]) -> Result<Txid, Error> {
        Ok(match self {
            ClientWrap::Plain(client) => client.transaction_broadcast_raw(raw_tx)?,
            ClientWrap::Tls(client) => client.transaction_broadcast_raw(raw_tx)?,
        })
    }
}

pub struct Syncer<S: Read + Write> {
    pub db: Forest,
    pub client: electrum_client::Client<S>,
    pub master_blinding: Option<MasterBlindingKey>,
    pub network: Network,
}

pub struct Tipper<S: Read + Write> {
    pub db: Forest,
    pub client: electrum_client::Client<S>,
    pub network: Network,
}

pub struct Headers<S: Read + Write> {
    pub db: Forest,
    pub client: electrum_client::Client<S>,
    pub checker: ChainOrVerifier,
}

impl<S: Read + Write> Tipper<S> {
    pub fn new(
        db: Forest,
        client: electrum_client::Client<S>,
        network: Network,
    ) -> Result<Self, Error> {
        Ok(Tipper {
            db,
            client,
            network,
        })
    }
}

impl<S: Read + Write> Syncer<S> {
    pub fn new(
        db: Forest,
        client: electrum_client::Client<S>,
        master_blinding: Option<MasterBlindingKey>,
        network: Network,
    ) -> Self {
        Syncer {
            db,
            client,
            master_blinding,
            network,
        }
    }
}

impl<S: Read + Write> Headers<S> {
    pub fn new(
        db: Forest,
        checker: ChainOrVerifier,
        client: electrum_client::Client<S>,
    ) -> Result<Self, Error> {
        Ok(Headers {
            db,
            checker,
            client,
        })
    }
}

#[derive(Clone)]
pub struct NativeNotif(
    pub Option<(extern "C" fn(*const libc::c_void, *const GDKRUST_json), *const libc::c_void)>,
);
unsafe impl Send for NativeNotif {}

pub struct Closer {
    pub senders: Vec<Sender<()>>,
}

impl Closer {
    pub fn close(&mut self) -> Result<(), Error> {
        while let Some(sender) = self.senders.pop() {
            sender.send(())?;
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

fn notify_block(notif: NativeNotif, height: usize) {
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
    determine_electrum_url(&network.url, network.tls, network.validate_domain)
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
            },
        }
    }

    pub fn get_wallet(&self) -> Result<&WalletCtx, Error> {
        self.wallet.as_ref().ok_or_else(|| Error::Generic("wallet not initialized".into()))
    }

    pub fn get_wallet_mut(&mut self) -> Result<&mut WalletCtx, Error> {
        self.wallet.as_mut().ok_or_else(|| Error::Generic("wallet not initialized".into()))
    }

    fn try_get_fee_estimates(&mut self) -> Result<Vec<FeeEstimate>, Error> {
        let mut client = ClientWrap::new(self.url.clone())?;
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
        memo: "".into(), // TODO: TransactionMeta -> TxListItem memo
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
        spv_verified: tx.spv_verified,
        instant: false,
        fee: tx.fee,
        fee_rate,
        addresses: vec![],
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
        if self.data_root == "" {
            self.data_root = net_params["state_dir"]
                .as_str()
                .map(|x| x.to_string())
                .unwrap_or_else(|| "".into());
            info!("setting db_root to {:?}", self.data_root);
        }

        info!("connect {:?}", self.network);

        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        info!("disconnect");
        self.closer.close()?;
        Ok(())
    }

    fn login(
        &mut self,
        mnemonic: &Mnemonic,
        password: Option<Password>,
    ) -> Result<Vec<Notification>, Error> {
        info!("login {:#?}", self.network);

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

        let wallet_desc = format!("{}{:?}{}", xpub, self.network, DB_VERSION);
        let wallet_id = hex::encode(sha256::Hash::hash(wallet_desc.as_bytes()));
        let sync_interval = self.network.sync_interval.unwrap_or(7);

        let master_blinding = if self.network.liquid {
            Some(asset_blinding_key_from_seed(&seed))
        } else {
            None
        };

        let mut path: PathBuf = self.data_root.as_str().into();
        path.push(wallet_id);
        info!("opening sled db root path: {:?}", path);
        let db = Forest::new(&path, xpub, master_blinding.clone(), self.network.id())?;

        let mut wait_registry = false;
        let registry_thread = if self.network.liquid {
            let registry_policy = self.network.policy_asset.clone();
            let asset_icons = db.get_asset_icons()?;
            let asset_registry = db.get_asset_registry()?;
            wait_registry = asset_icons.is_none() || asset_registry.is_none();
            let db_for_registry = db.clone();
            Some(thread::spawn(move || {
                info!("start registry thread");
                // TODO add if_modified_since, gzip encoding
                let registry = ureq::get("https://assets.blockstream.info/index.json").call();
                let icons = ureq::get("https://assets.blockstream.info/icons.json").call();
                if registry.status() == 200 && icons.status() == 200 {
                    match (registry.into_json(), icons.into_json()) {
                        (Ok(mut registry), Ok(icons)) => {
                            info!("got registry and icons");
                            if let Some(policy) = registry_policy {
                                info!("inserting policy asset {}", &policy);
                                registry[policy] = json!({"asset_id": &policy, "name": "Liquid Bitcoin", "ticker": "L-BTC"});
                            }

                            db_for_registry.insert_asset_registry(&registry).unwrap();
                            db_for_registry.insert_asset_icons(&icons).unwrap();
                        }
                        _ => warn!("Registry or icons are not json"),
                    }
                } else {
                    warn!("Cannot download registry and icons");
                }
            }))
        } else {
            None
        };

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

        let mut headers_kind = match &self.url {
            ElectrumUrl::Tls(url, validate) => {
                let client = electrum_client::Client::new_ssl(url.as_str(), *validate)?;
                HeadersKind::Tls(
                    Headers::new(db.clone(), checker, client)?,
                    url.to_string(),
                    *validate,
                )
            }
            ElectrumUrl::Plaintext(url) => {
                let client = electrum_client::Client::new(&url)?;
                HeadersKind::Plain(Headers::new(db.clone(), checker, client)?, url.to_string())
            }
        };
        let (close_headers, r) = channel();
        self.closer.senders.push(close_headers);
        let mut chunk_size = DIFFCHANGE_INTERVAL as usize;
        thread::spawn(move || 'outer: loop {
            if wait_or_close(&r, sync_interval) {
                info!("closing headers thread");
                break;
            }

            loop {
                match headers_kind.ask(chunk_size) {
                    Ok(headers_found) => {
                        if headers_found == 0 {
                            chunk_size = 1
                        } else {
                            info!("headers found: {}", headers_found);
                        }
                    }
                    Err(Error::InvalidHeaders) => {
                        // this should handle reorgs and also broke IO writes update
                        if headers_kind.remove(144).is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("error while asking headers {}", e);
                        if chunk_size > 1 {
                            chunk_size /= 2
                        }
                    }
                };
                if r.try_recv().is_ok() {
                    info!("closing headers thread");
                    break 'outer;
                }
                if chunk_size == 1 {
                    break;
                }
            }

            match headers_kind.get_proofs() {
                Ok(found) => {
                    if found > 0 {
                        info!("found proof {}", found)
                    }
                }
                Err(e) => warn!("error in getting proofs {:?}", e),
            }
        });

        let mut syncer = match &self.url {
            ElectrumUrl::Tls(url, validate) => {
                let client = electrum_client::Client::new_ssl(url.as_str(), *validate)?;
                SyncerKind::Tls(
                    Syncer::new(db.clone(), client, master_blinding.clone(), self.network.clone()),
                    url.to_string(),
                    *validate,
                )
            }
            ElectrumUrl::Plaintext(url) => {
                let client = electrum_client::Client::new(&url)?;
                SyncerKind::Plain(
                    Syncer::new(db.clone(), client, master_blinding.clone(), self.network.clone()),
                    url.to_string(),
                )
            }
        };

        let mut tipper = match &self.url {
            ElectrumUrl::Tls(url, validate) => {
                let client = electrum_client::Client::new_ssl(url.as_str(), *validate)?;
                TipperKind::Tls(
                    Tipper::new(db.clone(), client, self.network.clone())?,
                    url.to_string(),
                    *validate,
                )
            }
            ElectrumUrl::Plaintext(url) => {
                let client = electrum_client::Client::new(&url)?;
                TipperKind::Plain(
                    Tipper::new(db.clone(), client, self.network.clone())?,
                    url.to_string(),
                )
            }
        };

        let wallet = WalletCtx::new(
            db,
            mnemonic.clone(),
            self.network.clone(),
            xprv,
            xpub,
            master_blinding,
        )?;

        self.wallet = Some(wallet);

        let notify_blocks = self.notify.clone();

        let mut last_tip = tipper.tip()?;
        info!("tip is {:?}", last_tip);
        notify_block(notify_blocks.clone(), last_tip);

        let (close_tipper, r) = channel();
        self.closer.senders.push(close_tipper);
        thread::spawn(move || loop {
            if wait_or_close(&r, sync_interval) {
                info!("closing tipper thread");
                break;
            }

            match tipper.tip() {
                Ok(current_tip) => {
                    if last_tip != current_tip {
                        last_tip = current_tip;
                        info!("tip is {:?}", last_tip);
                        notify_block(notify_blocks.clone(), last_tip);
                    }
                }
                Err(e) => {
                    warn!("exception in tipper {:?}", e);
                    match e {
                        Error::ClientError(electrum_client::types::Error::JSON(_)) => {
                            info!("tipper Client error, doing nothing")
                        }
                        _ => {
                            warn!("trying to recreate died tipper client, {:?}", e);
                            match &mut tipper {
                                TipperKind::Plain(tipper, url) => {
                                    if let Ok(client) = electrum_client::Client::new(url.as_str()) {
                                        info!("succesfully created new tipper client");
                                        tipper.client = client;
                                    }
                                }
                                TipperKind::Tls(tipper, url, validate) => {
                                    if let Ok(client) =
                                        electrum_client::Client::new_ssl(url.as_str(), *validate)
                                    {
                                        info!("succesfully created new tipper client");
                                        tipper.client = client;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let (close_syncer, r) = channel();
        self.closer.senders.push(close_syncer);
        let notify_txs = self.notify.clone();
        thread::spawn(move || loop {
            match syncer.sync() {
                Ok(new_txs) => {
                    if new_txs {
                        info!("there are new transactions");
                        let mockup_json =
                            json!({"event":"transaction","transaction":{"subaccounts":[0]}});
                        notify(notify_txs.clone(), mockup_json);
                    }
                }
                Err(e) => {
                    warn!("trying to recreate died syncer client, {:?}", e);
                    match &mut syncer {
                        SyncerKind::Plain(syncer, url) => {
                            if let Ok(client) = electrum_client::Client::new(url.as_str()) {
                                info!("succesfully created new syncer client");
                                syncer.client = client
                            }
                        }
                        SyncerKind::Tls(syncer, url, validate) => {
                            if let Ok(client) =
                                electrum_client::Client::new_ssl(url.as_str(), *validate)
                            {
                                info!("succesfully created new syncer client");
                                syncer.client = client
                            }
                        }
                    }
                }
            };
            if wait_or_close(&r, sync_interval) {
                info!("closing syncer thread");
                break;
            }
        });

        notify_settings(self.notify.clone(), &self.get_settings()?);

        let estimates = self.get_fee_estimates()?;
        notify_fee(self.notify.clone(), &estimates);

        if let Some(registry_thread) = registry_thread {
            if wait_registry {
                info!("waiting registry thread");
                registry_thread.join().map_err(|_| Error::Generic("cannot join".to_string()))?;
                info!("registry thread joined");
            }
        }

        Ok(vec![])
    }

    fn get_receive_address(&self, addr_details: &Value) -> Result<AddressPointer, Error> {
        debug!("get_receive_address {:?}", addr_details);
        let w = self.get_wallet()?;
        let a = w.get_address()?;
        debug!("get_address {:?}", a);
        Ok(a)
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

    fn set_transaction_memo(&self, _txid: &str, _memo: &str, _memo_type: u32) -> Result<(), Error> {
        Err(Error::Generic("implementme: ElectrumSession set_transaction_memo".into()))
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
        let mut client = ClientWrap::new(self.url.clone())?;
        let tx_bytes = hex::decode(&tx.hex)?;
        let txid = client.transaction_broadcast_raw(&tx_bytes)?;
        Ok(format!("{}", txid))
    }

    fn broadcast_transaction(&mut self, tx_hex: &str) -> Result<String, Error> {
        let transaction = BETransaction::from_hex(&tx_hex, self.network.id())?;

        info!("broadcast_transaction {:#?}", transaction.txid());
        let mut client = ClientWrap::new(self.url.clone())?;
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
        Ok(self.try_get_fee_estimates().unwrap_or_else(|_| vec![FeeEstimate(1000u64); 25]))
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
        info!("refresh_assets details {:?}", details);
        let mut map = serde_json::Map::new();

        let wallet = self.get_wallet()?;
        if details.assets {
            let assets = wallet
                .get_asset_registry()?
                .ok_or_else(|| Error::Generic("cannot find asset registry".into()))?;
            map.insert("assets".to_string(), assets);
        }
        if details.icons {
            let icons = wallet
                .get_asset_icons()?
                .ok_or_else(|| Error::Generic("cannot find asset icons".into()))?;
            map.insert("icons".to_string(), icons);
        }
        Ok(Value::Object(map))
    }

    fn status(&self) -> Result<u64, Error> {
        let mut opt = GetTransactionsOpt::default();
        opt.count = 100;
        let txs = self.get_wallet()?.list_tx(&opt)?;
        let mut hasher = DefaultHasher::new();
        for tx in txs.iter() {
            std::hash::Hash::hash(&tx.txid, &mut hasher);
        }
        let tip = self.get_wallet()?.get_tip()?;
        std::hash::Hash::hash(&tip, &mut hasher);
        let status = hasher.finish();
        debug!("txs.len={} tip={} status={}", txs.len(), tip, status);
        Ok(status)
    }
}

impl<S: Read + Write> Tipper<S> {
    pub fn tip(&mut self) -> Result<usize, Error> {
        let header = self.client.block_headers_subscribe_raw()?;
        self.db.insert_tip(header.height as u32)?;
        Ok(header.height)
    }
}

impl<S: Read + Write> Headers<S> {
    pub fn ask(&mut self, chunk_size: usize) -> Result<usize, Error> {
        if let ChainOrVerifier::Chain(chain) = &mut self.checker {
            info!("asking headers, current height:{} chunk_size:{} ", chain.height(), chunk_size);
            let headers =
                self.client.block_headers(chain.height() as usize + 1, chunk_size)?.headers;
            let len = headers.len();
            chain.push(headers)?;
            Ok(len)
        } else {
            // Liquid doesn't need to download the header's chain
            Ok(0)
        }
    }

    pub fn get_proofs(&mut self) -> Result<usize, Error> {
        let my_confirmed_txs: Vec<(Txid, u32)> = self.db.get_my_confirmed()?;
        let my_proofs: HashSet<Txid> = self.db.get_my_verified()?;
        let mut found = 0;
        for (txid, height) in my_confirmed_txs {
            if !my_proofs.contains(&txid) {
                let proof = self.client.transaction_get_merkle(&txid, height as usize)?;
                let verified = match &self.checker {
                    ChainOrVerifier::Chain(chain) => {
                        chain.verify_tx_proof(&txid, height, proof).is_ok()
                    }
                    ChainOrVerifier::Verifier(verifier) => {
                        if let Some(BEBlockHeader::Elements(header)) = self.db.get_header(height)? {
                            verifier.verify_tx_proof(&txid, proof, &header).is_ok()
                        } else {
                            false
                        }
                    }
                };

                if verified {
                    info!("proof for {} verified!", txid);
                    self.db.insert_tx_verified(&txid)?;
                    found += 1;
                }
            }
        }
        Ok(found)
    }

    pub fn remove(&mut self, headers: u32) -> Result<(), Error> {
        if let ChainOrVerifier::Chain(chain) = &mut self.checker {
            chain.remove(headers)?;
        }
        Ok(())
    }
}
impl<S: Read + Write> Syncer<S> {
    pub fn sync(&mut self) -> Result<bool, Error> {
        trace!("start sync");
        let start = Instant::now();

        let mut history_txs_id = HashSet::new();
        let mut heights_set = HashSet::new();
        let mut txid_height = HashMap::new();

        let mut last_used = [0u32; 2];
        for i in 0..=1 {
            let int_or_ext = Index::from(i)?;
            let mut batch_count = 0;
            loop {
                let batch = self.db.get_script_batch(int_or_ext, batch_count)?;
                let result: Vec<Vec<GetHistoryRes>> =
                    self.client.batch_script_get_history(&batch)?;
                let max = result
                    .iter()
                    .enumerate()
                    .filter(|(_, v)| !v.is_empty())
                    .map(|(i, _)| i as u32)
                    .max();
                if let Some(max) = max {
                    last_used[i as usize] = max + batch_count * BATCH_SIZE;
                };

                let flattened: Vec<GetHistoryRes> = result.into_iter().flatten().collect();
                trace!("{}/batch({}) {:?}", i, batch_count, flattened.len());

                if flattened.is_empty() {
                    break;
                }

                for el in flattened {
                    if el.height >= 0 {
                        heights_set.insert(el.height as u32);
                        txid_height.insert(el.tx_hash, el.height as u32);
                    }
                    history_txs_id.insert(el.tx_hash);
                }

                batch_count += 1;
            }
        }

        self.db.insert_index(Index::External, last_used[Index::External as usize])?;
        self.db.insert_index(Index::Internal, last_used[Index::Internal as usize])?;
        trace!("last_used: {:?}", last_used,);

        let new_txs = self.sync_txs(&history_txs_id)?;
        self.sync_headers(&heights_set)?;
        self.sync_height(&txid_height)?;

        if new_txs {
            self.db.flush()?;
        }

        trace!("elapsed {}", start.elapsed().as_millis());

        Ok(new_txs)
    }

    fn sync_headers(&mut self, heights_set: &HashSet<u32>) -> Result<(), Error> {
        let heights_in_db = self.db.get_only_heights()?;
        let heights_to_download: Vec<u32> =
            heights_set.difference(&heights_in_db).cloned().collect();
        if !heights_to_download.is_empty() {
            let headers_bytes_downloaded =
                self.client.batch_block_header_raw(heights_to_download.clone())?;
            let mut headers_downloaded: Vec<BEBlockHeader> = vec![];
            for vec in headers_bytes_downloaded {
                headers_downloaded.push(BEBlockHeader::deserialize(&vec, self.network.id())?);
            }

            for (header, height) in headers_downloaded.iter().zip(heights_to_download.iter()) {
                self.db.insert_header(*height, header)?;
            }
            info!("headers_downloaded {:?}", headers_downloaded);
        }

        Ok(())
    }

    fn sync_height(&self, txid_height: &HashMap<Txid, u32>) -> Result<(), Error> {
        // sync heights, which are my txs
        for (txid, height) in txid_height.iter() {
            self.db.insert_height(txid, *height)?; // adding new, but also updating reorged tx
        }
        for txid_db in self.db.get_only_txids()?.iter() {
            if txid_height.get(txid_db).is_none() {
                self.db.remove_height(txid_db)?; // something in the db is not in live list (rbf), removing
            }
        }

        Ok(())
    }

    fn sync_txs(&mut self, history_txs_id: &HashSet<Txid>) -> Result<bool, Error> {
        let mut txs_in_db = self.db.get_all_txid()?;
        let txs_to_download: Vec<&Txid> = history_txs_id.difference(&txs_in_db).collect();
        if !txs_to_download.is_empty() {
            let mut batch = Batch::default();

            let txs_bytes_downloaded = self.client.batch_transaction_get_raw(txs_to_download)?;
            let mut txs_downloaded: Vec<BETransaction> = vec![];
            for vec in txs_bytes_downloaded {
                txs_downloaded.push(BETransaction::deserialize(&vec, self.network.id())?);
            }
            info!("txs_downloaded {:?}", txs_downloaded.len());
            let mut previous_txs_to_download = HashSet::new();
            for tx in txs_downloaded.iter() {
                //self.db.insert_tx(&tx.txid(), &tx)?;
                batch.insert(self.db.encrypt(tx.txid()), self.db.encrypt(tx.serialize()));
                txs_in_db.insert(tx.txid());
                for txid in tx.previous_output_txids() {
                    previous_txs_to_download.insert(txid);
                }

                //TODO compute OutPoint Unblinded if tx is mine and it is liquid
                if let BETransaction::Elements(tx) = tx {
                    info!("compute OutPoint Unblinded");
                    for (i, output) in tx.output.iter().enumerate() {
                        if self.db.is_mine(&output.script_pubkey) {
                            let txid = tx.txid();
                            let vout = i as u32;
                            let outpoint = elements::OutPoint {
                                txid,
                                vout,
                            };
                            if self.try_unblind(outpoint, output.clone()).is_err() {
                                info!("{} cannot unblind, ignoring (could be sender messed up with the blinding process)", outpoint);
                            }
                        }
                    }
                }
            }

            let txs_to_download: Vec<&Txid> =
                previous_txs_to_download.difference(&txs_in_db).collect();
            if !txs_to_download.is_empty() {
                let txs_bytes_downloaded =
                    self.client.batch_transaction_get_raw(txs_to_download)?;
                let mut txs_downloaded: Vec<BETransaction> = vec![];
                for vec in txs_bytes_downloaded {
                    txs_downloaded.push(BETransaction::deserialize(&vec, self.network.id())?);
                }
                info!("previous txs_downloaded {:?}", txs_downloaded.len());
                for tx in txs_downloaded.iter() {
                    //self.db.insert_tx(&tx.txid(), tx)?;
                    batch.insert(self.db.encrypt(tx.txid()), self.db.encrypt(tx.serialize()));
                }
            }
            self.db.apply_txs_batch(batch)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn try_unblind(
        &self,
        outpoint: elements::OutPoint,
        output: elements::TxOut,
    ) -> Result<(), Error> {
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
                self.db.insert_unblinded(&outpoint, &unblinded)?;
            }
            _ => warn!("received unconfidential or null asset/value/nonce"),
        }
        Ok(())
    }
}

fn wait_or_close(r: &Receiver<()>, interval: u32) -> bool {
    for _ in 0..interval {
        thread::sleep(Duration::from_secs(1));
        if r.try_recv().is_ok() {
            return true;
        }
    }
    false
}
