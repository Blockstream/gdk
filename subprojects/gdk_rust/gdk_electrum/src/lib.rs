#[macro_use]
extern crate serde_json;

use log::{debug, info, trace, warn};
use serde_json::Value;

pub mod db;
pub mod error;
pub mod interface;
pub mod model;
pub mod tools;

use crate::db::{Forest, Index, BATCH_SIZE};
use crate::error::Error;
use crate::interface::{ElectrumUrl, WalletCtx};

use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::{self, Secp256k1};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::Txid;
pub use electrum_client::client::{ElectrumPlaintextStream, ElectrumSslStream};

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
use std::sync::mpsc::{channel, Sender};
use std::thread;
use std::time::{Duration, Instant};

pub enum SyncerKind {
    Plain(Syncer<ElectrumPlaintextStream>, String),
    Tls(Syncer<ElectrumSslStream>, String, bool),
}

pub enum TipperKind {
    Plain(Tipper<ElectrumPlaintextStream>, String),
    Tls(Tipper<ElectrumSslStream>, String, bool),
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

    pub fn batch_estimate_fee<'s, I>(&mut self, numbers: I) -> Result<Vec<f64>, Error>
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
    pub client: electrum_client::Client<S>,
    pub network: Network,
}

impl<S: Read + Write> Tipper<S> {
    pub fn new(client: electrum_client::Client<S>, network: Network) -> Result<Self, Error> {
        Ok(Tipper {
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
    pub db_root: String,
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

fn notify_fee(notif: NativeNotif, fees: &Vec<FeeEstimate>) {
    let data = json!({"fees":fees,"event":"fees"});
    notify(notif, data);
}

fn determine_electrum_url(
    url: &Option<String>,
    tls: &Option<bool>,
    validate_domain: &Option<bool>,
) -> Result<ElectrumUrl, Error> {
    let url = url.as_ref().ok_or_else(|| Error::Generic("network url is missing".into()))?;
    if url == "" {
        return Err(Error::Generic("network url is empty".into()))?;
    }

    if tls.unwrap_or(false) {
        Ok(ElectrumUrl::Tls(url.into(), validate_domain.unwrap_or(false)))
    } else {
        Ok(ElectrumUrl::Plaintext(url.into()))
    }
}

pub fn determine_electrum_url_from_net(network: &Network) -> Result<ElectrumUrl, Error> {
    determine_electrum_url(&network.url, &network.tls, &network.validate_domain)
}

impl ElectrumSession {
    pub fn new_session(network: Network, db_root: &str, url: ElectrumUrl) -> Result<Self, Error> {
        Ok(Self::create_session(network, db_root, url))
    }
}

impl ElectrumSession {
    pub fn create_session(network: Network, db_root: &str, url: ElectrumUrl) -> Self {
        Self {
            db_root: db_root.to_string(),
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
        let blocks: Vec<usize> = (1..25).collect();
        let mut estimates: Vec<FeeEstimate> = client
            .batch_estimate_fee(blocks)?
            .iter()
            .map(|e| FeeEstimate((*e * 100_000_000.0) as u64))
            .collect();
        let relay_fee = client.relay_fee()?;
        estimates.insert(0, FeeEstimate((relay_fee * 100_000_000.0) as u64));
        Ok(estimates)
    }
}

fn make_txlist_item(tx: &TransactionMeta) -> TxListItem {
    let type_ = tx.type_.clone();
    let len = tx.hex.len() / 2;
    let fee_rate = (tx.fee as f64 / len as f64) as u64;
    let addressees = vec![];

    TxListItem {
        block_height: tx.height.unwrap_or_default(),
        created_at: tx.created_at.clone(),
        type_,
        memo: "".into(), // TODO: TransactionMeta -> TxListItem memo
        txhash: tx.txid.clone(),
        transaction_size: len,
        transaction: tx.hex.clone(), // FIXME
        satoshi: tx.satoshi.clone(),
        rbf_optin: false,           // TODO: TransactionMeta -> TxListItem rbf_optin
        cap_cpfp: false,            // TODO: TransactionMeta -> TxListItem cap_cpfp
        can_rbf: false,             // TODO: TransactionMeta -> TxListItem can_rbf
        has_payment_request: false, // TODO: TransactionMeta -> TxListItem has_payment_request
        server_signed: false,       // TODO: TransactionMeta -> TxListItem server_signed
        user_signed: true,
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
        if self.db_root == "" {
            self.db_root =
                net_params["state_dir"].as_str().map(|x| x.to_string()).unwrap_or("".into());
            info!("setting db_root to {:?}", self.db_root);
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

        let wallet_desc = format!("{}{:?}", xpub, self.network);
        let wallet_id = hex::encode(sha256::Hash::hash(wallet_desc.as_bytes()));

        let master_blinding = if self.network.liquid {
            Some(asset_blinding_key_from_seed(&seed))
        } else {
            None
        };

        let mut path: PathBuf = self.db_root.as_str().into();
        path.push(wallet_id);
        info!("opening sled db root path: {:?}", path);
        let db = Forest::new(&path, xpub, master_blinding.clone(), self.network.id())?;

        let mut wait_registry = false;
        let mut registry_thread = None;
        if self.network.liquid {
            let asset_icons = db.get_asset_icons()?;
            let asset_registry = db.get_asset_registry()?;
            wait_registry = asset_icons.is_none() || asset_registry.is_none();
            let db_for_registry = db.clone();
            registry_thread = Some(thread::spawn(move || {
                info!("start registry thread");
                //TODO add if_modified_since
                let registry = ureq::get("https://assets.blockstream.info/index.json")
                    .call()
                    .into_string()
                    .unwrap();

                info!("got registry (len:{})", registry.len());
                db_for_registry.insert_asset_registry(&registry).unwrap();
                let icons = ureq::get("https://assets.blockstream.info/icons.json")
                    .call()
                    .into_string()
                    .unwrap();
                info!("got icons (len:{})", icons.len());
                db_for_registry.insert_asset_icons(&icons).unwrap();
            }));
        }

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
                    Tipper::new(client, self.network.clone())?,
                    url.to_string(),
                    *validate,
                )
            }
            ElectrumUrl::Plaintext(url) => {
                let client = electrum_client::Client::new(&url)?;
                TipperKind::Plain(Tipper::new(client, self.network.clone())?, url.to_string())
            }
        };

        let wallet = WalletCtx::new(
            db,
            mnemonic.clone(),
            self.network.clone(),
            xprv,
            xpub,
            master_blinding.clone(),
        )?;

        self.wallet = Some(wallet);

        let notify_blocks = self.notify.clone();

        let mut last_tip = tipper.tip().unwrap();
        info!("tip is {:?}", last_tip);
        notify_block(notify_blocks.clone(), last_tip);

        let (close_tipper, r) = channel();
        self.closer.senders.push(close_tipper);
        thread::spawn(move || 'outer: loop {
            for _ in 0..7 {
                thread::sleep(Duration::from_secs(1));
                if r.try_recv().is_ok() {
                    info!("closing tipper");
                    break 'outer;
                }
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
                        Error::ClientError(_) => info!("Client error, doing nothing"),
                        _ => {
                            warn!("Recreating died tipper client, {:?}", e);

                            match &mut tipper {
                                TipperKind::Plain(a, url) => {
                                    a.client = electrum_client::Client::new(url.as_str()).unwrap()
                                }
                                TipperKind::Tls(a, url, validate) => {
                                    a.client =
                                        electrum_client::Client::new_ssl(url.as_str(), *validate)
                                            .unwrap()
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
        thread::spawn(move || 'outer: loop {
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
                    warn!("Recreating died syncer client, {:?}", e);
                    match &mut syncer {
                        SyncerKind::Plain(a, url) => {
                            a.client = electrum_client::Client::new(url.as_str()).unwrap()
                        }
                        SyncerKind::Tls(a, url, validate) => {
                            a.client =
                                electrum_client::Client::new_ssl(url.as_str(), *validate).unwrap()
                        }
                    }
                }
            };
            for _ in 0..9 {
                thread::sleep(Duration::from_secs(1));
                if r.try_recv().is_ok() {
                    info!("closing syncer");
                    break 'outer;
                }
            }
        });

        notify_settings(self.notify.clone(), &self.get_settings()?);

        let estimates = self.get_fee_estimates()?;
        notify_fee(self.notify.clone(), &estimates);

        if let Some(registry_thread) = registry_thread {
            if wait_registry {
                info!("waiting registry thread");
                registry_thread.join().unwrap();
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
        match &tx.transaction {
            BETransaction::Bitcoin(tx) => {
                let tx_bytes = bitcoin::consensus::encode::serialize(tx);
                client.transaction_broadcast_raw(&tx_bytes)?
            }
            BETransaction::Elements(tx) => {
                let tx_bytes = elements::encode::serialize(tx);
                client.transaction_broadcast_raw(&tx_bytes)?
            }
        };
        Ok(format!("{}", tx.txid))
    }

    fn broadcast_transaction(&mut self, tx_hex: &str) -> Result<String, Error> {
        let mut client = ClientWrap::new(self.url.clone())?;
        info!("broadcast_transaction {:#?}", tx_hex);
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
        Ok(self.try_get_fee_estimates().unwrap_or(vec![FeeEstimate(1000u64); 25]))
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
}

impl<S: Read + Write> Tipper<S> {
    pub fn tip(&mut self) -> Result<usize, Error> {
        let header = self.client.block_headers_subscribe_raw()?;
        Ok(header.height)
    }
}

impl<S: Read + Write> Syncer<S> {
    pub fn sync(&mut self) -> Result<bool, Error> {
        trace!("start sync");
        let start = Instant::now();

        //let mut client = Client::new("tn.not.fyi:55001")?;
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
            let txs_bytes_downloaded = self.client.batch_transaction_get_raw(txs_to_download)?;
            let mut txs_downloaded: Vec<BETransaction> = vec![];
            for vec in txs_bytes_downloaded {
                txs_downloaded.push(BETransaction::deserialize(&vec, self.network.id())?);
            }
            info!("txs_downloaded {:?}", txs_downloaded.len());
            let mut previous_txs_to_download = HashSet::new();
            for tx in txs_downloaded.iter() {
                self.db.insert_tx(&tx.txid(), &tx)?;
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
                            if let Err(_) = self.try_unblind(outpoint, output.clone()) {
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
                    self.db.insert_tx(&tx.txid(), tx)?;
                }
            }
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
                    "commitmnents len {} {} {}",
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
