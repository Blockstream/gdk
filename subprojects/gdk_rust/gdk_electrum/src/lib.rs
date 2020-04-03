#[macro_use]
extern crate serde_json;

use log::{debug, info};
use serde_json::Value;

pub mod db;
pub mod error;
pub mod interface;
pub mod model;
pub mod tools;

use crate::db::{Index, BATCH_SIZE};
use crate::error::Error;
use crate::interface::{ElectrumUrl, WalletCtx};

use bitcoin::consensus::deserialize;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::Transaction;
use bitcoin::Txid;
pub use electrum_client::client::{ElectrumPlaintextStream, ElectrumSslStream};

use electrum_client::GetHistoryRes;
use gdk_common::be::*;
use gdk_common::mnemonic::Mnemonic;
use gdk_common::model::*;
use gdk_common::network::Network;
use gdk_common::password::Password;
use gdk_common::session::Session;
use gdk_common::wally::{self, asset_blinding_key_from_seed};

use bitcoin::BitcoinHash;
use gdk_common::{ElementsNetwork, NetworkId};
use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::str::FromStr;
use std::time::Instant;

pub struct ElectrumSession<S: Read + Write> {
    pub db_root: String,
    pub network: Network,
    pub client: electrum_client::Client<S>,
    pub wallet: Option<WalletCtx>,
    pub notify:
        Option<(extern "C" fn(*const libc::c_void, *const GDKRUST_json), *const libc::c_void)>,
}

fn determine_electrum_url(url: &Option<String>, tls: &Option<bool>) -> Result<ElectrumUrl, Error> {
    let url = url.as_ref().ok_or_else(|| Error::Generic("network url is missing".into()))?;
    if url == "" {
        return Err(Error::Generic("network url is empty".into()))?;
    }

    if tls.unwrap_or(false) {
        Ok(ElectrumUrl::Tls(url.into()))
    } else {
        Ok(ElectrumUrl::Plaintext(url.into()))
    }
}

pub fn determine_electrum_url_from_net(network: &Network) -> Result<ElectrumUrl, Error> {
    determine_electrum_url(&network.url, &network.tls)
}

impl ElectrumSession<ElectrumSslStream> {
    pub fn new_tls_session(network: Network, db_root: &str) -> Result<Self, Error> {
        let url: &str = network
            .url
            .as_ref()
            .ok_or_else(|| Error::Generic("network url missing in new_tls_session".into()))?;
        let validate = network.validate_domain.unwrap_or(true);
        let client = electrum_client::Client::new_ssl(url, validate)?;
        Ok(Self::create_session(network, db_root, client))
    }
}

impl ElectrumSession<ElectrumPlaintextStream> {
    pub fn new_plaintext_session(network: Network, db_root: &str) -> Result<Self, Error> {
        let url: &str = network
            .url
            .as_ref()
            .ok_or_else(|| Error::Generic("network url missing in new_plaintext_session".into()))?;
        let client = electrum_client::Client::new(url)?;
        Ok(Self::create_session(network, db_root, client))
    }
}

impl<S: Read + Write> ElectrumSession<S> {
    pub fn create_session(
        network: Network,
        db_root: &str,
        client: electrum_client::Client<S>,
    ) -> Self {
        Self {
            db_root: db_root.to_string(),
            client,
            network,
            wallet: None,
            notify: None,
        }
    }

    pub fn notify_blocks(
        &mut self,
        headers: Vec<(BEBlockHeader, u32)>,
    ) -> Result<Vec<Notification>, Error> {
        Ok(headers
            .iter()
            .map(|(be_header, height)| match be_header {
                BEBlockHeader::Bitcoin(ref header) => Notification::Block(BlockNotification {
                    block_hash: header.bitcoin_hash(),
                    block_height: *height,
                }),

                BEBlockHeader::Elements(ref header) => Notification::Block(BlockNotification {
                    block_hash: header.bitcoin_hash(),
                    block_height: *height,
                }),
            })
            .collect())
    }

    pub fn get_wallet(&self) -> Result<&WalletCtx, Error> {
        self.wallet.as_ref().ok_or_else(|| Error::Generic("wallet not initialized".into()))
    }

    pub fn get_wallet_mut(&mut self) -> Result<&mut WalletCtx, Error> {
        self.wallet.as_mut().ok_or_else(|| Error::Generic("wallet not initialized".into()))
    }

    fn sync_headers(
        &mut self,
        heights_set: &HashSet<u32>,
    ) -> Result<Vec<(BEBlockHeader, u32)>, Error> {
        let mut header_heights: Vec<(BEBlockHeader, u32)> = vec![];
        let heights_in_db = self.get_wallet()?.db.get_only_heights()?;
        let heights_to_download: Vec<u32> =
            heights_set.difference(&heights_in_db).cloned().collect();
        if !heights_to_download.is_empty() {
            let headers_bytes_downloaded =
                self.client.batch_block_header_raw(heights_to_download.clone())?;
            let mut headers_downloaded: Vec<BEBlockHeader> = vec![];
            for vec in headers_bytes_downloaded {
                headers_downloaded
                    .push(BEBlockHeader::deserialize(&vec, self.get_wallet()?.network.id())?);
            }

            for (header, height) in headers_downloaded.iter().zip(heights_to_download.iter()) {
                header_heights.push(((*header).clone(), *height));
                self.get_wallet()?.db.insert_header(*height, header)?;
            }
            debug!("headers_downloaded {:?}", headers_downloaded.len());
        }

        Ok(header_heights)
    }

    fn sync_height(&mut self, txid_height: &HashMap<Txid, u32>) -> Result<(), Error> {
        // sync heights, which are my txs
        for (txid, height) in txid_height.iter() {
            self.get_wallet()?.db.insert_height(txid, *height)?; // adding new, but also updating reorged tx
        }
        for txid_db in self.get_wallet()?.db.get_only_txids()?.iter() {
            if txid_height.get(txid_db).is_none() {
                self.get_wallet()?.db.remove_height(txid_db)?; // something in the db is not in live list (rbf), removing
            }
        }

        Ok(())
    }

    fn sync_txs(&mut self, history_txs_id: &HashSet<Txid>) -> Result<(), Error> {
        let mut txs_in_db = self.get_wallet()?.db.get_all_txid()?;
        let txs_to_download: Vec<&Txid> = history_txs_id.difference(&txs_in_db).collect();
        if !txs_to_download.is_empty() {
            let txs_bytes_downloaded = self.client.batch_transaction_get_raw(txs_to_download)?;
            let mut txs_downloaded: Vec<BETransaction> = vec![];
            for vec in txs_bytes_downloaded {
                txs_downloaded
                    .push(BETransaction::deserialize(&vec, self.get_wallet()?.network.id())?);
            }
            debug!("txs_downloaded {:?}", txs_downloaded.len());
            let mut previous_txs_to_download = HashSet::new();
            for tx in txs_downloaded.iter() {
                self.get_wallet()?.db.insert_tx(&tx.txid(), &tx)?;
                txs_in_db.insert(tx.txid());
                for txid in tx.previous_output_txids() {
                    previous_txs_to_download.insert(txid);
                }

                //TODO compute OutPoint Unblinded if tx is mine and it is liquid
                if let BETransaction::Elements(tx) = tx {
                    debug!("compute OutPoint Unblinded");
                    for (i, output) in tx.output.iter().enumerate() {
                        if self.get_wallet()?.db.is_mine(&output.script_pubkey) {
                            let txid = tx.txid();
                            let vout = i as u32;
                            let outpoint = elements::OutPoint {
                                txid,
                                vout,
                            };
                            if let Err(_) = self.get_wallet()?.try_unblind(outpoint, output.clone())
                            {
                                debug!("{} cannot unblind, ignoring (could be sender messed up with the blinding process)", outpoint);
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
                    txs_downloaded
                        .push(BETransaction::deserialize(&vec, self.get_wallet()?.network.id())?);
                }
                debug!("previous txs_downloaded {:?}", txs_downloaded.len());
                for tx in txs_downloaded.iter() {
                    self.get_wallet()?.db.insert_tx(&tx.txid(), tx)?;
                }
            }
        }

        Ok(())
    }

    fn try_get_fee_estimates(&mut self) -> Result<Vec<FeeEstimate>, Error> {
        let blocks: Vec<usize> = (1..25).collect();
        let mut estimates: Vec<FeeEstimate> = self
            .client
            .batch_estimate_fee(blocks)?
            .iter()
            .map(|e| FeeEstimate((*e * 100_000_000.0) as u64))
            .collect();
        let relay_fee = self.client.relay_fee()?;
        estimates.insert(0, FeeEstimate((relay_fee * 100_000_000.0) as u64));
        Ok(estimates)
    }
}

fn make_txlist_item(tx: &TransactionMeta) -> TxListItem {
    let type_ = "incoming".to_string(); // TODO, compute
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

impl<S: Read + Write> Session<Error> for ElectrumSession<S> {
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
            debug!("setting db_root to {:?}", self.db_root);
        }

        info!("connect {:?}", self.network);

        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        //TODO call db flush
        Err(Error::Generic("implementme: ElectrumSession connect".into()))
    }

    fn sync(&mut self) -> Result<Vec<Notification>, Error> {
        debug!("start sync {}", self.get_wallet()?.xpub);
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
                let batch = self.get_wallet()?.db.get_script_batch(
                    int_or_ext,
                    batch_count,
                    self.get_wallet()?.master_blinding.as_ref(),
                )?;
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
                debug!("{}/batch({}) {:?}", i, batch_count, flattened.len());

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

        self.get_wallet()?.db.insert_index(Index::External, last_used[Index::External as usize])?;
        self.get_wallet()?.db.insert_index(Index::Internal, last_used[Index::Internal as usize])?;
        debug!("last_used: {:?}", last_used,);

        self.sync_txs(&history_txs_id)?;
        let new_headers = self.sync_headers(&heights_set)?;
        self.sync_height(&txid_height)?;

        debug!("elapsed {}", start.elapsed().as_millis());

        self.notify_blocks(new_headers)
    }

    fn login(
        &mut self,
        mnemonic: &Mnemonic,
        password: Option<Password>,
    ) -> Result<Vec<Notification>, Error> {
        debug!("login {:#?}", self.network);

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
        let path_string = format!("m/44'/{}'/0'", coin_type);
        debug!("Using derivation path {}/0|1/*", path_string);
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

        let wallet = WalletCtx::new(
            &self.db_root,
            wallet_id,
            mnemonic.clone(),
            self.network.clone(),
            xprv,
            xpub,
            master_blinding,
        )?;

        self.wallet = Some(wallet);
        self.sync()
    }

    fn get_receive_address(&self, _addr_details: &Value) -> Result<AddressResult, Error> {
        let w = self.get_wallet()?;
        let a = w.get_address()?;
        Ok(AddressResult(a.address.to_string()))
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
        let txs = self.get_transactions(&json!({}))?;

        let subaccounts_fake = Subaccount {
            type_: "electrum".into(),
            name: "Single sig wallet".into(),
            has_transactions: !txs.0.is_empty(),
            satoshi: balance,
        };

        Ok(subaccounts_fake)
    }

    fn get_transactions(&self, _details: &Value) -> Result<TxsResult, Error> {
        let txs = self.get_wallet()?.list_tx()?.iter().map(make_txlist_item).collect();

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

    fn create_transaction(&self, tx_req: &CreateTransaction) -> Result<TransactionMeta, Error> {
        debug!("electrum create_transaction {:#?}", tx_req);
        self.get_wallet()?.create_tx(tx_req)
    }

    fn sign_transaction(&self, create_tx: &TransactionMeta) -> Result<TransactionMeta, Error> {
        debug!("electrum sign_transaction {:#?}", create_tx);
        self.get_wallet()?.sign(create_tx)
    }

    fn send_transaction(&mut self, tx: &TransactionMeta) -> Result<String, Error> {
        debug!("electrum send_transaction {:#?}", tx);
        match &tx.transaction {
            BETransaction::Bitcoin(tx) => self.client.transaction_broadcast(&tx)?,
            BETransaction::Elements(_tx) => {
                return Err(Error::Generic("implementme: send liquid transaction".into()))
            }
        };
        Ok(format!("{}", tx.txid))
    }

    fn broadcast_transaction(&mut self, tx_hex: &str) -> Result<String, Error> {
        debug!("broadcast_transaction {:#?}", tx_hex);
        let tx: Transaction = deserialize(&hex::decode(tx_hex)?)?;
        self.client.transaction_broadcast(&tx)?;
        Ok(format!("{}", tx.txid()))
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

    fn get_settings(&self) -> Result<Value, Error> {
        let settings = self.get_wallet()?.get_settings()?;
        Ok(serde_json::to_value(settings)?)
    }

    fn change_settings(&mut self, settings: &Settings) -> Result<(), Error> {
        self.get_wallet()?.change_settings(settings)
    }

    fn get_available_currencies(&self) -> Result<Value, Error> {
        Ok(json!({ "all": [ "USD" ], "per_exchange": { "BITFINEX": [ "USD" ] } }))
        // TODO implement
    }
}
