use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::str::FromStr;

use log::{debug, info, trace, warn};

use bitcoin::blockdata::script;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, Message};
use bitcoin::util::address::Payload;
use bitcoin::util::bip143::SigHashCache;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{PublicKey, SigHashType};
use elements::confidential::Value;

use gdk_common::be::{
    BEAddress, BEOutPoint, BEScript, BEScriptConvert, BETransaction, BETxid, ScriptBatch, UTXOInfo,
    Utxos, DUST_VALUE,
};
use gdk_common::error::fn_err;
use gdk_common::model::{
    AccountInfo, AddressAmount, AddressPointer, Balances, CreateTransaction, GetTransactionsOpt,
    SPVVerifyResult, TransactionMeta, UpdateAccountOpt, UtxoStrategy,
};
use gdk_common::scripts::{p2pkh_script, p2shwpkh_script_sig, ScriptType};
use gdk_common::util::is_confidential_txoutsecrets;
use gdk_common::wally::{
    asset_blinding_key_to_ec_private_key, ec_public_key_from_private_key, MasterBlindingKey,
};
use gdk_common::{ElementsNetwork, Network, NetworkId};

use crate::error::Error;
use crate::interface::ElectrumUrl;
use crate::store::{Store, BATCH_SIZE};

// The number of account types, including these reserved for future use.
// Currently only 3 are used: P2SH-P2WPKH, P2WPKH and P2PKH
const NUM_RESERVED_ACCOUNT_TYPES: u32 = 16;

lazy_static! {
    static ref EC: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

pub struct Account {
    account_num: u32,
    script_type: ScriptType,
    xprv: ExtendedPrivKey,
    xpub: ExtendedPubKey,
    chains: [ExtendedPubKey; 2],
    network: Network,
    store: Store,
    // elements only
    master_blinding: Option<MasterBlindingKey>,

    _path: DerivationPath,
}

impl Account {
    pub fn new(
        network: Network,
        master_xprv: &ExtendedPrivKey,
        master_blinding: Option<MasterBlindingKey>,
        store: Store,
        account_num: u32,
    ) -> Result<Self, Error> {
        let (script_type, path) = get_account_derivation(account_num, network.id())?;

        let xprv = master_xprv.derive_priv(&EC, &path)?;
        let xpub = ExtendedPubKey::from_private(&EC, &xprv);

        // cache internal/external chains
        let chains = [xpub.ckd_pub(&EC, 0.into())?, xpub.ckd_pub(&EC, 1.into())?];

        store.write().unwrap().make_account_cache(account_num);

        info!("initialized account #{} path={} type={:?}", account_num, path, script_type);

        Ok(Self {
            network,
            account_num,
            script_type,
            xprv,
            xpub,
            chains,
            store,
            master_blinding,
            // currently unused, but seems useful to have around
            _path: path,
        })
    }

    pub fn num(&self) -> u32 {
        self.account_num
    }

    pub fn info(&self) -> Result<AccountInfo, Error> {
        let settings = self.store.read()?.get_account_settings(self.account_num).cloned();

        Ok(AccountInfo {
            account_num: self.account_num,
            script_type: self.script_type,
            settings: settings.unwrap_or_default(),
            required_ca: 0,
            receiving_id: "".to_string(),
        })
    }

    pub fn set_settings(&self, opt: UpdateAccountOpt) -> Result<(), Error> {
        let mut store_write = self.store.write()?;
        let mut settings =
            store_write.get_account_settings(self.account_num).cloned().unwrap_or_default();
        if let Some(name) = opt.name {
            settings.name = name;
        }
        if let Some(hidden) = opt.hidden {
            settings.hidden = hidden;
        }
        store_write.set_account_settings(self.account_num, settings);
        Ok(())
    }

    pub fn set_name(&self, name: &str) -> Result<(), Error> {
        self.set_settings(UpdateAccountOpt {
            name: Some(name.into()),
            ..Default::default()
        })
    }

    pub fn derive_address(&self, is_change: bool, index: u32) -> Result<BEAddress, Error> {
        derive_address(
            &self.chains[is_change as usize],
            index,
            self.script_type,
            self.network.id(),
            self.master_blinding.as_ref(),
        )
    }

    pub fn get_next_address(&self) -> Result<AddressPointer, Error> {
        let pointer = {
            let store = &mut self.store.write()?;
            let acc_store = store.account_cache_mut(self.account_num)?;
            acc_store.indexes.external += 1;
            acc_store.indexes.external
        };
        let address = self.derive_address(false, pointer)?.to_string();
        Ok(AddressPointer {
            address,
            pointer,
        })
    }

    pub fn list_tx(&self, opt: &GetTransactionsOpt) -> Result<Vec<TransactionMeta>, Error> {
        let store = self.store.read()?;
        let acc_store = store.account_cache(self.account_num)?;

        let tip_height = store.cache.tip.0;
        let num_confs = opt.num_confs.unwrap_or(0);

        let mut txs = vec![];
        let mut my_txids: Vec<(&BETxid, &Option<u32>)> = acc_store
            .heights
            .iter()
            .filter(|(_, height)| {
                num_confs <= height.map_or(0, |height| (tip_height + 1).saturating_sub(height))
            })
            .collect();
        my_txids.sort_by(|a, b| {
            let height_cmp = b.1.unwrap_or(std::u32::MAX).cmp(&a.1.unwrap_or(std::u32::MAX));
            match height_cmp {
                Ordering::Equal => b.0.cmp(a.0),
                h @ _ => h,
            }
        });

        for (tx_id, height) in my_txids.iter().skip(opt.first).take(opt.count) {
            trace!("tx_id {}", tx_id);

            let txe = acc_store
                .all_txs
                .get(*tx_id)
                .ok_or_else(fn_err(&format!("list_tx no tx {}", tx_id)))?;
            let tx = &txe.tx;

            let header = height.map(|h| store.cache.headers.get(&h)).flatten();
            trace!("tx_id {} header {:?}", tx_id, header);
            let mut addressees = vec![];
            for i in 0..tx.output_len() as u32 {
                let script = tx.output_script(i);
                if !script.is_empty() && !acc_store.paths.contains_key(&script) {
                    let address = tx.output_address(i, self.network.id());
                    trace!("tx_id {}:{} not my script, address {:?}", tx_id, i, address);
                    addressees.push(AddressAmount {
                        address: address.unwrap_or_else(|| "".to_string()),
                        satoshi: 0, // apparently not needed in list_tx addressees
                        asset_id: None,
                    });
                }
            }
            let memo = store.get_memo(tx_id).cloned();

            let create_transaction = CreateTransaction {
                addressees,
                memo,
                ..Default::default()
            };

            let fee = tx.fee(
                &acc_store.all_txs,
                &acc_store.unblinded,
                &self.network.policy_asset_id().ok(),
            )?;
            trace!("tx_id {} fee {}", tx_id, fee);

            let satoshi =
                tx.my_balance_changes(&acc_store.all_txs, &acc_store.paths, &acc_store.unblinded);
            trace!("tx_id {} balances {:?}", tx_id, satoshi);

            // We define an incoming txs if there are more assets received by the wallet than spent
            // when they are equal it's an outgoing tx because the special asset liquid BTC
            // is negative due to the fee being paid
            // TODO how do we label issuance tx?
            let negatives = satoshi.iter().filter(|(_, v)| **v < 0).count();
            let positives = satoshi.iter().filter(|(_, v)| **v > 0).count();
            let (type_, user_signed) = if satoshi.is_empty() && self.network.liquid {
                ("unblindable", false)
            } else if tx.is_redeposit(&acc_store.paths, &acc_store.all_txs) {
                ("redeposit", true)
            } else if positives > negatives {
                ("incoming", false)
            } else {
                ("outgoing", true)
            };

            let spv_verified = if self.network.spv_enabled.unwrap_or(false) {
                store.spv_verification_status(self.num(), tx_id)
            } else {
                SPVVerifyResult::Disabled
            };

            trace!(
                "tx_id {} type {} user_signed {} spv_verified {:?}",
                tx_id,
                type_,
                user_signed,
                spv_verified
            );

            let tx_meta = TransactionMeta::new(
                txe.clone(),
                **height,
                header.map(|h| 1_000_000u64.saturating_mul(h.time() as u64)), // in microseconds
                satoshi,
                fee,
                self.network.id().get_bitcoin_network().unwrap_or(bitcoin::Network::Bitcoin),
                type_.to_string(),
                create_transaction,
                user_signed,
                spv_verified,
            );

            txs.push(tx_meta);
        }
        info!("list_tx {:?}", txs.iter().map(|e| &e.txid).collect::<Vec<&String>>());

        Ok(txs)
    }

    pub fn utxos(&self, num_confs: u32, confidential_utxos_only: bool) -> Result<Utxos, Error> {
        info!("start utxos");
        let store_read = self.store.read()?;
        let acc_store = store_read.account_cache(self.account_num)?;

        let tip_height = store_read.cache.tip.0;

        let mut utxos = vec![];
        let spent = self.spent()?;
        for (tx_id, height) in acc_store.heights.iter() {
            if num_confs > height.map_or(0, |height| (tip_height + 1).saturating_sub(height)) {
                continue;
            }

            let tx = &acc_store
                .all_txs
                .get(tx_id)
                .ok_or_else(fn_err(&format!("utxos no tx {}", tx_id)))?
                .tx;
            let tx_utxos: Vec<(BEOutPoint, UTXOInfo)> = match tx {
                BETransaction::Bitcoin(tx) => tx
                    .output
                    .clone()
                    .into_iter()
                    .enumerate()
                    .filter(|(_, output)| output.value > DUST_VALUE)
                    .map(|(vout, output)| (BEOutPoint::new_bitcoin(tx.txid(), vout as u32), output))
                    .filter_map(|(vout, output)| {
                        acc_store
                            .paths
                            .get(&(&output.script_pubkey).into())
                            .map(|path| (vout, output, path))
                    })
                    .filter(|(outpoint, _, _)| !spent.contains(&outpoint))
                    .map(|(outpoint, output, path)| {
                        (
                            outpoint,
                            UTXOInfo::new_bitcoin(
                                output.value,
                                output.script_pubkey.into(),
                                height.clone(),
                                path.clone(),
                            ),
                        )
                    })
                    .collect(),
                BETransaction::Elements(tx) => {
                    let policy_asset = self.network.policy_asset_id()?;
                    tx.output
                        .clone()
                        .into_iter()
                        .enumerate()
                        .map(|(vout, output)| {
                            (BEOutPoint::new_elements(tx.txid(), vout as u32), output)
                        })
                        .filter_map(|(vout, output)| {
                            acc_store
                                .paths
                                .get(&(&output.script_pubkey).into())
                                .map(|path| (vout, output, path))
                        })
                        .filter(|(outpoint, _, _)| !spent.contains(&outpoint))
                        .filter_map(|(outpoint, output, path)| {
                            if let BEOutPoint::Elements(el_outpoint) = outpoint {
                                if let Some(unblinded) = acc_store.unblinded.get(&el_outpoint) {
                                    if unblinded.value < DUST_VALUE
                                        && unblinded.asset == policy_asset
                                    {
                                        return None;
                                    }
                                    if confidential_utxos_only
                                        && is_confidential_txoutsecrets(unblinded)
                                    {
                                        return None;
                                    }
                                    return Some((
                                        outpoint,
                                        UTXOInfo::new_elements(
                                            unblinded.asset,
                                            unblinded.value,
                                            output.script_pubkey.into(),
                                            height.clone(),
                                            path.clone(),
                                            output.asset.is_confidential()
                                                && output.value.is_confidential(),
                                        ),
                                    ));
                                }
                            }
                            None
                        })
                        .collect()
                }
            };
            utxos.extend(tx_utxos);
        }
        utxos.sort_by(|a, b| (b.1).value.cmp(&(a.1).value));

        Ok(utxos)
    }

    fn spent(&self) -> Result<HashSet<BEOutPoint>, Error> {
        let store_read = self.store.read()?;
        let acc_store = store_read.account_cache(self.account_num)?;
        let mut result = HashSet::new();
        for txe in acc_store.all_txs.values() {
            let outpoints: Vec<BEOutPoint> = match &txe.tx {
                BETransaction::Bitcoin(tx) => {
                    tx.input.iter().map(|i| BEOutPoint::Bitcoin(i.previous_output)).collect()
                }
                BETransaction::Elements(tx) => {
                    tx.input.iter().map(|i| BEOutPoint::Elements(i.previous_output)).collect()
                }
            };
            result.extend(outpoints.into_iter());
        }
        Ok(result)
    }

    pub fn balance(
        &self,
        num_confs: u32,
        confidential_utxos_only: bool,
    ) -> Result<Balances, Error> {
        info!("start balance");
        let mut result = HashMap::new();
        match self.network.id() {
            NetworkId::Bitcoin(_) => result.entry("btc".to_string()).or_insert(0),
            NetworkId::Elements(_) => {
                result.entry(self.network.policy_asset.as_ref().unwrap().clone()).or_insert(0)
            }
        };
        for (_, info) in self.utxos(num_confs, confidential_utxos_only)?.iter() {
            *result.entry(info.asset.clone()).or_default() += info.value as i64;
        }
        Ok(result)
    }

    pub fn has_transactions(&self) -> bool {
        let store_read = self.store.read().unwrap();
        let acc_store = store_read.account_cache(self.account_num).unwrap();
        !acc_store.heights.is_empty()
    }

    pub fn create_tx(&self, request: &mut CreateTransaction) -> Result<TransactionMeta, Error> {
        if request.subaccount != self.account_num {
            return Err(Error::InvalidSubaccount(request.subaccount));
        }
        create_tx(self, request)
    }

    // TODO when we can serialize psbt
    //pub fn sign(&self, psbt: PartiallySignedTransaction) -> Result<PartiallySignedTransaction, Error> { Err(Error::Generic("NotImplemented".to_string())) }
    pub fn sign(&self, request: &TransactionMeta) -> Result<TransactionMeta, Error> {
        info!("sign");

        let be_tx =
            BETransaction::deserialize(&Vec::<u8>::from_hex(&request.hex)?, self.network.id())?;
        let store_read = self.store.read()?;
        let acc_store = store_read.account_cache(self.account_num)?;

        let mut betx: TransactionMeta = match be_tx {
            BETransaction::Bitcoin(tx) => {
                let mut out_tx = tx.clone();

                for i in 0..tx.input.len() {
                    let prev_output = tx.input[i].previous_output;
                    info!("input#{} prev_output:{:?}", i, prev_output);
                    let prev_tx = acc_store.get_bitcoin_tx(&prev_output.txid)?;
                    let out = prev_tx.output[prev_output.vout as usize].clone();
                    let derivation_path: DerivationPath = acc_store
                        .paths
                        .get(&out.script_pubkey.into())
                        .ok_or_else(|| Error::Generic("can't find derivation path".into()))?
                        .clone();
                    info!(
                        "input#{} prev_output:{:?} derivation_path:{:?}",
                        i, prev_output, derivation_path
                    );

                    let (script_sig, witness) = internal_sign_bitcoin(
                        &tx,
                        i,
                        &self.xprv,
                        &derivation_path,
                        out.value,
                        self.script_type,
                    );

                    out_tx.input[i].script_sig = script_sig;
                    out_tx.input[i].witness = witness;
                }
                let tx = BETransaction::Bitcoin(out_tx);
                info!(
                    "transaction final size is {} bytes and {} vbytes",
                    tx.serialize().len(),
                    tx.get_weight() / 4
                );
                info!("FINALTX inputs:{} outputs:{}", tx.input_len(), tx.output_len());
                tx.into()
            }
            BETransaction::Elements(tx) => {
                let mut tx = blind_tx(self, &tx)?;

                for i in 0..tx.input.len() {
                    let prev_output = tx.input[i].previous_output;
                    info!("input#{} prev_output:{:?}", i, prev_output);
                    let prev_tx = acc_store.get_liquid_tx(&prev_output.txid)?;
                    let out = prev_tx.output[prev_output.vout as usize].clone();
                    let derivation_path: DerivationPath = acc_store
                        .paths
                        .get(&out.script_pubkey.into())
                        .ok_or_else(|| Error::Generic("can't find derivation path".into()))?
                        .clone();

                    let (script_sig, witness) = internal_sign_elements(
                        &tx,
                        i,
                        &self.xprv,
                        &derivation_path,
                        out.value,
                        self.script_type,
                    );

                    tx.input[i].script_sig = script_sig;
                    tx.input[i].witness.script_witness = witness;
                }

                let fee: u64 =
                    tx.output.iter().filter(|o| o.is_fee()).map(|o| o.minimum_value()).sum();
                let tx = BETransaction::Elements(tx);
                info!(
                    "transaction final size is {} bytes and {} vbytes and fee is {}",
                    tx.serialize().len(),
                    tx.get_weight() / 4,
                    fee
                );
                info!("FINALTX inputs:{} outputs:{}", tx.input_len(), tx.output_len());
                tx.into()
            }
        };

        betx.fee = request.fee;
        betx.create_transaction = request.create_transaction.clone();
        betx.user_signed = true;

        drop(acc_store);
        drop(store_read);
        let mut store_write = self.store.write()?;
        let mut acc_store = store_write.account_cache_mut(self.account_num)?;

        let changes_used = request.changes_used.unwrap_or(0);
        if changes_used > 0 {
            info!("tx used {} changes", changes_used);
            // The next sync would update the internal index but we increment the internal index also
            // here after sign so that if we immediately create another tx we are not reusing addresses
            // This implies signing multiple times without broadcasting leads to gaps in the internal chain
            acc_store.indexes.internal += changes_used;
        }

        if let Some(memo) = request.create_transaction.as_ref().and_then(|c| c.memo.as_ref()) {
            let txid = BETxid::from_hex(&betx.txid, self.network.id())?;
            store_write.insert_memo(txid, memo)?;
        }

        Ok(betx)
    }

    pub fn get_script_batch(&self, is_change: bool, batch: u32) -> Result<ScriptBatch, Error> {
        let store = self.store.read()?;
        let acc_store = store.account_cache(self.account_num)?;

        let mut result = ScriptBatch::default();
        result.cached = true;

        let start = batch * BATCH_SIZE;
        let end = start + BATCH_SIZE;
        for j in start..end {
            let path = DerivationPath::from(&[(is_change as u32).into(), j.into()][..]);
            let script = acc_store.scripts.get(&path).cloned().map_or_else(
                || -> Result<BEScript, Error> {
                    result.cached = false;
                    Ok(self.derive_address(is_change, j)?.script_pubkey())
                },
                Ok,
            )?;
            result.value.push((script, path));
        }
        Ok(result)
    }

    /// Get the chain number for the given address (0 for receive or 1 for change)
    pub fn get_wallet_chain_type(&self, script: &BEScript) -> Option<u32> {
        let store_read = self.store.read().unwrap();
        let acc_store = store_read.account_cache(self.account_num).unwrap();

        if let Some(path) = acc_store.paths.get(&script) {
            if let ChildNumber::Normal {
                index,
            } = path[0]
            {
                return Some(index);
            }
        }
        None
    }

    /// Verify that our own (outgoing) transactions were properly signed by the wallet.
    /// This is needed to prevent malicious servers from getting the user to fee-bump a
    /// transaction that they never signed in the first place.
    ///
    /// Invalid transactions will be removed from the db and result in an Ok(false).
    pub fn verify_own_txs(&self, txs: &[(BETxid, BETransaction)]) -> Result<bool, Error> {
        let mut all_valid = true;
        let mut store_write = self.store.write().unwrap();
        let acc_store = store_write.account_cache_mut(self.account_num).unwrap();

        for (txid, tx) in txs {
            info!("verifying tx: {}", txid);
            // Confirmed transactions and Elements transactions cannot be fee-bumped and therefore don't require verification
            if !matches!(tx, BETransaction::Bitcoin(_))
                || acc_store.heights.get(txid).map_or(true, |h| h.is_some())
            {
                continue;
            }
            let mut hashcache = None;
            for (vin, outpoint) in tx.previous_outputs().iter().enumerate() {
                let script = acc_store
                    .all_txs
                    .get_previous_output_script_pubkey(outpoint)
                    .expect("prevout to be indexed");
                let public_key = match acc_store.paths.get(&script) {
                    Some(path) => self.xpub.derive_pub(&EC, path)?,
                    // We only need to check wallet-owned inputs
                    None => continue,
                }
                .public_key;
                let value = acc_store
                    .all_txs
                    .get_previous_output_value(&outpoint, &acc_store.unblinded)
                    .expect("own prevout to have known value");
                if let Err(err) = tx.verify_input_sig(
                    &EC,
                    &mut hashcache,
                    vin,
                    &public_key,
                    value,
                    self.script_type,
                ) {
                    warn!("tx {} verification failed: {:?}", txid, err);
                    acc_store.all_txs.remove(txid);
                    acc_store.heights.remove(txid);
                    all_valid = false;
                    break;
                }
            }
        }
        if !all_valid {
            store_write.flush()?;
        }
        Ok(all_valid)
    }
}

/// Return the last (if any) and next account numbers for the given script type
pub fn get_last_next_account_nums(
    existing: HashSet<u32>,
    script_type: ScriptType,
) -> (Option<u32>, u32) {
    let first_account_num = script_type.first_account_num();
    let last_account = (first_account_num..)
        .step_by(NUM_RESERVED_ACCOUNT_TYPES as usize)
        .take_while(|n| existing.contains(n))
        .last();
    let next_account =
        last_account.map_or(first_account_num, |last| last + NUM_RESERVED_ACCOUNT_TYPES);
    (last_account, next_account)
}

pub fn get_account_script_purpose(account_num: u32) -> Result<(ScriptType, u32), Error> {
    Ok(match account_num % NUM_RESERVED_ACCOUNT_TYPES {
        0 => (ScriptType::P2shP2wpkh, 49),
        1 => (ScriptType::P2wpkh, 84),
        2 => (ScriptType::P2pkh, 44),
        _ => return Err(Error::InvalidSubaccount(account_num)),
    })
}

fn get_account_derivation(
    account_num: u32,
    network_id: NetworkId,
) -> Result<(ScriptType, DerivationPath), Error> {
    let coin_type = get_coin_type(network_id);
    let (script_type, purpose) = get_account_script_purpose(account_num)?;
    let bip32_account_num = account_num / NUM_RESERVED_ACCOUNT_TYPES;

    // BIP44: m / purpose' / coin_type' / account' / change / address_index
    let path: DerivationPath =
        format!("m/{}'/{}'/{}'", purpose, coin_type, bip32_account_num).parse().unwrap();

    info!("derivation path for account {}: {}", account_num, path);

    Ok((script_type, path))
}

fn get_coin_type(network_id: NetworkId) -> u32 {
    // coin_type = 0 bitcoin, 1 testnet, 1776 liquid bitcoin as defined in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
    // slip44 suggest 1 for every testnet, so we are using it also for regtest
    match network_id {
        NetworkId::Bitcoin(bitcoin_network) => match bitcoin_network {
            bitcoin::Network::Bitcoin => 0,
            bitcoin::Network::Testnet => 1,
            bitcoin::Network::Regtest => 1,
            bitcoin::Network::Signet => 1,
        },
        NetworkId::Elements(elements_network) => match elements_network {
            ElementsNetwork::Liquid => 1776,
            ElementsNetwork::LiquidTestnet => 1,
            ElementsNetwork::ElementsRegtest => 1,
        },
    }
}

fn derive_address(
    xpub: &ExtendedPubKey,
    index: u32,
    script_type: ScriptType,
    network_id: NetworkId,
    master_blinding: Option<&MasterBlindingKey>,
) -> Result<BEAddress, Error> {
    let child_key = xpub.ckd_pub(&EC, index.into())?;
    match network_id {
        NetworkId::Bitcoin(network) => {
            let address = bitcoin_address(&child_key.public_key, script_type, network);
            Ok(BEAddress::Bitcoin(address))
        }
        NetworkId::Elements(network) => {
            let address = elements_address(
                &child_key.public_key,
                master_blinding.expect("we are in elements but master blinding is None"),
                script_type,
                network,
            );
            Ok(BEAddress::Elements(address))
        }
    }
}

fn bitcoin_address(
    public_key: &PublicKey,
    script_type: ScriptType,
    net: bitcoin::Network,
) -> bitcoin::Address {
    use bitcoin::Address;
    match script_type {
        ScriptType::P2shP2wpkh => Address::p2shwpkh(public_key, net).expect("no compressed keys"),
        ScriptType::P2wpkh => Address::p2wpkh(public_key, net).expect("no compressed keys"),
        ScriptType::P2pkh => Address::p2pkh(public_key, net),
    }
}

fn elements_address(
    public_key: &PublicKey,
    master_blinding_key: &MasterBlindingKey,
    script_type: ScriptType,
    net: ElementsNetwork,
) -> elements::Address {
    let addr_params = net.address_params();
    let address = match script_type {
        ScriptType::P2pkh => elements::Address::p2pkh(public_key, None, addr_params),
        ScriptType::P2shP2wpkh => elements::Address::p2shwpkh(public_key, None, addr_params),
        ScriptType::P2wpkh => elements::Address::p2wpkh(public_key, None, addr_params),
    };
    let script_pubkey = address.script_pubkey();
    let blinding_prv = asset_blinding_key_to_ec_private_key(master_blinding_key, &script_pubkey);
    let blinding_pub = ec_public_key_from_private_key(blinding_prv);
    address.to_confidential(blinding_pub)
}

// Discover all the available accounts as per BIP 44:
// https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki#Account_discovery
pub fn discover_accounts(
    master_xprv: &ExtendedPrivKey,
    network_id: NetworkId,
    electrum_url: &ElectrumUrl,
    proxy: Option<&str>,
    master_blinding: Option<&MasterBlindingKey>,
) -> Result<Vec<u32>, Error> {
    use electrum_client::ElectrumApi;

    // build our own client so that the subscriptions are dropped at the end
    let client = electrum_url.build_client(proxy)?;

    // the batch size is the effective gap limit for our purposes. in reality it is a lower bound.
    let gap_limit = BATCH_SIZE;
    let num_types = NUM_RESERVED_ACCOUNT_TYPES as usize;
    let mut discovered_accounts: Vec<u32> = vec![];

    for script_type in ScriptType::types() {
        debug!("discovering script type {:?}", script_type);
        'next_account: for account_num in (script_type.first_account_num()..).step_by(num_types) {
            let (_, path) = get_account_derivation(account_num, network_id).unwrap();
            let recv_xprv = master_xprv.derive_priv(&EC, &path.child(0.into()))?;
            let recv_xpub = ExtendedPubKey::from_private(&EC, &recv_xprv);
            for child_code in 0..gap_limit {
                let script = derive_address(
                    &recv_xpub,
                    child_code,
                    *script_type,
                    network_id,
                    master_blinding,
                )
                .unwrap()
                .script_pubkey();
                if client.script_subscribe(&script.into_bitcoin())?.is_some() {
                    debug!("found account {:?} #{}", script_type, account_num);
                    discovered_accounts.push(account_num);
                    continue 'next_account;
                }
            }
            debug!("no activity found for account {:?} #{}", script_type, account_num);
            break;
        }
    }
    info!("discovered accounts: {:?}", discovered_accounts);

    Ok(discovered_accounts)
}

#[allow(clippy::cognitive_complexity)]
pub fn create_tx(
    account: &Account,
    request: &mut CreateTransaction,
) -> Result<TransactionMeta, Error> {
    info!("create_tx {:?}", request);

    let network = &account.network;

    let default_min_fee_rate = match network.id() {
        NetworkId::Bitcoin(_) => 1000,
        NetworkId::Elements(_) => 100,
    };
    let fee_rate_sat_kb = request.fee_rate.get_or_insert(default_min_fee_rate);
    if *fee_rate_sat_kb < default_min_fee_rate {
        return Err(Error::FeeRateBelowMinimum);
    }

    // convert from satoshi/kbyte to satoshi/byte
    let fee_rate = (*fee_rate_sat_kb as f64) / 1000.0;
    info!("target fee_rate {:?} satoshi/byte", fee_rate);

    let taproot_enabled_at = network.taproot_enabled_at.unwrap_or(u32::MAX);
    let mut tip_height: Option<u32> = if taproot_enabled_at == 0 {
        // no need to get tip
        Some(0)
    } else {
        // will get tip_height if needed
        None
    };

    // TODO put checks into CreateTransaction::validate, add check asset_id are valid asset hex
    // eagerly check for address validity
    for address in request.addressees.iter().map(|a| &a.address) {
        match network.id() {
            NetworkId::Bitcoin(network) => {
                if let Ok(address) = bitcoin::Address::from_str(address) {
                    info!("address.network:{} network:{}", address.network, network);
                    if address.network == network
                        || (address.network == bitcoin::Network::Testnet
                            && network == bitcoin::Network::Regtest)
                    {
                        // FIXME: use address.is_standard() once rust-bitcoin has P2tr variant
                        if let Payload::WitnessProgram {
                            version: v,
                            program: p,
                        } = &address.payload
                        {
                            // Do not support segwit greater than v1 and non-P2TR v1
                            if v.to_u8() > 1 || (v.to_u8() == 1 && p.len() != 32) {
                                return Err(Error::InvalidAddress);
                            }
                            if v.to_u8() == 1 {
                                let tip = match tip_height {
                                    Some(h) => h,
                                    None => {
                                        let tip = account.store.read()?.cache.tip.0;
                                        tip_height = Some(tip);
                                        tip
                                    }
                                };
                                if tip < taproot_enabled_at {
                                    return Err(Error::Generic(
                                        "Taproot has not yet activated on this network".into(),
                                    ));
                                }
                            }
                        }
                        continue;
                    }
                }
                return Err(Error::InvalidAddress);
            }
            NetworkId::Elements(network) => {
                if let Ok(address) =
                    elements::Address::parse_with_params(address, network.address_params())
                {
                    if !address.is_blinded() {
                        return Err(Error::NonConfidentialAddress);
                    }
                } else {
                    return Err(Error::InvalidAddress);
                }
            }
        }
    }

    let send_all = request.send_all;
    if !send_all && request.addressees.iter().any(|a| a.satoshi == 0) {
        return Err(Error::InvalidAmount);
    }

    let mut template_tx = None;
    let mut change_addresses = vec![];

    // When a previous transaction is replaced, use it as a template for the new transaction
    if let Some(ref prev_txitem) = request.previous_transaction {
        if send_all || network.liquid {
            return Err(Error::InvalidReplacementRequest);
        }

        let prev_tx = BETransaction::from_hex(&prev_txitem.transaction, network.id())?;

        let store_read = account.store.read()?;
        let acc_store = store_read.account_cache(account.num())?;

        // Strip the mining fee change output from the transaction, keeping the change address for reuse
        template_tx = Some(prev_tx.filter_outputs(&acc_store.unblinded, |vout, script, asset| {
            if asset == None && account.get_wallet_chain_type(&script) == Some(1) {
                let change_address = prev_tx
                    .output_address(vout, network.id())
                    .expect("own change addresses to have address representation");
                change_addresses.push(change_address);
                false
            } else {
                true
            }
        }));

        if let (Some(BETransaction::Bitcoin(tx)), NetworkId::Bitcoin(net)) =
            (&template_tx, network.id())
        {
            request.addressees = tx
                .output
                .iter()
                .filter_map(|o| {
                    Some(AddressAmount {
                        address: bitcoin::Address::from_script(&o.script_pubkey, net)?.to_string(),
                        satoshi: o.value,
                        asset_id: None,
                    })
                })
                .collect();
        } else {
            return Err(Error::InvalidReplacementRequest);
        }

        // Keep the previous transaction memo
        if request.memo.is_none() && !prev_txitem.memo.is_empty() {
            request.memo = Some(prev_txitem.memo.clone());
        }
    } else {
        if request.addressees.is_empty() {
            return Err(Error::EmptyAddressees);
        }

        if !send_all && request.addressees.iter().any(|a| a.satoshi == 0) {
            return Err(Error::InvalidAmount);
        }

        if !send_all {
            for address_amount in request.addressees.iter() {
                if address_amount.satoshi <= DUST_VALUE {
                    match network.id() {
                        NetworkId::Bitcoin(_) => return Err(Error::InvalidAmount),
                        NetworkId::Elements(_) => {
                            if address_amount.asset_id == network.policy_asset {
                                // we apply dust rules for liquid bitcoin as elements do
                                return Err(Error::InvalidAmount);
                            }
                        }
                    }
                }
            }
        }

        if let NetworkId::Elements(_) = network.id() {
            if request.addressees.iter().any(|a| a.asset_id.is_none()) {
                return Err(Error::AssetEmpty);
            }
        }
    }

    let mut utxos: Utxos = (&request.utxos).try_into()?;
    if request.confidential_utxos_only {
        utxos.retain(|(_, i)| i.confidential);
    }
    info!("utxos len:{} utxos:{:?}", utxos.len(), utxos);

    if send_all {
        // send_all works by creating a dummy tx with all utxos, estimate the fee and set the
        // sending amount to `total_amount_utxos - estimated_fee`
        info!("send_all calculating total_amount");
        if request.addressees.len() != 1 {
            return Err(Error::SendAll);
        }
        let asset = request.addressees[0].asset_id();
        let all_utxos: Vec<&(BEOutPoint, UTXOInfo)> =
            utxos.iter().filter(|(_, i)| i.asset_id() == asset).collect();
        let total_amount_utxos: u64 = all_utxos.iter().map(|(_, i)| i.value).sum();

        let to_send = if asset == network.policy_asset_id().ok() {
            let mut dummy_tx = BETransaction::new(network.id());
            for utxo in all_utxos.iter() {
                dummy_tx.add_input(utxo.0.clone());
            }
            let out = &request.addressees[0]; // safe because we checked we have exactly one recipient
            dummy_tx
                .add_output(&out.address, out.satoshi, out.asset_id(), network.id())
                .map_err(|_| Error::InvalidAddress)?;
            // estimating 2 satoshi more as estimating less would later result in InsufficientFunds
            let estimated_fee = dummy_tx.estimated_fee(fee_rate, 0, account.script_type) + 2;
            total_amount_utxos.checked_sub(estimated_fee).ok_or_else(|| Error::InsufficientFunds)?
        } else {
            total_amount_utxos
        };

        info!("send_all asset: {:?} to_send:{}", asset, to_send);

        request.addressees[0].satoshi = to_send;
    }

    // transaction is created in 3 steps:
    // 1) adding requested outputs to tx outputs, or using the replaced transaction template
    // 2) adding enough utxso to inputs such that tx outputs and estimated fees are covered
    // 3) adding change(s)

    // STEP 1) add the requested outputs for newly created transactions,
    //         or start with the replaced transaction (minus change) as a template
    let mut tx = template_tx.map_or_else(
        || -> Result<_, Error> {
            let mut new_tx = BETransaction::new(network.id());
            for out in request.addressees.iter() {
                new_tx
                    .add_output(&out.address, out.satoshi, out.asset_id(), network.id())
                    .map_err(|_| Error::InvalidAddress)?;
            }
            Ok(new_tx)
        },
        Ok,
    )?;

    // STEP 2) add utxos until tx outputs are covered (including fees) or fail
    let store_read = account.store.read()?;
    let acc_store = store_read.account_cache(account.num())?;
    match request.utxo_strategy {
        UtxoStrategy::Default => {
            let mut used_utxo: HashSet<BEOutPoint> = HashSet::new();
            loop {
                let mut needs = tx.needs(
                    fee_rate,
                    send_all,
                    network.policy_asset_id().ok(),
                    &acc_store.all_txs,
                    &acc_store.unblinded,
                    account.script_type,
                ); // "policy asset" is last, in bitcoin max 1 element
                info!("needs: {:?}", needs);
                if needs.is_empty() {
                    // SUCCESS tx doesn't need other inputs
                    break;
                }
                let current_need = needs.pop().unwrap(); // safe to unwrap just checked it's not empty

                // taking only utxos of current asset considered, filters also utxos used in this loop
                let mut asset_utxos: Vec<&(BEOutPoint, UTXOInfo)> = utxos
                    .iter()
                    .filter(|(o, i)| i.asset_id() == current_need.asset && !used_utxo.contains(o))
                    .collect();

                // sort by biggest utxo, random maybe another option, but it should be deterministically random (purely random breaks send_all algorithm)
                asset_utxos.sort_by(|a, b| (a.1).value.cmp(&(b.1).value));
                let utxo = asset_utxos.pop().ok_or(Error::InsufficientFunds)?;

                match network.id() {
                    NetworkId::Bitcoin(_) => {
                        // UTXO with same script must be spent together
                        for other_utxo in utxos.iter() {
                            if (other_utxo.1).script == (utxo.1).script {
                                used_utxo.insert(other_utxo.0.clone());
                                tx.add_input(other_utxo.0.clone());
                            }
                        }
                    }
                    NetworkId::Elements(_) => {
                        // Don't spend same script together in liquid. This would allow an attacker
                        // to cheaply send assets without value to the target, which will have to
                        // waste fees for the extra tx inputs and (eventually) outputs.
                        // While blinded address are required and not public knowledge,
                        // they are still available to whom transacted with us in the past
                        used_utxo.insert(utxo.0.clone());
                        tx.add_input(utxo.0.clone());
                    }
                }
            }
        }
        UtxoStrategy::Manual => {
            for utxo in utxos.iter() {
                tx.add_input(utxo.0.clone());
            }
            let needs = tx.needs(
                fee_rate,
                send_all,
                network.policy_asset_id().ok(),
                &acc_store.all_txs,
                &acc_store.unblinded,
                account.script_type,
            );
            if !needs.is_empty() {
                return Err(Error::InsufficientFunds);
            }
        }
    }

    // STEP 3) adding change(s)
    let estimated_fee = tx.estimated_fee(
        fee_rate,
        tx.estimated_changes(send_all, &acc_store.all_txs, &acc_store.unblinded),
        account.script_type,
    );
    let changes = tx.changes(
        estimated_fee,
        network.policy_asset_id().ok(),
        &acc_store.all_txs,
        &acc_store.unblinded,
    ); // Vec<Change> asset, value
    for (i, change) in changes.iter().enumerate() {
        let change_address = change_addresses.pop().map_or_else(
            || -> Result<_, Error> {
                let change_index = acc_store.indexes.internal + i as u32 + 1;
                Ok(account.derive_address(true, change_index)?.to_string())
            },
            Ok,
        )?;
        info!(
            "adding change to {} of {} asset {:?}",
            &change_address, change.satoshi, change.asset
        );
        tx.add_output(&change_address, change.satoshi, change.asset, network.id())?;
    }

    // randomize inputs and outputs, BIP69 has been rejected because lacks wallets adoption
    tx.scramble();

    let policy_asset = network.policy_asset_id().ok();
    // recompute exact fee_val from built tx
    let fee_val = tx.fee(&acc_store.all_txs, &acc_store.unblinded, &policy_asset)?;
    tx.add_fee_if_elements(fee_val, &policy_asset)?;

    info!("created tx fee {:?}", fee_val);

    let mut satoshi =
        tx.my_balance_changes(&acc_store.all_txs, &acc_store.paths, &acc_store.unblinded);

    for (_, v) in satoshi.iter_mut() {
        *v = v.abs();
    }

    let mut created_tx = TransactionMeta::new(
        tx,
        None,
        None,
        satoshi,
        fee_val,
        network.id().get_bitcoin_network().unwrap_or(bitcoin::Network::Bitcoin),
        "outgoing".to_string(),
        request.clone(),
        false,
        SPVVerifyResult::InProgress,
    );
    created_tx.changes_used = Some(changes.len() as u32);
    created_tx.addressees_read_only = request.previous_transaction.is_some();
    info!("returning: {:?}", created_tx);

    Ok(created_tx)
}

fn internal_sign_bitcoin(
    tx: &bitcoin::Transaction,
    input_index: usize,
    xprv: &ExtendedPrivKey,
    path: &DerivationPath,
    value: u64,
    script_type: ScriptType,
) -> (bitcoin::Script, Vec<Vec<u8>>) {
    let xprv = xprv.derive_priv(&EC, &path).unwrap();
    let private_key = &xprv.private_key;
    let public_key = &PublicKey::from_private_key(&EC, private_key);
    let script_code = p2pkh_script(public_key);

    let hash = if script_type.is_segwit() {
        SigHashCache::new(tx).signature_hash(input_index, &script_code, value, SigHashType::All)
    } else {
        tx.signature_hash(input_index, &script_code, SigHashType::All as u32)
    };

    let message = Message::from_slice(&hash.into_inner()[..]).unwrap();
    let signature = EC.sign(&message, &private_key.key);

    let mut signature = signature.serialize_der().to_vec();
    signature.push(SigHashType::All as u8);

    prepare_input(&public_key, signature, script_type)
}

fn internal_sign_elements(
    tx: &elements::Transaction,
    input_index: usize,
    xprv: &ExtendedPrivKey,
    path: &DerivationPath,
    value: Value,
    script_type: ScriptType,
) -> (elements::Script, Vec<Vec<u8>>) {
    let xprv = xprv.derive_priv(&EC, &path).unwrap();
    let private_key = &xprv.private_key;
    let public_key = &PublicKey::from_private_key(&EC, private_key);

    let script_code = p2pkh_script(public_key).into_elements();
    let sighash = if script_type.is_segwit() {
        elements::sighash::SigHashCache::new(tx).segwitv0_sighash(
            input_index,
            &script_code,
            value,
            elements::SigHashType::All,
        )
    } else {
        elements::sighash::SigHashCache::new(tx).legacy_sighash(
            input_index,
            &script_code,
            elements::SigHashType::All,
        )
    };
    let message = secp256k1::Message::from_slice(&sighash[..]).unwrap();
    let signature = EC.sign(&message, &private_key.key);
    let mut signature = signature.serialize_der().to_vec();
    signature.push(SigHashType::All as u8);

    let (script_sig, witness) = prepare_input(&public_key, signature, script_type);
    (script_sig.into_elements(), witness)
}

// Get the input's script sig and witness data
fn prepare_input(
    public_key: &PublicKey,
    signature: Vec<u8>,
    script_type: ScriptType,
) -> (bitcoin::Script, Vec<Vec<u8>>) {
    let pk = public_key.to_bytes();

    match script_type {
        ScriptType::P2shP2wpkh => (p2shwpkh_script_sig(public_key), vec![signature, pk]),
        ScriptType::P2wpkh => (bitcoin::Script::new(), vec![signature, pk]),
        ScriptType::P2pkh => (
            script::Builder::new()
                .push_slice(signature.as_slice())
                .push_slice(pk.as_slice())
                .into_script(),
            vec![],
        ),
    }
}

fn blind_tx(account: &Account, tx: &elements::Transaction) -> Result<elements::Transaction, Error> {
    info!("blind_tx {}", tx.txid());

    let store_read = account.store.read()?;
    let acc_store = store_read.account_cache(account.num())?;

    let mut pset = elements::pset::PartiallySignedTransaction::from_tx(tx.clone());
    let mut inp_txout_sec: Vec<Option<elements::TxOutSecrets>> = vec![];

    for input in pset.inputs.iter_mut() {
        let previous_output =
            elements::OutPoint::new(input.previous_txid, input.previous_output_index);
        let unblinded = acc_store
            .unblinded
            .get(&previous_output)
            .ok_or_else(|| Error::Generic("cannot find unblinded values".into()))?;

        inp_txout_sec.push(Some(unblinded.clone()));

        let prev_tx = acc_store.get_liquid_tx(&input.previous_txid)?;
        let txout = prev_tx.output[input.previous_output_index as usize].clone();
        input.witness_utxo = Some(txout);
    }
    for output in pset.outputs.iter_mut() {
        // We are the owner of all inputs and outputs
        output.blinder_index = Some(0);
    }

    let inp_txout_sec: Vec<_> = inp_txout_sec.iter().map(|e| e.as_ref()).collect();
    pset.blind_last(&mut rand::thread_rng(), &EC, &inp_txout_sec[..])?;
    pset.extract_tx().map_err(Into::into)
}

#[cfg(test)]
mod test {
    use super::*;

    const NETWORK: NetworkId = NetworkId::Bitcoin(bitcoin::Network::Regtest);

    fn test_derivation(account_num: u32, expected_type: ScriptType, expected_path: &str) {
        let (script_type, path) = get_account_derivation(account_num, NETWORK).unwrap();
        assert_eq!(script_type, expected_type);
        assert_eq!(path, DerivationPath::from_str(expected_path).unwrap());
    }

    fn test_derivation_fails(account_num: u32) {
        assert!(get_account_derivation(account_num, NETWORK).is_err());
    }

    #[test]
    fn account_derivation() {
        test_derivation(0, ScriptType::P2shP2wpkh, "m/49'/1'/0'");
        test_derivation(1, ScriptType::P2wpkh, "m/84'/1'/0'");
        test_derivation(2, ScriptType::P2pkh, "m/44'/1'/0'");

        // reserved for future use, currently rejected
        for n in 3..=15 {
            test_derivation_fails(n);
        }

        test_derivation(16, ScriptType::P2shP2wpkh, "m/49'/1'/1'");
        test_derivation(17, ScriptType::P2wpkh, "m/84'/1'/1'");
        test_derivation(18, ScriptType::P2pkh, "m/44'/1'/1'");
        test_derivation_fails(19);

        test_derivation(160, ScriptType::P2shP2wpkh, "m/49'/1'/10'");
        test_derivation(161, ScriptType::P2wpkh, "m/84'/1'/10'");
        test_derivation(162, ScriptType::P2pkh, "m/44'/1'/10'");
    }
}
