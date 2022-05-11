use std::cmp::Ordering;
use std::collections::HashSet;
use std::convert::TryInto;
use std::str::FromStr;

use log::{info, warn};

use bitcoin::blockdata::script;
use bitcoin::hashes::hex::{FromHex, ToHex};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, Message};
use bitcoin::util::address::Payload;
use bitcoin::util::bip143::SigHashCache;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{PublicKey, SigHashType};
use elements::confidential::Value;

use gdk_common::be::{
    BEAddress, BEOutPoint, BEScript, BEScriptConvert, BETransaction, BETxid, ScriptBatch,
    DUST_VALUE,
};
use gdk_common::error::fn_err;
use gdk_common::model::{
    parse_path, AccountInfo, AddressAmount, AddressPointer, CreateTransaction, GetTransactionsOpt,
    GetTxInOut, SPVVerifyTxResult, TransactionMeta, TransactionOutput, TxListItem, Txo,
    UnspentOutput, UpdateAccountOpt, UtxoStrategy,
};
use gdk_common::scripts::{p2pkh_script, p2shwpkh_script_sig, ScriptType};
use gdk_common::util::{now, weight_to_vsize};
use gdk_common::wally::{
    asset_blinding_key_to_ec_private_key, ec_public_key_from_private_key, MasterBlindingKey,
};
use gdk_common::{ElementsNetwork, NetworkId, NetworkParameters};

use crate::error::Error;
use crate::interface::ElectrumUrl;
use crate::store::{Store, BATCH_SIZE};

// The number of account types, including these reserved for future use.
// Currently only 3 are used: P2SH-P2WPKH, P2WPKH and P2PKH
const NUM_RESERVED_ACCOUNT_TYPES: u32 = 16;

#[derive(Clone)]
pub struct Account {
    account_num: u32,
    script_type: ScriptType,

    /// The account extended private key
    ///
    /// This fields will be removed once we have full support for external signers.
    /// For the time being, if it is None, the xpub cannot be verified and
    /// `Account::sign` will always fail.
    xprv: Option<ExtendedPrivKey>,
    xpub: ExtendedPubKey,
    chains: [ExtendedPubKey; 2],
    network: NetworkParameters,
    store: Store,
    // elements only
    master_blinding: Option<MasterBlindingKey>,

    path: DerivationPath,
}

/// Compare xpub ignoring the fingerprint (which computation might be skipped),
/// depth and child_number (which might not be set correctly by some signers).
pub fn xpubs_equivalent(xpub1: &ExtendedPubKey, xpub2: &ExtendedPubKey) -> Result<(), Error> {
    if !(xpub1.network == xpub2.network
        && xpub1.public_key == xpub2.public_key
        && xpub1.chain_code == xpub2.chain_code)
    {
        return Err(Error::MismatchingXpubs(xpub1.clone(), xpub2.clone()));
    }
    Ok(())
}

impl Account {
    pub fn new(
        network: NetworkParameters,
        master_xprv: &Option<ExtendedPrivKey>,
        account_xpub: &Option<ExtendedPubKey>,
        master_blinding: Option<MasterBlindingKey>,
        store: Store,
        account_num: u32,
        discovered: bool,
    ) -> Result<Self, Error> {
        let (script_type, path) = get_account_derivation(account_num, network.id())?;

        let (xprv, xpub) = if let Some(master_xprv) = master_xprv {
            let xprv = master_xprv.derive_priv(&crate::EC, &path)?;
            let xpub = ExtendedPubKey::from_private(&crate::EC, &xprv);
            if let Some(account_xpub) = account_xpub {
                xpubs_equivalent(&xpub, account_xpub)?;
            };
            (Some(xprv), xpub)
        } else {
            if let Some(xpub) = account_xpub {
                (None, xpub.clone())
            } else {
                return Err(Error::Generic(
                    "Account::new: either master_xprv or account_xpub must be Some".to_string(),
                ));
            }
        };

        // cache internal/external chains
        let chains = [xpub.ckd_pub(&crate::EC, 0.into())?, xpub.ckd_pub(&crate::EC, 1.into())?];

        store.write().unwrap().make_account(account_num, xpub.clone(), discovered)?;

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
            path,
        })
    }

    pub fn num(&self) -> u32 {
        self.account_num
    }

    /// Get the full path from the master key to address index
    ///
    /// //  <                        full path                       >
    /// m / purpose' / coin_type ' / account' / change / address_index
    /// //                                      <    account path    >
    ///
    fn get_full_path(&self, account_path: &DerivationPath) -> DerivationPath {
        self.path.extend(account_path)
    }

    pub fn info(&self) -> Result<AccountInfo, Error> {
        let settings = self.store.read()?.get_account_settings(self.account_num).cloned();

        Ok(AccountInfo {
            account_num: self.account_num,
            script_type: self.script_type,
            settings: settings.unwrap_or_default(),
            required_ca: 0,
            receiving_id: "".to_string(),
            bip44_discovered: self.has_transactions()?,
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
        let account_path = DerivationPath::from(&[0.into(), pointer.into()][..]); // 0 is external
        let user_path = self.get_full_path(&account_path);
        let address = self.derive_address(false, pointer)?.to_string();
        Ok(AddressPointer {
            address,
            pointer,
            user_path: user_path.into(),
        })
    }

    pub fn list_tx(&self, opt: &GetTransactionsOpt) -> Result<Vec<TxListItem>, Error> {
        let store = self.store.read()?;
        let acc_store = store.account_cache(self.account_num)?;

        let tip_height = store.cache.tip_height();
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
            let txe = acc_store
                .all_txs
                .get(*tx_id)
                .ok_or_else(fn_err(&format!("list_tx no tx {}", tx_id)))?;
            let tx = &txe.tx;

            let timestamp = height
                .map(|h| store.cache.headers.get(&h))
                .flatten()
                .map(|h| 1_000_000u64.saturating_mul(h.time() as u64))
                .unwrap_or_else(now); // in microseconds

            let mut addressees = vec![];
            for i in 0..tx.output_len() as u32 {
                let script = tx.output_script(i);
                if !script.is_empty() && !acc_store.paths.contains_key(&script) {
                    if let Some(address) = tx.output_address(i, self.network.id()) {
                        addressees.push(address);
                    };
                }
            }

            let memo = store.get_memo(tx_id).cloned().unwrap_or("".to_string());

            let fee = tx.fee(
                &acc_store.all_txs,
                &acc_store.unblinded,
                &self.network.policy_asset_id().ok(),
            )?;

            let fee_rate = txe.fee_rate(fee);

            let satoshi =
                tx.my_balance_changes(&acc_store.all_txs, &acc_store.paths, &acc_store.unblinded);

            let is_redeposit = tx.is_redeposit(&acc_store.paths, &acc_store.all_txs);
            let type_ = tx.type_(&satoshi, is_redeposit);
            let user_signed = type_.user_signed();

            let spv_verified = if self.network.spv_enabled.unwrap_or(false) {
                store.spv_verification_status(self.num(), tx_id)
            } else {
                SPVVerifyTxResult::Disabled
            };

            let rbf_optin = tx.rbf_optin();
            let can_rbf = height.is_none() && rbf_optin && user_signed;

            let inputs = tx
                .previous_outputs()
                .iter()
                .enumerate()
                .map(|(vin, beoutpoint)| {
                    let (is_relevant, is_internal, pointer) = {
                        if let Some(script) =
                            acc_store.all_txs.get_previous_output_script_pubkey(beoutpoint)
                        {
                            match acc_store.paths.get(&script) {
                                None => (false, false, 0),
                                Some(path) => {
                                    let (is_internal, pointer) = parse_path(&path)?;
                                    (true, is_internal, pointer)
                                }
                            }
                        } else {
                            (false, false, 0)
                        }
                    };

                    let (subaccount, address_type) = if is_relevant {
                        (self.account_num, self.script_type.to_string())
                    } else {
                        (0, "".to_string())
                    };

                    let address = acc_store
                        .all_txs
                        .get_previous_output_address(beoutpoint, self.network.id())
                        .unwrap_or_else(|| "".to_string());

                    let satoshi = acc_store
                        .all_txs
                        .get_previous_output_value(beoutpoint, &acc_store.unblinded)
                        .unwrap_or(0);

                    let (asset_id, asset_blinder, amount_blinder) = {
                        if let BEOutPoint::Elements(outpoint) = beoutpoint {
                            (
                                acc_store
                                    .all_txs
                                    .get_previous_output_asset(*outpoint, &acc_store.unblinded)
                                    .map(|a| a.to_hex()),
                                acc_store.all_txs.get_previous_output_assetblinder_hex(
                                    *outpoint,
                                    &acc_store.unblinded,
                                ),
                                acc_store.all_txs.get_previous_output_amountblinder_hex(
                                    *outpoint,
                                    &acc_store.unblinded,
                                ),
                            )
                        } else {
                            (None, None, None)
                        }
                    };

                    Ok(GetTxInOut {
                        addressee: "".to_string(),
                        is_output: false,
                        is_spent: true,
                        pt_idx: vin as u32,
                        script_type: 0,
                        subtype: 0,
                        is_relevant,
                        is_internal,
                        pointer,
                        subaccount,
                        address_type,
                        address,
                        satoshi,
                        asset_id,
                        asset_blinder,
                        amount_blinder,
                    })
                })
                .collect::<Result<Vec<GetTxInOut>, Error>>()?;

            let outputs = (0..tx.output_len() as u32)
                .map(|vout| {
                    let (is_relevant, is_internal, pointer) = {
                        match acc_store.paths.get(&tx.output_script(vout)) {
                            None => (false, false, 0),
                            Some(path) => {
                                let (is_internal, pointer) = parse_path(&path)?;
                                (true, is_internal, pointer)
                            }
                        }
                    };

                    let (subaccount, address_type) = if is_relevant {
                        (self.account_num, self.script_type.to_string())
                    } else {
                        (0, "".to_string())
                    };

                    let address = tx
                        .output_address(vout, self.network.id())
                        .unwrap_or_else(|| "".to_string());
                    let satoshi = tx.output_value(vout, &acc_store.unblinded).unwrap_or(0);
                    let asset_id = tx.output_asset(vout, &acc_store.unblinded).map(|a| a.to_hex());
                    let asset_blinder = tx.output_assetblinder_hex(vout, &acc_store.unblinded);
                    let amount_blinder = tx.output_amountblinder_hex(vout, &acc_store.unblinded);

                    Ok(GetTxInOut {
                        addressee: "".to_string(),
                        is_output: true,
                        // FIXME: this can be wrong, however setting this value correctly might be quite
                        // expensive: involing db hits and potentially network calls; postponing it for now.
                        is_spent: false,
                        pt_idx: vout,
                        script_type: 0,
                        subtype: 0,
                        is_relevant,
                        is_internal,
                        pointer,
                        subaccount,
                        address_type,
                        address,
                        satoshi,
                        asset_id,
                        asset_blinder,
                        amount_blinder,
                    })
                })
                .collect::<Result<Vec<GetTxInOut>, Error>>()?;

            txs.push(TxListItem {
                block_height: height.unwrap_or(0),
                created_at_ts: timestamp,
                type_,
                memo,
                txhash: tx_id.to_string(),
                satoshi,
                rbf_optin,
                can_cpfp: false,
                can_rbf,
                server_signed: false,
                user_signed,
                spv_verified: spv_verified.to_string(),
                fee,
                fee_rate,
                addressees,
                inputs,
                outputs,
                transaction_size: txe.size,
                transaction_vsize: weight_to_vsize(txe.weight),
                transaction_weight: txe.weight,
            });
        }
        info!("list_tx {:?}", txs.iter().map(|e| &e.txhash).collect::<Vec<&String>>());

        Ok(txs)
    }

    pub fn public_key(&self, path: &DerivationPath) -> PublicKey {
        let xpub = self.xpub.derive_pub(&crate::EC, path).unwrap();
        xpub.public_key
    }

    pub fn script_code(&self, path: &DerivationPath) -> BEScript {
        let public_key = self.public_key(path);
        // script code is the same for the currently supported script type
        p2pkh_script(&public_key).into()
    }

    pub fn tx_outputs(&self, tx: &BETransaction) -> Result<Vec<TransactionOutput>, Error> {
        let store_read = self.store.read()?;
        let acc_store = store_read.account_cache(self.account_num)?;
        let mut tx_outputs = vec![];
        for vout in 0..tx.output_len() as u32 {
            let address = tx.output_address(vout, self.network.id()).unwrap_or_default();
            let satoshi = tx.output_value(vout, &acc_store.unblinded).unwrap_or_default();
            let script_pubkey = tx.output_script(vout);
            tx_outputs.push(match acc_store.paths.get(&script_pubkey) {
                None => TransactionOutput {
                    address,
                    satoshi,
                    address_type: "".into(),
                    is_relevant: false,
                    is_change: false,
                    subaccount: self.account_num,
                    is_internal: false,
                    pointer: 0,
                    pt_idx: vout,
                    script_pubkey: script_pubkey.to_hex(),
                    user_path: vec![],
                },
                Some(account_path) => {
                    let (is_internal, pointer) = parse_path(&account_path)?;
                    TransactionOutput {
                        address,
                        satoshi,
                        address_type: self.script_type.to_string(),
                        is_relevant: true,
                        subaccount: self.account_num,
                        is_internal,
                        is_change: is_internal,
                        pointer,
                        pt_idx: vout,
                        script_pubkey: script_pubkey.to_hex(),
                        user_path: self.get_full_path(&account_path).into(),
                    }
                }
            });
        }
        Ok(tx_outputs)
    }

    pub fn txo(&self, outpoint: &BEOutPoint) -> Result<Txo, Error> {
        let vout = outpoint.vout();
        let txid = outpoint.txid();

        let store_read = self.store.read()?;
        let acc_store = store_read.account_cache(self.account_num)?;

        let txe = acc_store.all_txs.get(&txid).ok_or_else(|| Error::TxNotFound(txid))?;
        let tx = &txe.tx;
        let height = acc_store.heights.get(&txid).cloned().flatten();
        let script_pubkey = tx.output_script(vout);
        let account_path = acc_store.get_path(&script_pubkey)?;
        let satoshi = tx.output_value(vout, &acc_store.unblinded).unwrap_or_default();
        let txoutsecrets = match outpoint {
            BEOutPoint::Bitcoin(_) => None,
            BEOutPoint::Elements(o) => acc_store.unblinded.get(&o).cloned(),
        };

        let txoutcommitments = match tx {
            BETransaction::Bitcoin(_) => None,
            BETransaction::Elements(tx) => {
                let txout = &tx.output[vout as usize];
                Some((txout.asset, txout.value, txout.nonce))
            }
        };

        Ok(Txo {
            outpoint: outpoint.clone(),
            height,

            public_key: self.public_key(&account_path),
            script_pubkey,
            script_code: self.script_code(&account_path),

            subaccount: self.account_num,
            script_type: self.script_type.clone(),

            user_path: self.get_full_path(&account_path).into(),

            satoshi,
            sequence: None,
            txoutsecrets,
            txoutcommitments,
        })
    }

    pub fn used_utxos(&self, tx: &BETransaction) -> Result<Vec<UnspentOutput>, Error> {
        tx.previous_sequence_and_outpoints()
            .into_iter()
            .map(|(sequence, outpoint)| {
                self.txo(&outpoint)
                    .and_then(|mut u| {
                        u.sequence = Some(sequence);
                        Ok(u.try_into()?)
                    })
                    .map_err(|_| Error::Generic("missing inputs not supported yet".into()))
            })
            .collect()
    }

    pub fn unspents(&self) -> Result<HashSet<BEOutPoint>, Error> {
        let mut relevant_outputs = HashSet::new();
        let mut inputs = HashSet::new();
        let store_read = self.store.read()?;
        let acc_store = store_read.account_cache(self.account_num)?;
        for txe in acc_store.all_txs.values() {
            inputs.extend(txe.tx.previous_outputs());
            for vout in 0..(txe.tx.output_len() as u32) {
                let script_pubkey = txe.tx.output_script(vout);
                if !script_pubkey.is_empty() && acc_store.paths.contains_key(&script_pubkey) {
                    let outpoint = txe.tx.outpoint(vout);
                    if let BEOutPoint::Elements(outpoint) = outpoint {
                        if acc_store.unblinded.get(&outpoint).is_none() {
                            // If Liquid, ignore outputs we cannot unblind
                            continue;
                        }
                    }
                    relevant_outputs.insert(outpoint);
                }
            }
        }
        Ok(relevant_outputs.difference(&inputs).cloned().collect())
    }

    pub fn has_transactions(&self) -> Result<bool, Error> {
        let store_read = self.store.read()?;
        let acc_store = store_read.account_cache(self.account_num)?;
        Ok(match acc_store.bip44_discovered {
            Some(true) => true,
            _ => !acc_store.heights.is_empty(),
        })
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
        let xprv = self
            .xprv
            .ok_or_else(|| Error::Generic("Internal software signing is not supported".into()))?;

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
                    let derivation_path = acc_store.get_path(&out.script_pubkey.into())?;
                    info!(
                        "input#{} prev_output:{:?} derivation_path:{:?}",
                        i, prev_output, derivation_path
                    );

                    let (script_sig, witness) = internal_sign_bitcoin(
                        &tx,
                        i,
                        &xprv,
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
                    let derivation_path = acc_store.get_path(&out.script_pubkey.into())?;

                    let (script_sig, witness) = internal_sign_elements(
                        &tx,
                        i,
                        &xprv,
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
                    Some(path) => self.xpub.derive_pub(&crate::EC, path)?,
                    // We only need to check wallet-owned inputs
                    None => continue,
                }
                .public_key;
                let value = acc_store
                    .all_txs
                    .get_previous_output_value(&outpoint, &acc_store.unblinded)
                    .expect("own prevout to have known value");
                if let Err(err) = tx.verify_input_sig(
                    &crate::EC,
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

pub fn get_account_derivation(
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
    let child_key = xpub.ckd_pub(&crate::EC, index.into())?;
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

pub fn discover_account(
    electrum_url: &ElectrumUrl,
    proxy: Option<&str>,
    account_xpub: &ExtendedPubKey,
    script_type: ScriptType,
) -> Result<bool, Error> {
    use electrum_client::ElectrumApi;

    // build our own client so that the subscriptions are dropped at the end
    let client = electrum_url.build_client(proxy, None)?;

    // the batch size is the effective gap limit for our purposes. in reality it is a lower bound.
    let gap_limit = BATCH_SIZE;

    let external_xpub = account_xpub.ckd_pub(&crate::EC, 0.into())?;
    for index in 0..gap_limit {
        let child_key = external_xpub.ckd_pub(&crate::EC, index.into())?;
        // Every network has the same scriptpubkey
        let script = bitcoin_address(&child_key.public_key, script_type, bitcoin::Network::Bitcoin)
            .script_pubkey();

        if client.script_subscribe(&script)?.is_some() {
            return Ok(true);
        }
    }

    Ok(false)
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

    // TODO put checks into CreateTransaction::validate
    // eagerly check for address validity
    for addressee in request.addressees.iter() {
        match network.id() {
            NetworkId::Bitcoin(network) => {
                if let Ok(address) = bitcoin::Address::from_str(&addressee.address) {
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
                        }
                        continue;
                    }
                }
                return Err(Error::InvalidAddress);
            }
            NetworkId::Elements(network) => {
                if let Ok(address) = elements::Address::parse_with_params(
                    &addressee.address,
                    network.address_params(),
                ) {
                    if !address.is_blinded() {
                        return Err(Error::NonConfidentialAddress);
                    }
                    if let elements::address::Payload::WitnessProgram {
                        version: v,
                        program: p,
                    } = &address.payload
                    {
                        // Do not support segwit greater than v1 and non-P2TR v1
                        if v.to_u8() > 1 || (v.to_u8() == 1 && p.len() != 32) {
                            return Err(Error::InvalidAddress);
                        }
                    }
                } else {
                    return Err(Error::InvalidAddress);
                }
                if let Some(Ok(_)) = addressee
                    .asset_id
                    .as_ref()
                    .map(|asset_id| elements::issuance::AssetId::from_str(&asset_id))
                {
                    // non-empty and valid asset id
                } else {
                    return Err(Error::InvalidAssetId);
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

        let store_read = account.store.read()?;
        let acc_store = store_read.account_cache(account.num())?;

        let txid = BETxid::from_hex(&prev_txitem.txhash, network.id())?;
        let prev_tx = &acc_store.all_txs.get(&txid).ok_or_else(|| Error::TxNotFound(txid))?.tx;

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

    let id = network.id();
    let mut utxos: Vec<Txo> = vec![];
    for (_, outpoints) in request.utxos.iter() {
        for o in outpoints {
            let outpoint = o.outpoint(id)?;
            // TODO: check that the outpoint is not confirmed
            // TODO: check that outpoints are unique
            let utxo = account.txo(&outpoint)?;
            if request.confidential_utxos_only && !utxo.is_confidential() {
                continue;
            }
            utxos.push(utxo);
        }
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
        let all_utxos: Vec<&Txo> = utxos.iter().filter(|u| u.asset_id() == asset).collect();
        let total_amount_utxos: u64 = all_utxos.iter().map(|u| u.satoshi).sum();

        let to_send = if asset == network.policy_asset_id().ok() {
            let mut dummy_tx = BETransaction::new(network.id());
            for utxo in all_utxos.iter() {
                dummy_tx.add_input(utxo.outpoint.clone());
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
                let mut asset_utxos: Vec<&Txo> = utxos
                    .iter()
                    .filter(|u| {
                        u.asset_id() == current_need.asset && !used_utxo.contains(&u.outpoint)
                    })
                    .collect();

                // sort by biggest utxo, random maybe another option, but it should be deterministically random (purely random breaks send_all algorithm)
                asset_utxos.sort_by(|a, b| a.satoshi.cmp(&b.satoshi));
                let utxo = asset_utxos.pop().ok_or(Error::InsufficientFunds)?;

                match network.id() {
                    NetworkId::Bitcoin(_) => {
                        // UTXO with same script must be spent together
                        for other_utxo in utxos.iter() {
                            if other_utxo.script_pubkey == utxo.script_pubkey {
                                used_utxo.insert(other_utxo.outpoint.clone());
                                tx.add_input(other_utxo.outpoint.clone());
                            }
                        }
                    }
                    NetworkId::Elements(_) => {
                        // Don't spend same script together in liquid. This would allow an attacker
                        // to cheaply send assets without value to the target, which will have to
                        // waste fees for the extra tx inputs and (eventually) outputs.
                        // While blinded address are required and not public knowledge,
                        // they are still available to whom transacted with us in the past
                        used_utxo.insert(utxo.outpoint.clone());
                        tx.add_input(utxo.outpoint.clone());
                    }
                }
            }
        }
        UtxoStrategy::Manual => {
            for utxo in utxos.iter() {
                tx.add_input(utxo.outpoint.clone());
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

    let used_utxos = account.used_utxos(&tx)?;
    let tx_outputs = account.tx_outputs(&tx)?;
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
        SPVVerifyTxResult::InProgress,
    );
    created_tx.used_utxos = used_utxos;
    created_tx.transaction_outputs = tx_outputs;
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
    let xprv = xprv.derive_priv(&crate::EC, &path).unwrap();
    let private_key = &xprv.private_key;
    let public_key = &PublicKey::from_private_key(&crate::EC, private_key);
    let script_code = p2pkh_script(public_key);

    let hash = if script_type.is_segwit() {
        SigHashCache::new(tx).signature_hash(input_index, &script_code, value, SigHashType::All)
    } else {
        tx.signature_hash(input_index, &script_code, SigHashType::All as u32)
    };

    let message = Message::from_slice(&hash.into_inner()[..]).unwrap();
    let signature = crate::EC.sign(&message, &private_key.key);

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
    let xprv = xprv.derive_priv(&crate::EC, &path).unwrap();
    let private_key = &xprv.private_key;
    let public_key = &PublicKey::from_private_key(&crate::EC, private_key);

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
    let signature = crate::EC.sign(&message, &private_key.key);
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

    for input in pset.inputs_mut().iter_mut() {
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
    for output in pset.outputs_mut().iter_mut() {
        // We are the owner of all inputs and outputs
        output.blinder_index = Some(0);
    }

    let inp_txout_sec: Vec<_> = inp_txout_sec.iter().map(|e| e.as_ref()).collect();
    pset.blind_last(&mut rand::thread_rng(), &crate::EC, &inp_txout_sec[..])?;
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

    #[test]
    fn xpubs_equivalence() {
        // equivalent xpubs from different signers
        let j = ExtendedPubKey::from_str("xpub6BsYXth6AveJGNDT7LWSVPfjUuvsxfnBoNh4pLMxrqKvTLyKKzjfQb3nH5kQM7QiRM7ou9BH3Ff4thS7DE1fEKkijcFZJqvUSuoTHqw2hHb").unwrap();
        let t = ExtendedPubKey::from_str("xpub67tVq9TC3jGc93MFouaJsne9ysbJTgd2z283AhzbJnJBYLaSgd7eCneb917z4mCmt9NT1jrex9JwZnxSqMo683zUWgMvBXGFcep95TuSPo6").unwrap();
        let l = ExtendedPubKey::from_str("xpub67tVq9TC3jGc6VXHGwpDsFaC382minnK3Us9gBC6XRpoxGMYLu8UpywPrmGQ5ZgrFEzMU8g93Ag9XBztNSfnvkqmQFt6jMUCn6NuZwucwf6").unwrap();
        // another xpub
        let o = ExtendedPubKey::from_str("xpub67tVq9TC3jGc6UecWK21xBDnB32fHpL3tStfyi5QaDsArWv66HnXg59wQ2LWPxrqsoagvoLfmwG8YGRzfu3gqRAvouknar2HM7egLuGZzTE").unwrap();

        xpubs_equivalent(&j, &j).unwrap();
        xpubs_equivalent(&j, &t).unwrap();
        xpubs_equivalent(&j, &l).unwrap();
        xpubs_equivalent(&t, &l).unwrap();
        assert!(xpubs_equivalent(&j, &o).is_err());
    }
}
