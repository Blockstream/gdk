use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};

use gdk_common::electrum_client::ScriptStatus;
use gdk_common::log::info;

use gdk_common::bitcoin::bip32::{DerivationPath, Fingerprint, Xpub};
use gdk_common::bitcoin::hashes::Hash;
use gdk_common::bitcoin::CompressedPublicKey;
use gdk_common::{bitcoin, elements};

use gdk_common::be::{BEAddress, BEOutPoint, BEScript, BETransaction, BETransactions, BETxid};
use gdk_common::error::fn_err;
use gdk_common::model::{
    parse_path, AccountInfo, AddressDataResult, AddressPointer, GetPreviousAddressesOpt,
    GetTransactionsOpt, GetTxInOut, PreviousAddress, PreviousAddresses, SPVVerifyTxResult,
    TxListItem, Txo, UpdateAccountOpt,
};
use gdk_common::scripts::{p2pkh_script, ScriptType};
use gdk_common::slip132::slip132_version;
use gdk_common::util::{
    asset_blinding_key_to_ec_private_key, ec_public_key_from_private_key, MasterBlindingKey,
};
use gdk_common::util::{now, weight_to_vsize};
use gdk_common::{ElementsNetwork, NetworkId, NetworkParameters};

use crate::error::Error;
use crate::interface::ElectrumUrl;
use crate::store::{RawAccountCache, Store};
use crate::ScriptStatuses;

// The number of account types, including these reserved for future use.
// Currently only 3 are used: P2SH-P2WPKH, P2WPKH and P2PKH
const NUM_RESERVED_ACCOUNT_TYPES: u32 = 16;

#[derive(Clone)]
pub struct Account {
    account_num: u32,
    script_type: ScriptType,

    xpub: Xpub,
    master_xpub_fingerprint: Fingerprint,
    chains: [Xpub; 2],
    network: NetworkParameters,
    store: Store,
    // elements only
    master_blinding: Option<MasterBlindingKey>,

    path: DerivationPath,
}

/// Compare xpub ignoring the fingerprint (which computation might be skipped),
/// depth and child_number (which might not be set correctly by some signers).
pub fn xpubs_equivalent(xpub1: &Xpub, xpub2: &Xpub) -> Result<(), Error> {
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
        master_xpub_fingerprint: Fingerprint,
        xpub: Xpub,
        master_blinding: Option<MasterBlindingKey>,
        store: Store,
        account_num: u32,
        discovered: bool,
    ) -> Result<Self, Error> {
        let (script_type, path) = get_account_derivation(account_num, network.id())?;

        // cache internal/external chains
        let chains = [xpub.ckd_pub(&crate::EC, 0.into())?, xpub.ckd_pub(&crate::EC, 1.into())?];

        store.lock().unwrap().make_account(account_num, xpub.clone(), discovered)?;

        info!("initialized account #{} path={} type={:?}", account_num, path, script_type);

        Ok(Self {
            network,
            account_num,
            script_type,
            xpub,
            master_xpub_fingerprint,
            chains,
            store,
            master_blinding,
            path,
        })
    }

    pub fn num(&self) -> u32 {
        self.account_num
    }

    pub fn script_type(&self) -> ScriptType {
        self.script_type
    }

    fn descriptor(&self, is_internal: bool) -> Result<String, Error> {
        let internal_idx = if is_internal {
            1
        } else {
            0
        };
        let (prefix, suffix) = match self.script_type {
            ScriptType::P2shP2wpkh => ("sh(wpkh", ")"),
            ScriptType::P2wpkh => ("wpkh", ""),
            ScriptType::P2pkh => ("pkh", ""),
            ScriptType::P2tr => ("tr", ""),
        };
        let (_, path) = get_account_derivation(self.account_num, self.network.id())?;
        let parent_fingerprint = self.master_xpub_fingerprint.to_string();
        let key_origin = format!("[{}/{}]", parent_fingerprint, path);
        let desc = format!("{}({}{}/{}/*){}", prefix, key_origin, self.xpub, internal_idx, suffix);
        if self.network.liquid {
            let slip77_key = self
                .master_blinding
                .as_ref()
                .expect("master blinding key always available in liquid")
                .0
                .to_string();
            let desc = format!("ct(slip77({}),el{})", slip77_key, desc);
            let checksum =
                gdk_common::elements_miniscript::descriptor::checksum::desc_checksum(&desc)?;
            Ok(format!("{}#{}", &desc, checksum))
        } else {
            let (desc, _) = gdk_common::miniscript::descriptor::Descriptor::parse_descriptor(
                &crate::EC,
                &desc,
            )?;
            Ok(desc.to_string())
        }
    }

    fn slip132_extended_pubkey(&self) -> Option<String> {
        if self.network.liquid {
            None
        } else {
            match slip132_version(self.network.mainnet, self.script_type) {
                Ok(version) => {
                    let mut xpub_bytes = self.xpub.encode();
                    xpub_bytes[0..4].copy_from_slice(&version);
                    Some(bitcoin::base58::encode_check(&xpub_bytes))
                }
                _ => None,
            }
        }
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
        let settings = self.store.lock()?.get_account_settings(self.account_num).cloned();

        Ok(AccountInfo {
            account_num: self.account_num,
            script_type: self.script_type,
            settings: settings.unwrap_or_default(),
            required_ca: 0,
            receiving_id: "".to_string(),
            bip44_discovered: self.has_transactions()?,
            user_path: self.path.clone().into(),
            core_descriptors: vec![self.descriptor(false)?, self.descriptor(true)?],
            slip132_extended_pubkey: self.slip132_extended_pubkey(),
        })
    }

    pub fn set_settings(&self, opt: UpdateAccountOpt) -> Result<bool, Error> {
        let mut store_write = self.store.lock()?;
        let mut settings =
            store_write.get_account_settings(self.account_num).cloned().unwrap_or_default();
        if let Some(name) = opt.name {
            settings.name = name;
        }
        if let Some(hidden) = opt.hidden {
            settings.hidden = hidden;
        }
        store_write.set_account_settings(self.account_num, settings)?;
        Ok(true)
    }

    pub fn set_name(&self, name: &str) -> Result<bool, Error> {
        self.set_settings(UpdateAccountOpt {
            name: Some(name.into()),
            ..Default::default()
        })
    }

    pub fn derive_address(&self, is_internal: bool, index: u32) -> Result<BEAddress, Error> {
        derive_address(
            &self.chains[is_internal as usize],
            index,
            self.script_type,
            self.network.id(),
            self.master_blinding.as_ref(),
        )
    }

    pub fn get_next_address(
        &self,
        is_internal: bool,
        ignore_gap_limit: bool,
        gap_limit: u32,
    ) -> Result<AddressPointer, Error> {
        let store = &mut self.store.lock()?;
        let acc_store = store.account_cache_mut(self.account_num)?;
        let pointer = acc_store.get_next_pointer(is_internal);
        acc_store.increment_pointer(is_internal, ignore_gap_limit, gap_limit);
        let account_path = DerivationPath::from(&[(is_internal as u32).into(), pointer.into()][..]);
        let user_path = self.get_full_path(&account_path);
        let address = self.derive_address(is_internal, pointer)?;
        let (is_blinded, unconfidential_address, blinding_key) = match address {
            BEAddress::Elements(ref a) => {
                let blinding_key = a.blinding_pubkey.map(|p| p.to_string());
                (Some(a.is_blinded()), Some(a.to_unconfidential().to_string()), blinding_key)
            }
            _ => (None, None, None),
        };
        let script_pubkey = &address.script_pubkey();
        acc_store.scripts.insert(account_path.clone(), script_pubkey.clone());
        acc_store.paths.insert(script_pubkey.clone(), account_path.clone());
        Ok(AddressPointer {
            subaccount: self.account_num,
            address_type: self.script_type.to_string(),
            address: address.to_string(),
            script_pubkey: script_pubkey.to_hex(),
            blinding_key: blinding_key,
            pointer: pointer,
            user_path: user_path.into(),
            is_internal: is_internal,
            is_confidential: is_blinded,
            unconfidential_address: unconfidential_address,
        })
    }

    /// Get the number of transactions where at least one input or output has a certain script
    /// pubkey.
    fn tx_count(
        &self,
        script_pubkey: &BEScript,
        heights: &HashMap<BETxid, Option<u32>>,
        txs: &BETransactions,
    ) -> u32 {
        let mut tot = 0;
        // Use heights to filter out conflicting transactions
        for txid in heights.keys() {
            if let Some(txe) = txs.get(&txid) {
                if txe.tx.creates_script_pubkey(&script_pubkey)
                    || txe.tx.spends_script_pubkey(&script_pubkey, txs)
                {
                    tot += 1;
                }
            }
        }
        tot
    }

    pub fn get_previous_addresses(
        &self,
        opt: &GetPreviousAddressesOpt,
    ) -> Result<PreviousAddresses, Error> {
        let subaccount = self.account_num;
        let is_internal = opt.is_internal;
        let store = self.store.lock()?;
        let acc_store = store.account_cache(subaccount)?;
        let wallet_last_pointer = acc_store.get_next_pointer(is_internal);
        let before_pointer = match opt.last_pointer {
            None => wallet_last_pointer,
            Some(p) => std::cmp::min(p, wallet_last_pointer),
        };
        let end = before_pointer.saturating_sub(opt.count);
        let mut previous_addresses = vec![];
        for index in (end..before_pointer).rev() {
            let address = self.derive_address(is_internal, index)?;
            let script_pubkey = address.script_pubkey();
            let account_path =
                DerivationPath::from(&[(is_internal as u32).into(), index.into()][..]);
            let (is_confidential, unconfidential_address, blinding_key) = match address {
                BEAddress::Elements(ref a) => {
                    let blinding_key = a.blinding_pubkey.map(|p| p.to_string());
                    (Some(a.is_blinded()), Some(a.to_unconfidential().to_string()), blinding_key)
                }
                _ => (None, None, None),
            };
            let tx_count = self.tx_count(&script_pubkey, &acc_store.heights, &acc_store.all_txs);
            previous_addresses.push(PreviousAddress {
                address: address.to_string(),
                address_type: self.script_type.to_string(),
                subaccount,
                is_internal,
                pointer: index,
                script_pubkey: script_pubkey.to_hex(),
                user_path: self.get_full_path(&account_path).into(),
                tx_count,
                is_confidential,
                unconfidential_address,
                scriptpubkey: script_pubkey.to_hex(),
                blinding_key,
            });
        }
        let ret_last_pointer = match end {
            0 => None,
            n => Some(n),
        };
        Ok(PreviousAddresses {
            last_pointer: ret_last_pointer,
            list: previous_addresses,
        })
    }

    pub fn list_tx(&self, opt: &GetTransactionsOpt) -> Result<Vec<TxListItem>, Error> {
        let store = self.store.lock()?;
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

                    let (
                        address,
                        script_pubkey,
                        unconfidential_address,
                        is_confidential,
                        blinding_key,
                    ) = if is_relevant {
                        let addr = self
                            .derive_address(is_internal, pointer)
                            .expect("deriving a relevant address");
                        let script_pubkey = addr.script_pubkey().to_hex();
                        let address = addr.to_string();
                        let unconfidential_address =
                            addr.elements().map(|a| a.to_unconfidential().to_string());
                        let is_confidential = addr.elements().map(|_| true);
                        let blinding_key = addr.blinding_pubkey().map(|p| p.to_string());
                        (
                            address,
                            script_pubkey,
                            unconfidential_address,
                            is_confidential,
                            blinding_key,
                        )
                    } else {
                        let address = acc_store
                            .all_txs
                            .get_previous_output_address(beoutpoint, self.network.id())
                            .unwrap_or_else(|| "".to_string());
                        let script_pubkey = acc_store
                            .all_txs
                            .get_previous_output_script_pubkey(beoutpoint)
                            .map(|s| s.to_hex())
                            .unwrap_or_else(|| "".to_string());
                        (address, script_pubkey, None, None, None)
                    };

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
                                    .map(|a| a.to_string()),
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

                    let is_blinded = is_blinded(&asset_blinder, &amount_blinder);

                    Ok(GetTxInOut {
                        is_output: false,
                        is_spent: true,
                        pt_idx: vin as u32,
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
                        is_blinded,
                        is_confidential,
                        unconfidential_address,
                        blinding_key,
                        script_pubkey,
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

                    let (
                        address,
                        script_pubkey,
                        unconfidential_address,
                        is_confidential,
                        blinding_key,
                    ) = if is_relevant {
                        let addr = self
                            .derive_address(is_internal, pointer)
                            .expect("deriving a relevant address");
                        let address = addr.to_string();
                        let script_pubkey = addr.script_pubkey().to_hex();
                        let unconfidential_address =
                            addr.elements().map(|a| a.to_unconfidential().to_string());
                        let is_confidential = addr.elements().map(|_| true);
                        let blinding_key = addr.blinding_pubkey().map(|p| p.to_string());
                        (
                            address,
                            script_pubkey,
                            unconfidential_address,
                            is_confidential,
                            blinding_key,
                        )
                    } else {
                        let address = tx
                            .output_address(vout, self.network.id())
                            .unwrap_or_else(|| "".to_string());
                        let script_pubkey = tx.output_script(vout).to_hex();
                        (address, script_pubkey, None, None, None)
                    };

                    let satoshi = tx.output_value(vout, &acc_store.unblinded).unwrap_or(0);
                    let asset_id =
                        tx.output_asset(vout, &acc_store.unblinded).map(|a| a.to_string());
                    let asset_blinder = tx.output_assetblinder_hex(vout, &acc_store.unblinded);
                    let amount_blinder = tx.output_amountblinder_hex(vout, &acc_store.unblinded);
                    let is_blinded = is_blinded(&asset_blinder, &amount_blinder);

                    Ok(GetTxInOut {
                        is_output: true,
                        // FIXME: this can be wrong, however setting this value correctly might be quite
                        // expensive: involing db hits and potentially network calls; postponing it for now.
                        is_spent: false,
                        pt_idx: vout,
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
                        is_blinded,
                        is_confidential,
                        unconfidential_address,
                        blinding_key,
                        script_pubkey,
                    })
                })
                .collect::<Result<Vec<GetTxInOut>, Error>>()?;

            let discount_weight = match &txe.tx {
                BETransaction::Bitcoin(_tx) => txe.weight,
                BETransaction::Elements(tx) => tx.discount_weight(),
            };

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
                spv_verified: spv_verified.to_string(),
                fee,
                fee_rate,
                inputs,
                outputs,
                transaction_size: txe.size,
                transaction_vsize: weight_to_vsize(txe.weight),
                transaction_weight: txe.weight,
                discount_weight,
            });
        }
        info!("list_tx {:?}", txs.iter().map(|e| &e.txhash).collect::<Vec<&String>>());

        Ok(txs)
    }

    pub fn public_key(&self, path: &DerivationPath) -> CompressedPublicKey {
        let xpub = self.xpub.derive_pub(&crate::EC, path).unwrap();
        xpub.to_pub()
    }

    pub fn script_code(&self, path: &DerivationPath) -> BEScript {
        // FIXME: TAPROOT: elements p2tr
        let public_key = self.public_key(path);
        match (self.network.id(), self.script_type) {
            (NetworkId::Bitcoin(network), ScriptType::P2tr) => {
                // script_code is the p2tr scriptpubkey for p2tr
                use gdk_common::bitcoin::Address;
                Address::p2tr(&crate::EC, public_key.into(), None, network).script_pubkey().into()
            }
            (_, _) => {
                // script_code is the p2pkh scriptpubkey for p2pkh/p2wpkh/p2sh-p2wpkh
                p2pkh_script(&public_key).into()
            }
        }
    }

    pub fn txo(&self, outpoint: &BEOutPoint, acc_store: &RawAccountCache) -> Result<Txo, Error> {
        let vout = outpoint.vout();
        let txid = outpoint.txid();

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

            public_key: self.public_key(&account_path).into(),
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

    pub fn unspents(&self) -> Result<HashSet<BEOutPoint>, Error> {
        let mut relevant_outputs = HashSet::new();
        let mut inputs = HashSet::new();
        let store_read = self.store.lock()?;
        let acc_store = store_read.account_cache(self.account_num)?;
        for (txid, txe) in acc_store.all_txs.iter() {
            if !acc_store.heights.contains_key(&txid) {
                // transaction has been replaced or dropped out of mempool
                continue;
            }
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
        let store_read = self.store.lock()?;
        let acc_store = store_read.account_cache(self.account_num)?;
        Ok(acc_store.bip44_discovered || !acc_store.heights.is_empty())
    }

    pub fn status(&self) -> Result<ScriptStatuses, Error> {
        let store = self.store.lock()?;
        Ok(store.account_cache(self.account_num)?.script_statuses.clone().unwrap_or_default())
    }

    pub fn get_script_batch(
        &self,
        is_internal: bool,
        batch_count: u32,
    ) -> Result<Vec<(bool, u32, DerivationPath, BEScript)>, Error> {
        let store = self.store.lock()?;
        let acc_store = store.account_cache(self.account_num)?;

        let mut result = vec![];
        // TODO: investigate how different batch sizes affect performance
        const BATCH_SIZE: u32 = 20;
        let start = batch_count * BATCH_SIZE;
        let end = start + BATCH_SIZE;

        for j in start..end {
            let path = DerivationPath::from(&[(is_internal as u32).into(), j.into()][..]);
            let mut cached = true;
            let script = acc_store.scripts.get(&path).cloned().map_or_else(
                || -> Result<BEScript, Error> {
                    cached = false;
                    Ok(self.derive_address(is_internal, j)?.script_pubkey())
                },
                Ok,
            )?;
            result.push((cached, j, path, script));
        }

        Ok(result)
    }

    pub fn get_address_data(&self, address: &BEAddress) -> Result<AddressDataResult, Error> {
        let store_read = self.store.lock()?;
        let acc_store = store_read.account_cache(self.account_num)?;
        let script_pubkey = address.script_pubkey();
        let account_path = acc_store.get_path(&script_pubkey)?;
        Ok(AddressDataResult {
            user_path: self.get_full_path(account_path).into(),
        })
    }
}

pub(crate) fn compute_script_status<Txs>(txs: Txs) -> ScriptStatus
where
    Txs: IntoIterator<Item = (BETxid, i32)>,
{
    let mut data = String::new();
    for (txid, height) in txs {
        data.push_str(&format!("{txid}:{height}:"));
    }
    let hash = bitcoin::hashes::sha256::Hash::hash(data.as_bytes());
    let hash_arr: [u8; 32] = hash.to_byte_array();
    hash_arr.into()
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
        3 => (ScriptType::P2tr, 86),
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
        format!("{}'/{}'/{}'", purpose, coin_type, bip32_account_num).parse().unwrap();

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
            _ => panic!("unknown network"),
        },
        NetworkId::Elements(elements_network) => match elements_network {
            ElementsNetwork::Liquid => 1776,
            ElementsNetwork::LiquidTestnet => 1,
            ElementsNetwork::ElementsRegtest => 1,
        },
    }
}

fn derive_address(
    xpub: &Xpub,
    index: u32,
    script_type: ScriptType,
    network_id: NetworkId,
    master_blinding: Option<&MasterBlindingKey>,
) -> Result<BEAddress, Error> {
    let child_key = xpub.ckd_pub(&crate::EC, index.into())?;
    match network_id {
        NetworkId::Bitcoin(network) => {
            let address = bitcoin_address(&child_key.to_pub(), script_type, network);
            Ok(BEAddress::Bitcoin(address))
        }
        NetworkId::Elements(network) => {
            let address = elements_address(
                &child_key.to_pub(),
                master_blinding.expect("we are in elements but master blinding is None"),
                script_type,
                network,
            );
            Ok(BEAddress::Elements(address))
        }
    }
}

fn bitcoin_address(
    public_key: &CompressedPublicKey,
    script_type: ScriptType,
    net: bitcoin::Network,
) -> bitcoin::Address {
    use gdk_common::bitcoin::Address;
    match script_type {
        ScriptType::P2shP2wpkh => Address::p2shwpkh(public_key, net),
        ScriptType::P2wpkh => Address::p2wpkh(public_key, net),
        ScriptType::P2pkh => Address::p2pkh(public_key, net),
        ScriptType::P2tr => Address::p2tr(&crate::EC, (*public_key).into(), None, net),
    }
}

fn elements_address(
    public_key: &CompressedPublicKey,
    master_blinding_key: &MasterBlindingKey,
    script_type: ScriptType,
    net: ElementsNetwork,
) -> elements::Address {
    let addr_params = net.address_params();
    let address = match script_type {
        ScriptType::P2pkh => elements::Address::p2pkh(&public_key.0.into(), None, addr_params),
        ScriptType::P2shP2wpkh => {
            elements::Address::p2shwpkh(&public_key.0.into(), None, addr_params)
        }
        ScriptType::P2wpkh => elements::Address::p2wpkh(&public_key.0.into(), None, addr_params),
        ScriptType::P2tr => {
            let (x_only, _) = public_key.0.x_only_public_key();
            elements::Address::p2tr(&crate::EC, x_only, None, None, addr_params)
        }
    };
    let script_pubkey = address.script_pubkey();
    let blinding_prv = asset_blinding_key_to_ec_private_key(master_blinding_key, &script_pubkey);
    let blinding_pub = ec_public_key_from_private_key(blinding_prv);
    address.to_confidential(blinding_pub)
}

pub fn discover_account(
    electrum_url: &ElectrumUrl,
    proxy: Option<&str>,
    account_xpub: &Xpub,
    script_type: ScriptType,
    gap_limit: u32,
) -> Result<bool, Error> {
    use gdk_common::electrum_client::ElectrumApi;

    // build our own client so that the subscriptions are dropped at the end
    let client = electrum_url.build_client(proxy, None)?;

    let external_xpub = account_xpub.ckd_pub(&crate::EC, 0.into())?;
    for index in 0..gap_limit {
        let child_key = external_xpub.ckd_pub(&crate::EC, index.into())?;
        // Every network has the same scriptpubkey
        let script = bitcoin_address(&child_key.to_pub(), script_type, bitcoin::Network::Bitcoin)
            .script_pubkey();

        if client.script_subscribe(&script)?.is_some() {
            return Ok(true);
        }
    }

    Ok(false)
}

fn is_blinded_inner(blinder: &str) -> bool {
    blinder.chars().any(|c| c != '0')
}

/// False if both the asset and value blinders are zero.
///
/// The partially blinded case, i.e. when one of the two blinders is zero and the other is not, is
/// interpreted as blinded.
fn is_blinded(
    asset_blinder_hex: &Option<String>,
    amount_blinder_hex: &Option<String>,
) -> Option<bool> {
    match (asset_blinder_hex, amount_blinder_hex) {
        (Some(abf), Some(vbf)) => Some(is_blinded_inner(abf) || is_blinded_inner(vbf)),
        _ => None,
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use gdk_common::bitcoin::hashes::hex::FromHex;
    use std::str::FromStr;

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
        test_derivation(0, ScriptType::P2shP2wpkh, "49'/1'/0'");
        test_derivation(1, ScriptType::P2wpkh, "84'/1'/0'");
        test_derivation(2, ScriptType::P2pkh, "44'/1'/0'");
        test_derivation(3, ScriptType::P2tr, "86'/1'/0'");

        // reserved for future use, currently rejected
        for n in 4..=15 {
            test_derivation_fails(n);
        }

        test_derivation(16, ScriptType::P2shP2wpkh, "49'/1'/1'");
        test_derivation(17, ScriptType::P2wpkh, "84'/1'/1'");
        test_derivation(18, ScriptType::P2pkh, "44'/1'/1'");
        test_derivation(19, ScriptType::P2tr, "86'/1'/1'");
        test_derivation_fails(20);

        test_derivation(160, ScriptType::P2shP2wpkh, "49'/1'/10'");
        test_derivation(161, ScriptType::P2wpkh, "84'/1'/10'");
        test_derivation(162, ScriptType::P2pkh, "44'/1'/10'");
        test_derivation(163, ScriptType::P2tr, "86'/1'/10'");
    }

    #[test]
    fn xpubs_equivalence() {
        // equivalent xpubs from different signers
        let j = Xpub::from_str("xpub6BsYXth6AveJGNDT7LWSVPfjUuvsxfnBoNh4pLMxrqKvTLyKKzjfQb3nH5kQM7QiRM7ou9BH3Ff4thS7DE1fEKkijcFZJqvUSuoTHqw2hHb").unwrap();
        let t = Xpub::from_str("xpub67tVq9TC3jGc93MFouaJsne9ysbJTgd2z283AhzbJnJBYLaSgd7eCneb917z4mCmt9NT1jrex9JwZnxSqMo683zUWgMvBXGFcep95TuSPo6").unwrap();
        let l = Xpub::from_str("xpub67tVq9TC3jGc6VXHGwpDsFaC382minnK3Us9gBC6XRpoxGMYLu8UpywPrmGQ5ZgrFEzMU8g93Ag9XBztNSfnvkqmQFt6jMUCn6NuZwucwf6").unwrap();
        // another xpub
        let o = Xpub::from_str("xpub67tVq9TC3jGc6UecWK21xBDnB32fHpL3tStfyi5QaDsArWv66HnXg59wQ2LWPxrqsoagvoLfmwG8YGRzfu3gqRAvouknar2HM7egLuGZzTE").unwrap();

        xpubs_equivalent(&j, &j).unwrap();
        xpubs_equivalent(&j, &t).unwrap();
        xpubs_equivalent(&j, &l).unwrap();
        xpubs_equivalent(&t, &l).unwrap();
        assert!(xpubs_equivalent(&j, &o).is_err());
    }

    #[test]
    fn test_script_status() {
        // The following test vectors were generated with an electrs server.

        let inputs: [&[(&str, i32)]; 3] = [
            &[("5aeab6d4c51cb9f7f808c3884410b4b3a6ec2ef0ab90d05af1411e5ef1264629", 2)],
            &[
                ("5aeab6d4c51cb9f7f808c3884410b4b3a6ec2ef0ab90d05af1411e5ef1264629", 2),
                ("3774bced240ff74289b3d05f3d12467fd182744cd28cf7bce4f61648a9defaec", 0),
            ],
            &[
                ("5aeab6d4c51cb9f7f808c3884410b4b3a6ec2ef0ab90d05af1411e5ef1264629", 2),
                ("3774bced240ff74289b3d05f3d12467fd182744cd28cf7bce4f61648a9defaec", 103),
            ],
        ];

        fn script_status(hex: &str) -> ScriptStatus {
            <[u8; 32]>::from_hex(hex).unwrap().into()
        }

        let expected = [
            script_status("beb13d2a759cf2f6e376338ced5f40c81e80929d8f4f51ca22e5c7d243f7fe25"),
            script_status("5b7f40c0c8daa2db6457510b785a7373262845a7edb34c689ab7ab7bca9d92b2"),
            script_status("89a73c3e525bb8a1a1313214d08b00b1095744f049ad60607ea4c241f6ec963c"),
        ];

        for (&txs, expected) in inputs.iter().zip(expected) {
            let txs = txs.iter().map(|(txid, height)| {
                let txid = BETxid::Bitcoin(bitcoin::Txid::from_str(txid).unwrap());
                (txid, *height)
            });
            let script_status = compute_script_status(txs);
            assert_eq!(script_status, expected);
        }
    }
}
