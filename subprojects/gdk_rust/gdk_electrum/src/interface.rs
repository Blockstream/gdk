use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hash_types::PubkeyHash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, All, Message, Secp256k1};
use bitcoin::util::address::Address;
use bitcoin::util::bip143::SighashComponents;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::PublicKey;
use elements;
use gdk_common::model::{AddressAmount, Balances, GetTransactionsOpt};
use hex;
use log::{debug, info};
use rand::Rng;

use gdk_common::mnemonic::Mnemonic;
use gdk_common::model::{AddressPointer, CreateTransaction, Settings, TransactionMeta};
use gdk_common::network::{ElementsNetwork, Network, NetworkId};
use gdk_common::util::p2shwpkh_script;
use gdk_common::wally::*;

use crate::db::*;
use crate::error::*;

use elements::confidential::{Asset, Nonce, Value};
use gdk_common::be::*;
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::str::FromStr;

#[derive(Debug)]
pub struct WalletCtx {
    pub secp: Secp256k1<All>,
    pub network: Network,
    pub mnemonic: Mnemonic,
    pub db: Forest,
    pub xprv: ExtendedPrivKey,
    pub xpub: ExtendedPubKey,
    pub master_blinding: Option<MasterBlindingKey>,
    pub change_max_deriv: u32,
}

#[derive(Clone)]
pub enum ElectrumUrl {
    Tls(String, bool),
    Plaintext(String),
}

impl WalletCtx {
    pub fn new(
        db: Forest,
        mnemonic: Mnemonic,
        network: Network,
        xprv: ExtendedPrivKey,
        xpub: ExtendedPubKey,
        master_blinding: Option<MasterBlindingKey>,
    ) -> Result<Self, Error> {
        Ok(WalletCtx {
            mnemonic,
            db,
            network, // TODO: from db
            secp: Secp256k1::gen_new(),
            xprv,
            xpub,
            master_blinding,
            change_max_deriv: 0,
        })
    }

    pub fn get_mnemonic(&self) -> &Mnemonic {
        &self.mnemonic
    }

    fn derive_address(&self, xpub: &ExtendedPubKey, path: [u32; 2]) -> Result<BEAddress, Error> {
        let path: Vec<ChildNumber> = path
            .iter()
            .map(|x| ChildNumber::Normal {
                index: *x,
            })
            .collect();
        let derived = xpub.derive_pub(&self.secp, &path)?;
        if self.network.liquid {}
        match self.network.id() {
            NetworkId::Bitcoin(network) => {
                Ok(BEAddress::Bitcoin(Address::p2shwpkh(&derived.public_key, network)))
            }
            NetworkId::Elements(network) => {
                let master_blinding_key = self
                    .master_blinding
                    .as_ref()
                    .expect("we are in elements but master blinding is None");
                let script = p2shwpkh_script(&derived.public_key);
                let blinding_key =
                    asset_blinding_key_to_ec_private_key(&master_blinding_key, &script);
                let public_key = ec_public_key_from_private_key(blinding_key);
                let blinder = Some(public_key);
                let addr = elements::Address::p2shwpkh(
                    &derived.public_key,
                    blinder,
                    address_params(network),
                );

                Ok(BEAddress::Elements(addr))
            }
        }
    }

    pub fn get_settings(&self) -> Result<Settings, Error> {
        Ok(self.db.get_settings()?.unwrap_or_default())
    }

    pub fn change_settings(&self, settings: &Settings) -> Result<(), Error> {
        self.db.insert_settings(settings)
    }

    pub fn get_tip(&self) -> Result<u32, Error> {
        self.db.get_tip()
    }
    pub fn list_tx(&self, opt: &GetTransactionsOpt) -> Result<Vec<TransactionMeta>, Error> {
        let (_, all_txs) = self.db.get_all_spent_and_txs()?;
        let all_scripts = self.db.get_all_scripts()?;
        let all_unblinded = self.db.get_all_unblinded()?; // empty map if not liquid

        let mut txs = vec![];
        let mut my_txids = self.db.get_my()?;
        my_txids.sort_by(|a, b| b.1.unwrap_or(std::u32::MAX).cmp(&a.1.unwrap_or(std::u32::MAX)));

        for (tx_id, height) in my_txids.iter().skip(opt.first).take(opt.count) {
            debug!("tx_id {}", tx_id);

            let tx = all_txs.get(tx_id).ok_or_else(fn_err(&format!("list_tx no tx {}", tx_id)))?;
            let header = height
                .map(|h| self.db.get_header(h)?.ok_or_else(fn_err("no header")))
                .transpose()?;

            let mut addressees = vec![];
            for i in 0..tx.output_len() as u32 {
                let script = tx.output_script(i);
                if !script.is_empty() && !all_scripts.contains(&script) {
                    let address = tx.output_address(i, self.network.id());
                    addressees.push(AddressAmount {
                        address: address.unwrap_or("".to_string()),
                        satoshi: 0, // apparently not needed in list_tx addressees
                        asset_tag: None,
                    });
                }
            }
            let create_transaction = CreateTransaction {
                addressees,
                ..Default::default()
            };

            let fee = tx.fee(&all_txs, &all_unblinded);
            let satoshi = tx.my_balances(&all_txs, &all_scripts, &all_unblinded);

            let negatives = satoshi.iter().filter(|(_, v)| **v < 0).count();
            let positives = satoshi.iter().filter(|(_, v)| **v > 0).count();
            let (type_, user_signed) =
                match (positives > negatives, tx.is_redeposit(&all_scripts, &all_txs)) {
                    (_, true) => ("redeposit", true),
                    (true, false) => ("incoming", false),
                    (false, false) => ("outgoing", true),
                };

            let tx_meta = TransactionMeta::new(
                tx.clone(),
                *height,
                header.map(|h| h.time()),
                satoshi,
                fee,
                self.network.id().get_bitcoin_network().unwrap_or(bitcoin::Network::Bitcoin),
                type_.to_string(),
                create_transaction,
                user_signed,
            );

            txs.push(tx_meta);
        }
        info!("list_tx {:?}", txs.iter().map(|e| &e.txid).collect::<Vec<&String>>());

        Ok(txs)
    }

    fn utxos(&self) -> Result<WalletData, Error> {
        info!("start utxos");
        let (spent, all_txs) = self.db.get_all_spent_and_txs()?;
        let all_scripts = self.db.get_all_scripts()?;
        let all_unblinded = self.db.get_all_unblinded()?; // empty map if not liquid

        let mut utxos = vec![];
        for tx_id in self.db.get_only_txids()? {
            let tx = all_txs.get(&tx_id).ok_or_else(fn_err(&format!("utxos no tx {}", tx_id)))?;
            let tx_utxos: Vec<(BEOutPoint, UTXOInfo)> = match tx {
                BETransaction::Bitcoin(tx) => tx
                    .output
                    .clone()
                    .into_iter()
                    .enumerate()
                    .map(|(vout, output)| (BEOutPoint::new_bitcoin(tx.txid(), vout as u32), output))
                    .filter(|(_, output)| all_scripts.contains(&output.script_pubkey))
                    .filter(|(outpoint, _)| !spent.contains(&outpoint))
                    .map(|(outpoint, output)| {
                        (
                            outpoint,
                            UTXOInfo::new("btc".to_string(), output.value, output.script_pubkey),
                        )
                    })
                    .collect(),
                BETransaction::Elements(tx) => tx
                    .output
                    .clone()
                    .into_iter()
                    .enumerate()
                    .map(|(vout, output)| {
                        (BEOutPoint::new_elements(tx.txid(), vout as u32), output)
                    })
                    .filter(|(_, output)| all_scripts.contains(&output.script_pubkey))
                    .filter(|(outpoint, _)| !spent.contains(&outpoint))
                    .filter_map(|(outpoint, output)| {
                        if let BEOutPoint::Elements(el_outpoint) = outpoint {
                            if let Some(unblinded) = all_unblinded.get(&el_outpoint) {
                                return Some((
                                    outpoint,
                                    UTXOInfo::new(
                                        unblinded.asset_hex(),
                                        unblinded.value,
                                        output.script_pubkey,
                                    ),
                                ));
                            }
                        }
                        None
                    })
                    .collect(),
            };
            utxos.extend(tx_utxos);
        }
        utxos.sort_by(|a, b| (b.1).value.cmp(&(a.1).value));

        let result = WalletData {
            utxos,
            all_unblinded,
            all_txs,
            all_scripts,
            spent,
        };
        Ok(result)
    }

    pub fn balance(&self) -> Result<Balances, Error> {
        info!("start balance");
        let mut result = HashMap::new();
        match self.network.id() {
            NetworkId::Bitcoin(_) => result.entry("btc".to_string()).or_insert(0),
            NetworkId::Elements(_) => {
                result.entry(self.network.policy_asset.as_ref().unwrap().clone()).or_insert(0)
            }
        };
        for (_, info) in self.utxos()?.utxos.iter() {
            *result.entry(info.asset.clone()).or_default() += info.value as i64;
        }
        Ok(result)
    }

    pub fn create_tx(&self, request: &mut CreateTransaction) -> Result<TransactionMeta, Error> {
        info!("create_tx {:?}", request);

        // TODO put checks into CreateTransaction::validate, add check asset_tag are valid asset hex
        // eagerly check for address validity
        for address in request.addressees.iter().map(|a| &a.address) {
            match self.network.id() {
                NetworkId::Bitcoin(network) => {
                    if let Ok(address) = bitcoin::Address::from_str(address) {
                        info!("address.network:{} network:{}", address.network, network);
                        if address.network == network
                            || (address.network == bitcoin::Network::Testnet
                                && network == bitcoin::Network::Regtest)
                        {
                            continue;
                        }
                    }
                    return Err(Error::InvalidAddress);
                }
                NetworkId::Elements(network) => {
                    if let Ok(address) = elements::Address::from_str(address) {
                        info!(
                            "address.params:{:?} address_params(network):{:?}",
                            address.params,
                            address_params(network)
                        );
                        if address.params == address_params(network) {
                            continue;
                        }
                    }
                    return Err(Error::InvalidAddress);
                }
            }
        }

        if request.addressees.is_empty() {
            return Err(Error::EmptyAddressees);
        }

        let subaccount = request.subaccount.unwrap_or(0);
        if subaccount != 0 {
            return Err(Error::InvalidSubaccount(subaccount));
        }

        if !request.previous_transaction.is_empty() {
            return Err(Error::Generic("bump not supported".into()));
        }

        let send_all = request.send_all.unwrap_or(false);
        request.send_all = Some(send_all); // accept default false, but always return the value
        if !send_all && request.addressees.iter().any(|a| a.satoshi == 0) {
            return Err(Error::InvalidAmount);
        }

        if !send_all {
            for address_amount in request.addressees.iter() {
                if address_amount.satoshi <= 546 {
                    match self.network.id() {
                        NetworkId::Bitcoin(_) => return Err(Error::InvalidAmount),
                        NetworkId::Elements(_) => {
                            if address_amount.asset_tag == self.network.policy_asset {
                                // we apply dust rules for liquid bitcoin as elements do
                                return Err(Error::InvalidAmount);
                            }
                        }
                    }
                }
            }
        }

        if let NetworkId::Elements(_) = self.network.id() {
            if request.addressees.iter().any(|a| a.asset_tag.is_none()) {
                return Err(Error::AssetEmpty);
            }
        }

        // convert from satoshi/kbyte to satoshi/byte
        let default_value = match self.network.id() {
            NetworkId::Bitcoin(_) => 1000,
            NetworkId::Elements(_) => 100,
        };
        let fee_rate = (request.fee_rate.unwrap_or(default_value) as f64) / 1000.0;
        info!("target fee_rate {:?} satoshi/byte", fee_rate);

        let wallet_data = self.utxos()?;
        let utxos = &wallet_data.utxos;
        info!("utxos len:{} utxos:{:?}", utxos.len(), utxos);

        if send_all {
            // send_all works by creating a dummy tx with all utxos, estimate the fee and set the
            // sending amount to `total_amount_utxos - estimated_fee`
            info!("send_all calculating total_amount");
            if request.addressees.len() != 1 {
                return Err(Error::SendAll);
            }
            let asset = request.addressees[0].asset_tag.as_deref().unwrap_or("btc");
            let all_utxos: Vec<&(BEOutPoint, UTXOInfo)> =
                utxos.iter().filter(|(_, i)| i.asset == asset).collect();
            let total_amount_utxos: u64 = all_utxos.iter().map(|(_, i)| i.value).sum();

            let to_send = if asset == "btc" || Some(asset.to_string()) == self.network.policy_asset
            {
                let mut dummy_tx = BETransaction::new(self.network.id());
                for utxo in all_utxos.iter() {
                    dummy_tx.add_input(utxo.0.clone());
                }
                let estimated_fee = dummy_tx.estimated_fee(fee_rate, 1) + 3; // estimating 3 satoshi more as estimating less would later result in InsufficientFunds
                total_amount_utxos
                    .checked_sub(estimated_fee)
                    .ok_or_else(|| Error::InsufficientFunds)?
            } else {
                total_amount_utxos
            };

            info!("send_all asset: {} to_send:{}", asset, to_send);

            request.addressees[0].satoshi = to_send;
        }

        let mut tx = BETransaction::new(self.network.id());
        // transaction is created in 3 steps:
        // 1) adding requested outputs to tx outputs
        // 2) adding enough utxso to inputs such that tx outputs and estimated fees are covered
        // 3) adding change(s)

        // STEP 1) add the outputs requested for this transactions
        for out in request.addressees.iter() {
            tx.add_output(&out.address, out.satoshi, out.asset_tag.clone())
                .map_err(|_| Error::InvalidAddress)?;
        }

        // STEP 2) add utxos until tx outputs are covered (including fees) or fail
        let mut used_utxo: HashSet<BEOutPoint> = HashSet::new();
        loop {
            let mut needs =
                tx.needs(fee_rate, send_all, self.network.policy_asset.clone(), &wallet_data); // Vec<(asset_string, satoshi)  "policy asset" is last, in bitcoin asset_string="btc" and max 1 element
            info!("needs: {:?}", needs);
            if needs.is_empty() {
                // SUCCESS tx doesn't need other inputs
                break;
            }
            let current_need = needs.pop().unwrap(); // safe to unwrap just checked it's not empty

            // taking only utxos of current asset considered, filters also utxos used in this loop
            let mut asset_utxos: Vec<&(BEOutPoint, UTXOInfo)> = utxos
                .iter()
                .filter(|(o, i)| i.asset == current_need.asset && !used_utxo.contains(o))
                .collect();

            // sort by biggest utxo, random maybe another option, but it should be deterministically random (purely random breaks send_all algorithm)
            asset_utxos.sort_by(|a, b| (a.1).value.cmp(&(b.1).value));
            let utxo = asset_utxos.pop().ok_or(Error::InsufficientFunds)?;

            // UTXO with same script must be spent together, even if it's another asset
            for other_utxo in utxos.iter() {
                if (other_utxo.1).script == (utxo.1).script {
                    used_utxo.insert(other_utxo.0.clone());
                    tx.add_input(other_utxo.0.clone());
                }
            }
        }

        // STEP 3) adding change(s)
        let estimated_fee =
            tx.estimated_fee(fee_rate, tx.estimated_changes(send_all, &wallet_data));
        let changes = tx.changes(estimated_fee, self.network.policy_asset.clone(), &wallet_data); // Vec<Change> asset, value
        for (i, change) in changes.iter().enumerate() {
            let change_index = self.db.get_index(Index::Internal)? + i as u32 + 1;
            let change_address = self.derive_address(&self.xpub, [1, change_index])?.to_string();
            info!(
                "adding change to {} of {} asset {:?}",
                &change_address, change.satoshi, change.asset
            );
            tx.add_output(&change_address, change.satoshi, Some(change.asset.clone()))?;
        }

        // randomize inputs and outputs, BIP69 has been rejected because lacks wallets adoption
        tx.scramble();

        let fee_val = tx.fee(&wallet_data.all_txs, &wallet_data.all_unblinded); // recompute exact fee_val from built tx
        if let Some(policy_asset) = self.network.policy_asset.as_ref() {
            tx.add_fee_if_elements(fee_val, policy_asset);
        }

        info!("created tx fee {:?}", fee_val);

        let mut satoshi = tx.my_balances(
            &wallet_data.all_txs,
            &wallet_data.all_scripts,
            &wallet_data.all_unblinded,
        );
        for (_, v) in satoshi.iter_mut() {
            *v = v.abs();
        }

        let mut created_tx = TransactionMeta::new(
            tx,
            None,
            None,
            satoshi,
            fee_val,
            self.network.id().get_bitcoin_network().unwrap_or(bitcoin::Network::Bitcoin),
            "outgoing".to_string(),
            request.clone(),
            true,
        );
        created_tx.changes_used = Some(changes.len() as u32);
        info!("returning: {:?}", created_tx);

        Ok(created_tx)
    }

    // TODO when we can serialize psbt
    //pub fn sign(&self, psbt: PartiallySignedTransaction) -> Result<PartiallySignedTransaction, Error> { Err(Error::Generic("NotImplemented".to_string())) }

    fn internal_sign(
        &self,
        tx: &Transaction,
        input_index: usize,
        path: &DerivationPath,
        value: u64,
    ) -> (PublicKey, Vec<u8>) {
        let privkey = self.xprv.derive_priv(&self.secp, &path).unwrap();
        let pubkey = ExtendedPubKey::from_private(&self.secp, &privkey);

        let witness_script = Address::p2pkh(&pubkey.public_key, pubkey.network).script_pubkey();

        let hash =
            SighashComponents::new(tx).sighash_all(&tx.input[input_index], &witness_script, value);

        let signature = self
            .secp
            .sign(&Message::from_slice(&hash.into_inner()[..]).unwrap(), &privkey.private_key.key);

        //let mut signature = signature.serialize_der().to_vec();
        let mut signature = hex::decode(&format!("{:?}", signature)).unwrap();
        signature.push(0x01 as u8); // TODO how to properly do this?

        (pubkey.public_key, signature)
    }

    pub fn sign(&self, request: &TransactionMeta) -> Result<TransactionMeta, Error> {
        info!("sign");
        let mut betx: TransactionMeta = match self.network.id() {
            NetworkId::Bitcoin(_) => {
                let tx: bitcoin::Transaction =
                    bitcoin::consensus::deserialize(&hex::decode(&request.hex)?)?;
                let mut out_tx = tx.clone();

                for i in 0..tx.input.len() {
                    let prev_output = tx.input[i].previous_output;
                    info!("input#{} prev_output:{:?}", i, prev_output);
                    let prev_tx = self
                        .db
                        .get_bitcoin_tx(&prev_output.txid)?
                        .ok_or_else(|| Error::Generic("cannot find tx in db".into()))?;
                    let out = prev_tx.output[prev_output.vout as usize].clone();
                    let derivation_path = self
                        .db
                        .get_path(&out.script_pubkey)?
                        .ok_or_else(|| Error::Generic("can't find derivation path".into()))?
                        .into_derivation_path()?;
                    info!(
                        "input#{} prev_output:{:?} derivation_path:{:?}",
                        i, prev_output, derivation_path
                    );

                    let (pk, sig) = self.internal_sign(&tx, i, &derivation_path, out.value);
                    let script_sig = script_sig(&pk);
                    let witness = vec![sig, pk.to_bytes()];
                    info!(
                        "added size len: script_sig:{} witness:{}",
                        script_sig.len(),
                        witness.iter().map(|v| v.len()).sum::<usize>()
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
            NetworkId::Elements(_) => {
                let mut tx: elements::Transaction =
                    elements::encode::deserialize(&hex::decode(&request.hex)?)?;
                self.blind_tx(&mut tx)?;

                for idx in 0..tx.input.len() {
                    let prev_output = tx.input[idx].previous_output;
                    info!("input#{} prev_output:{:?}", idx, prev_output);
                    let prev_tx = self
                        .db
                        .get_liquid_tx(&prev_output.txid)?
                        .ok_or_else(|| Error::Generic("cannot find tx in db".into()))?;
                    let out = prev_tx.output[prev_output.vout as usize].clone();
                    let derivation_path = self
                        .db
                        .get_path(&out.script_pubkey)?
                        .ok_or_else(|| Error::Generic("can't find derivation path".into()))?
                        .into_derivation_path()?;

                    let privkey = self.xprv.derive_priv(&self.secp, &derivation_path).unwrap();
                    let pubkey = ExtendedPubKey::from_private(&self.secp, &privkey);
                    let el_net = self.network.id().get_elements_network().unwrap();
                    let script_code =
                        elements::Address::p2pkh(&pubkey.public_key, None, address_params(el_net))
                            .script_pubkey();
                    let sighash = tx_get_elements_signature_hash(
                        &tx,
                        idx,
                        &script_code,
                        &out.value,
                        bitcoin::SigHashType::All.as_u32(),
                        true, // segwit
                    );
                    let msg = secp256k1::Message::from_slice(&sighash[..]).unwrap();
                    let mut signature =
                        self.secp.sign(&msg, &privkey.private_key.key).serialize_der().to_vec();
                    signature.push(0x01);

                    let redeem_script = script_sig(&pubkey.public_key);
                    let witness = vec![signature, pubkey.public_key.to_bytes()];
                    info!(
                        "added size len: script_sig:{} witness:{}",
                        redeem_script.len(),
                        witness.iter().map(|v| v.len()).sum::<usize>()
                    );
                    tx.input[idx].script_sig = redeem_script;
                    tx.input[idx].witness.script_witness = witness;
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

        let changes_used = request.changes_used.unwrap_or(0);
        if changes_used > 0 {
            info!("tx used {} changes", changes_used);
            self.db.increment_index(Index::Internal, changes_used)?;
        }

        betx.fee = request.fee;
        betx.create_transaction = request.create_transaction.clone();

        Ok(betx)
    }

    fn blind_tx(&self, tx: &mut elements::Transaction) -> Result<(), Error> {
        info!("blind_tx {}", tx.txid());
        let mut input_assets = vec![];
        let mut input_abfs = vec![];
        let mut input_vbfs = vec![];
        let mut input_ags = vec![];
        let mut input_values = vec![];
        for input in tx.input.iter() {
            info!("input {:?}", input);

            let unblinded = self
                .db
                .get_unblinded(&input.previous_output)?
                .ok_or_else(|| Error::Generic("cannot find unblinded values".into()))?;
            info!(
                "unblinded value: {} asset:{}",
                unblinded.value,
                hex::encode(&unblinded.asset[..])
            );

            input_values.push(unblinded.value);
            input_assets.extend(unblinded.asset.to_vec());
            input_abfs.extend(unblinded.abf.to_vec());
            input_vbfs.extend(unblinded.vbf.to_vec());
            let input_asset = asset_generator_from_bytes(&unblinded.asset, &unblinded.abf);
            input_ags.extend(elements::encode::serialize(&input_asset));
        }

        let ct_min_value = self.network.ct_min_value;
        let ct_exp = self.network.ct_exponent;
        let ct_bits = self.network.ct_bits;
        info!("ct params ct_min_value:{} ct_exp:{}, ct_bits:{}", ct_min_value, ct_exp, ct_bits);

        let mut output_blinded_values = vec![];
        for output in tx.output.iter() {
            if !output.is_fee() {
                output_blinded_values.push(output.minimum_value());
            }
        }
        info!("output_blinded_values {:?}", output_blinded_values);
        let mut all_values = vec![];
        all_values.extend(input_values);
        all_values.extend(output_blinded_values);
        let in_num = tx.input.len();
        let out_num = tx.output.len();

        let output_abfs: Vec<Vec<u8>> = (0..out_num - 1).map(|_| random32()).collect();
        let mut output_vbfs: Vec<Vec<u8>> = (0..out_num - 2).map(|_| random32()).collect();

        let mut all_abfs = vec![];
        all_abfs.extend(input_abfs.to_vec());
        all_abfs.extend(output_abfs.iter().cloned().flatten().collect::<Vec<u8>>());

        let mut all_vbfs = vec![];
        all_vbfs.extend(input_vbfs.to_vec());
        all_vbfs.extend(output_vbfs.iter().cloned().flatten().collect::<Vec<u8>>());

        let last_vbf = asset_final_vbf(all_values, in_num as u32, all_abfs, all_vbfs);
        output_vbfs.push(last_vbf.to_vec());

        for (i, mut output) in tx.output.iter_mut().enumerate() {
            info!("output {:?}", output);
            if !output.is_fee() {
                match (output.value, output.asset, output.nonce) {
                    (Value::Explicit(value), Asset::Explicit(asset), Nonce::Confidential(_, _)) => {
                        info!("value: {}", value);
                        let nonce = elements::encode::serialize(&output.nonce);
                        let blinding_pubkey = PublicKey::from_slice(&nonce).unwrap();
                        let blinding_key = asset_blinding_key_to_ec_private_key(
                            self.master_blinding.as_ref().unwrap(),
                            &output.script_pubkey,
                        );
                        let blinding_public_key = ec_public_key_from_private_key(blinding_key);
                        let mut output_abf = [0u8; 32];
                        output_abf.copy_from_slice(&(&output_abfs[i])[..]);
                        let mut output_vbf = [0u8; 32];
                        output_vbf.copy_from_slice(&(&output_vbfs[i])[..]);
                        let asset = asset.clone().into_inner();

                        let output_generator = asset_generator_from_bytes(&asset, &output_abf);
                        let output_value_commitment =
                            asset_value_commitment(value, output_vbf, output_generator);

                        let rangeproof = asset_rangeproof(
                            value,
                            blinding_pubkey.key,
                            blinding_key,
                            asset,
                            output_abf,
                            output_vbf,
                            output_value_commitment,
                            &output.script_pubkey,
                            output_generator,
                            ct_min_value,
                            ct_exp,
                            ct_bits,
                        );
                        debug!("asset: {}", hex::encode(&asset));
                        debug!("output_abf: {}", hex::encode(&output_abf));
                        debug!(
                            "output_generator: {}",
                            hex::encode(&elements::encode::serialize(&output_generator))
                        );
                        debug!("input_assets: {}", hex::encode(&input_assets));
                        debug!("input_abfs: {}", hex::encode(&input_abfs));
                        debug!("input_ags: {}", hex::encode(&input_ags));
                        debug!("in_num: {}", in_num);

                        let surjectionproof = asset_surjectionproof(
                            asset,
                            output_abf,
                            output_generator,
                            output_abf,
                            &input_assets,
                            &input_abfs,
                            &input_ags,
                            in_num,
                        );
                        debug!("surjectionproof: {}", hex::encode(&surjectionproof));

                        let bytes = blinding_public_key.serialize();
                        let byte32: [u8; 32] = bytes[1..].as_ref().try_into().unwrap();
                        output.nonce =
                            elements::confidential::Nonce::Confidential(bytes[0], byte32);
                        output.asset = output_generator;
                        output.value = output_value_commitment;
                        info!(
                            "added size len: surjectionproof:{} rangeproof:{}",
                            surjectionproof.len(),
                            rangeproof.len()
                        );
                        output.witness.surjection_proof = surjectionproof;
                        output.witness.rangeproof = rangeproof;
                    }
                    _ => panic!("create_tx created things not right"),
                }
            }
        }
        Ok(())
    }

    pub fn validate_address(&self, _address: Address) -> Result<bool, Error> {
        // if we managed to get here it means that the address is already valid.
        // only other thing we can check is if it the network is right.

        // TODO implement for both Liquid and Bitcoin address
        //Ok(address.network == self.network)
        unimplemented!("validate not implemented");
    }

    pub fn get_address(&self) -> Result<AddressPointer, Error> {
        let pointer = self.db.increment_index(Index::External, 1)?;
        let address = self.derive_address(&self.xpub, [0, pointer])?.to_string();
        Ok(AddressPointer {
            address,
            pointer,
        })
    }

    pub fn get_asset_icons(&self) -> Result<Option<serde_json::Value>, Error> {
        self.db.get_asset_icons()
    }
    pub fn get_asset_registry(&self) -> Result<Option<serde_json::Value>, Error> {
        self.db.get_asset_registry()
    }
}

fn address_params(net: ElementsNetwork) -> &'static elements::AddressParams {
    match net {
        ElementsNetwork::Liquid => &elements::AddressParams::LIQUID,
        ElementsNetwork::ElementsRegtest => &elements::AddressParams::ELEMENTS,
    }
}

fn script_sig(public_key: &PublicKey) -> Script {
    let internal = Builder::new()
        .push_int(0)
        .push_slice(&PubkeyHash::hash(&public_key.to_bytes())[..])
        .into_script();
    Builder::new().push_slice(internal.as_bytes()).into_script()
}

fn random32() -> Vec<u8> {
    rand::thread_rng().gen::<[u8; 32]>().to_vec()
}

#[cfg(test)]
mod test {
    use crate::interface::script_sig;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::hash160;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
    use bitcoin::util::bip143::SighashComponents;
    use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
    use bitcoin::util::key::PrivateKey;
    use bitcoin::util::key::PublicKey;
    use bitcoin::Script;
    use bitcoin::{Address, Network, Transaction};
    use std::str::FromStr;

    fn p2pkh_hex(pk: &str) -> (PublicKey, Script) {
        let pk = hex::decode(pk).unwrap();
        let pk = PublicKey::from_slice(pk.as_slice()).unwrap();
        let witness_script = Address::p2pkh(&pk, Network::Bitcoin).script_pubkey();
        (pk, witness_script)
    }

    #[test]
    fn test_bip() {
        let secp: Secp256k1<All> = Secp256k1::gen_new();

        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
        let tx_bytes = hex::decode("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000").unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let private_key_bytes =
            hex::decode("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")
                .unwrap();

        let key = SecretKey::from_slice(&private_key_bytes).unwrap();
        let private_key = PrivateKey {
            compressed: true,
            network: Network::Testnet,
            key,
        };

        let (public_key, witness_script) =
            p2pkh_hex("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");
        assert_eq!(
            hex::encode(witness_script.to_bytes()),
            "76a91479091972186c449eb1ded22b78e40d009bdf008988ac"
        );
        let value = 1_000_000_000;
        let comp = SighashComponents::new(&tx);
        let hash = comp.sighash_all(&tx.input[0], &witness_script, value).into_inner();

        assert_eq!(
            &hash[..],
            &hex::decode("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6")
                .unwrap()[..],
        );

        let signature = secp.sign(&Message::from_slice(&hash[..]).unwrap(), &private_key.key);

        //let mut signature = signature.serialize_der().to_vec();
        let signature_hex = format!("{:?}01", signature); // add sighash type at the end
        assert_eq!(signature_hex, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01");

        let script_sig = script_sig(&public_key);

        assert_eq!(
            format!("{}", hex::encode(script_sig.as_bytes())),
            "16001479091972186c449eb1ded22b78e40d009bdf0089"
        );
    }

    #[test]
    fn test_my_tx() {
        let secp: Secp256k1<All> = Secp256k1::gen_new();
        let xprv = ExtendedPrivKey::from_str("tprv8jdzkeuCYeH5hi8k2JuZXJWV8sPNK62ashYyUVD9Euv5CPVr2xUbRFEM4yJBB1yBHZuRKWLeWuzH4ptmvSgjLj81AvPc9JhV4i8wEfZYfPb").unwrap();
        let xpub = ExtendedPubKey::from_private(&secp, &xprv);
        let private_key = xprv.private_key;
        let public_key = xpub.public_key;
        let public_key_bytes = public_key.to_bytes();
        let public_key_str = format!("{}", hex::encode(&public_key_bytes));

        let address = Address::p2shwpkh(&public_key, Network::Testnet);
        assert_eq!(format!("{}", address), "2NCEMwNagVAbbQWNfu7M7DNGxkknVTzhooC");

        assert_eq!(
            public_key_str,
            "0386fe0922d694cef4fa197f9040da7e264b0a0ff38aa2e647545e5a6d6eab5bfc"
        );
        let tx_hex = "020000000001010e73b361dd0f0320a33fd4c820b0c7ac0cae3b593f9da0f0509cc35de62932eb01000000171600141790ee5e7710a06ce4a9250c8677c1ec2843844f0000000002881300000000000017a914cc07bc6d554c684ea2b4af200d6d988cefed316e87a61300000000000017a914fda7018c5ee5148b71a767524a22ae5d1afad9a9870247304402206675ed5fb86d7665eb1f7950e69828d0aa9b41d866541cedcedf8348563ba69f022077aeabac4bd059148ff41a36d5740d83163f908eb629784841e52e9c79a3dbdb01210386fe0922d694cef4fa197f9040da7e264b0a0ff38aa2e647545e5a6d6eab5bfc00000000";

        let tx_bytes = hex::decode(tx_hex).unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let (_, witness_script) = p2pkh_hex(&public_key_str);
        assert_eq!(
            hex::encode(witness_script.to_bytes()),
            "76a9141790ee5e7710a06ce4a9250c8677c1ec2843844f88ac"
        );
        let value = 10_202;
        let comp = SighashComponents::new(&tx);
        let hash = comp.sighash_all(&tx.input[0], &witness_script, value);

        assert_eq!(
            &hash.into_inner()[..],
            &hex::decode("58b15613fc1701b2562430f861cdc5803531d08908df531082cf1828cd0b8995")
                .unwrap()[..],
        );

        let signature = secp.sign(&Message::from_slice(&hash[..]).unwrap(), &private_key.key);

        //let mut signature = signature.serialize_der().to_vec();
        let signature_hex = format!("{:?}01", signature); // add sighash type at the end
        let signature = hex::decode(&signature_hex).unwrap();

        assert_eq!(signature_hex, "304402206675ed5fb86d7665eb1f7950e69828d0aa9b41d866541cedcedf8348563ba69f022077aeabac4bd059148ff41a36d5740d83163f908eb629784841e52e9c79a3dbdb01");
        assert_eq!(tx.input[0].witness[0], signature);
        assert_eq!(tx.input[0].witness[1], public_key_bytes);

        let script_sig = script_sig(&public_key);
        assert_eq!(tx.input[0].script_sig, script_sig);
    }
}
