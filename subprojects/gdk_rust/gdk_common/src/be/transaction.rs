use crate::be::*;
use crate::error::Error;
use crate::model::{Balances, TransactionType};
use crate::scripts::{p2pkh_script, ScriptType};
use crate::NetworkId;
use bitcoin::amount::Amount;
use bitcoin::blockdata::script::Instruction;
use bitcoin::consensus::encode::deserialize as btc_des;
use bitcoin::consensus::encode::serialize as btc_ser;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, ecdsa::Signature, Message, Secp256k1};
use bitcoin::sighash::SighashCache;
use bitcoin::{CompressedPublicKey, Sequence};
use elements::encode::deserialize as elm_des;
use elements::encode::serialize as elm_ser;
use elements::hex::ToHex;
use log::trace;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

pub const DUST_VALUE: u64 = 546;

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum BETransaction {
    Bitcoin(bitcoin::Transaction),
    Elements(elements::Transaction),
}

impl BETransaction {
    pub fn is_elements(&self) -> bool {
        match self {
            BETransaction::Bitcoin(_) => false,
            BETransaction::Elements(_) => true,
        }
    }

    pub fn from_hex(hex: &str, id: NetworkId) -> Result<Self, crate::error::Error> {
        Self::deserialize(&Vec::<u8>::from_hex(hex)?, id)
    }

    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Bitcoin(tx) => btc_ser(tx),
            Self::Elements(tx) => elm_ser(tx),
        }
    }

    pub fn deserialize(bytes: &[u8], id: NetworkId) -> Result<Self, crate::error::Error> {
        Ok(match id {
            NetworkId::Bitcoin(_) => Self::Bitcoin(btc_des(bytes)?),
            NetworkId::Elements(_) => Self::Elements(elm_des(bytes)?),
        })
    }

    pub fn txid(&self) -> BETxid {
        match self {
            Self::Bitcoin(tx) => tx.compute_txid().into(),
            Self::Elements(tx) => tx.txid().into(),
        }
    }

    pub fn version(&self) -> u32 {
        match self {
            Self::Bitcoin(tx) => tx.version.0 as u32,
            Self::Elements(tx) => tx.version,
        }
    }

    pub fn lock_time(&self) -> u32 {
        match self {
            Self::Bitcoin(tx) => tx.lock_time.to_consensus_u32(),
            Self::Elements(tx) => tx.lock_time.to_consensus_u32(),
        }
    }

    pub fn previous_outputs(&self) -> Vec<BEOutPoint> {
        match self {
            Self::Bitcoin(tx) => {
                tx.input.iter().map(|i| BEOutPoint::Bitcoin(i.previous_output)).collect()
            }
            Self::Elements(tx) => {
                tx.input.iter().map(|i| BEOutPoint::Elements(i.previous_output)).collect()
            }
        }
    }

    pub fn previous_output_txids(&self) -> Vec<BETxid> {
        // every previous output, but skip coinbase
        match self {
            Self::Bitcoin(tx) => tx
                .input
                .iter()
                .filter(|i| !i.previous_output.is_null())
                .map(|i| i.previous_output.txid.into())
                .collect(),
            // FIXME: use elements::OutPoint::is_null once available upstream
            Self::Elements(tx) => tx
                .input
                .iter()
                .filter(|i| {
                    !(i.previous_output.vout == u32::max_value()
                        && i.previous_output.txid == elements::Txid::all_zeros())
                })
                .map(|i| i.previous_output.txid.into())
                .collect(),
        }
    }

    pub fn previous_sequence_and_outpoints(&self) -> Vec<(u32, BEOutPoint)> {
        match self {
            Self::Bitcoin(tx) => tx
                .input
                .iter()
                .map(|i| (i.sequence.to_consensus_u32(), BEOutPoint::Bitcoin(i.previous_output)))
                .collect(),
            Self::Elements(tx) => tx
                .input
                .iter()
                .map(|i| (i.sequence.to_consensus_u32(), BEOutPoint::Elements(i.previous_output)))
                .collect(),
        }
    }

    pub fn output_len(&self) -> usize {
        match self {
            Self::Bitcoin(tx) => tx.output.len(),
            Self::Elements(tx) => tx.output.len(),
        }
    }

    pub fn outpoint(&self, vout: u32) -> BEOutPoint {
        match self {
            Self::Bitcoin(tx) => BEOutPoint::new_bitcoin(tx.compute_txid(), vout),
            Self::Elements(tx) => BEOutPoint::new_elements(tx.txid(), vout),
        }
    }

    pub fn output_value(
        &self,
        vout: u32,
        all_unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
    ) -> Option<u64> {
        match self {
            Self::Bitcoin(tx) => Some(tx.output[vout as usize].value.to_sat()),
            Self::Elements(tx) => {
                let outpoint = elements::OutPoint {
                    txid: tx.txid(),
                    vout,
                };
                all_unblinded.get(&outpoint).map(|unblinded| unblinded.value)
            }
        }
    }

    pub fn output_script(&self, vout: u32) -> BEScript {
        match self {
            Self::Bitcoin(tx) => BEScript::Bitcoin(tx.output[vout as usize].script_pubkey.clone()),
            Self::Elements(tx) => {
                BEScript::Elements(tx.output[vout as usize].script_pubkey.clone())
            }
        }
    }

    pub fn output_address(&self, vout: u32, network: NetworkId) -> Option<String> {
        match (self, network) {
            (BETransaction::Bitcoin(tx), NetworkId::Bitcoin(net)) => {
                let script = &tx.output[vout as usize].script_pubkey;
                bitcoin::Address::from_script(script, net).map(|a| a.to_string()).ok()
            }
            (BETransaction::Elements(tx), NetworkId::Elements(net)) => {
                // Note we are returning the unconfidential address, because recipient blinding pub key is not in the transaction
                let script = &tx.output[vout as usize].script_pubkey;
                let params = net.address_params();
                elements::Address::from_script(script, None, params).map(|a| a.to_string())
            }
            _ => panic!("Invalid BETransaction and NetworkId combination"),
        }
    }

    pub fn output_asset(
        &self,
        vout: u32,
        all_unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
    ) -> Option<elements::issuance::AssetId> {
        match self {
            Self::Bitcoin(_) => None,
            Self::Elements(tx) => {
                let outpoint = elements::OutPoint {
                    txid: tx.txid(),
                    vout,
                };
                all_unblinded.get(&outpoint).map(|unblinded| unblinded.asset.clone())
            }
        }
    }

    pub fn output_assetblinder_hex(
        &self,
        vout: u32,
        all_unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
    ) -> Option<String> {
        match self {
            Self::Bitcoin(_) => None,
            Self::Elements(tx) => {
                let outpoint = elements::OutPoint {
                    txid: tx.txid(),
                    vout,
                };
                all_unblinded.get(&outpoint).map(|unblinded| unblinded.asset_bf.to_hex())
            }
        }
    }

    pub fn output_amountblinder_hex(
        &self,
        vout: u32,
        all_unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
    ) -> Option<String> {
        match self {
            Self::Bitcoin(_) => None,
            Self::Elements(tx) => {
                let outpoint = elements::OutPoint {
                    txid: tx.txid(),
                    vout,
                };
                all_unblinded.get(&outpoint).map(|unblinded| unblinded.value_bf.to_hex())
            }
        }
    }

    pub fn output_is_confidential(&self, vout: u32) -> bool {
        match self {
            Self::Bitcoin(_) => false,
            Self::Elements(tx) => {
                let output = &tx.output[vout as usize];
                output.asset.is_confidential() && output.value.is_confidential()
            }
        }
    }

    pub fn get_weight(&self) -> usize {
        match self {
            Self::Bitcoin(tx) => tx.weight().to_wu() as usize,
            Self::Elements(tx) => tx.weight(),
        }
    }

    /// calculate transaction fee,
    /// for bitcoin it requires all previous output to get input values.
    /// for elements,
    ///     for complete transactions looks at the explicit fee output,
    ///     for incomplete tx (without explicit fee output) take the sum previous outputs value, previously unblinded
    ///                       and use the outputs value that must be still unblinded
    pub fn fee(
        &self,
        all_txs: &BETransactions,
        all_unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
        policy_asset: &Option<elements::issuance::AssetId>,
    ) -> Result<u64, Error> {
        match self {
            Self::Bitcoin(tx) => {
                if tx.is_coinbase() {
                    Ok(0)
                } else {
                    let sum_inputs = sum_inputs(tx, all_txs);
                    let sum_outputs: u64 = tx.output.iter().map(|o| o.value.to_sat()).sum();
                    sum_inputs
                        .checked_sub(sum_outputs)
                        .ok_or_else(|| Error::Generic("unexpected tx balance".into()))
                }
            }
            Self::Elements(tx) => {
                if tx.is_coinbase() {
                    Ok(0)
                } else if tx.output.iter().any(|o| o.is_fee()) {
                    let policy_asset = policy_asset
                        .ok_or_else(|| Error::Generic("Missing policy asset".into()))?;
                    Ok(tx.fee_in(policy_asset))
                } else {
                    // while we are not filtering assets, the following holds for valid tx because
                    // sum of input assets = sum of output assets
                    let sum_outputs: u64 = tx.output.iter().map(|o| o.minimum_value()).sum();
                    let sum_inputs: u64 = tx
                        .input
                        .iter()
                        .map(|i| BEOutPoint::Elements(i.previous_output))
                        .filter_map(|o| all_txs.get_previous_output_value(&o, all_unblinded))
                        .sum();

                    sum_inputs
                        .checked_sub(sum_outputs)
                        .ok_or_else(|| Error::Generic("unexpected tx balance".into()))
                }
            }
        }
    }

    pub fn rbf_optin(&self) -> bool {
        match self {
            Self::Bitcoin(tx) => tx.input.iter().any(|e| e.sequence < Sequence(0xffff_fffe)),
            Self::Elements(tx) => {
                tx.input.iter().any(|e| e.sequence < elements::Sequence(0xffff_fffe))
            }
        }
    }

    pub fn is_redeposit(
        &self,
        all_scripts: &HashMap<BEScript, DerivationPath>,
        all_txs: &BETransactions,
    ) -> bool {
        match self {
            Self::Bitcoin(tx) => {
                let previous_scripts: Vec<BEScript> = tx
                    .input
                    .iter()
                    .filter_map(|i| {
                        all_txs.get_previous_output_script_pubkey(&i.previous_output.into())
                    })
                    .collect();

                previous_scripts.len() == tx.input.len()
                    && previous_scripts.iter().all(|i| all_scripts.contains_key(i))
                    && tx
                        .output
                        .iter()
                        .all(|o| all_scripts.contains_key(&o.script_pubkey.clone().into()))
            }
            Self::Elements(tx) => {
                let previous_scripts: Vec<BEScript> = tx
                    .input
                    .iter()
                    .filter_map(|i| {
                        all_txs.get_previous_output_script_pubkey(&i.previous_output.into())
                    })
                    .collect();

                previous_scripts.len() == tx.input.len()
                    && previous_scripts.iter().all(|i| all_scripts.contains_key(i))
                    && tx
                        .output
                        .iter()
                        .filter(|o| !o.is_fee())
                        .all(|o| all_scripts.contains_key(&o.script_pubkey.clone().into()))
            }
        }
    }

    pub fn my_balance_changes(
        &self,
        all_txs: &BETransactions,
        all_scripts: &HashMap<BEScript, DerivationPath>,
        all_unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
    ) -> Balances {
        match self {
            Self::Bitcoin(tx) => {
                let mut result = HashMap::new();
                let mut my_out: i64 = 0;
                for input in tx.input.iter() {
                    let outpoint = input.previous_output.clone().into();
                    let script = all_txs.get_previous_output_script_pubkey(&outpoint);
                    if let Some(script) = script {
                        if all_scripts.get(&script).is_some() {
                            my_out += all_txs
                                .get_previous_output_value(&outpoint, &all_unblinded)
                                .unwrap_or(0) as i64;
                        }
                    }
                }
                let my_in: i64 = tx
                    .output
                    .iter()
                    .filter(|o| all_scripts.contains_key(&o.script_pubkey.clone().into()))
                    .map(|o| o.value.to_sat() as i64)
                    .sum();
                result.insert("btc".to_string(), my_in - my_out);
                result
            }
            Self::Elements(tx) => {
                trace!(
                    "tx_id: {} my_balances elements all_unblinded.len(): {:?}",
                    tx.txid(),
                    all_unblinded
                );
                let mut result = HashMap::new();
                for input in tx.input.iter() {
                    let outpoint = input.previous_output;
                    if let Some(unblinded) = all_unblinded.get(&outpoint) {
                        trace!(
                            "tx_id: {} unblinded previous output {} {}",
                            tx.txid(),
                            outpoint,
                            unblinded.value
                        );
                        let asset_id_str = unblinded.asset.to_hex();
                        *result.entry(asset_id_str).or_default() -= unblinded.value as i64;
                        // TODO check overflow
                    }
                }
                for i in 0..tx.output.len() as u32 {
                    let outpoint = elements::OutPoint {
                        txid: tx.txid(),
                        vout: i,
                    };
                    if let Some(unblinded) = all_unblinded.get(&outpoint) {
                        trace!(
                            "tx_id: {} unblinded output {} {}",
                            tx.txid(),
                            outpoint,
                            unblinded.value
                        );
                        let asset_id_str = unblinded.asset.to_hex();
                        *result.entry(asset_id_str).or_default() += unblinded.value as i64;
                        // TODO check overflow
                    }
                }

                // we don't want to see redeposited assets
                return result.into_iter().filter(|&(_, v)| v != 0).collect();
            }
        }
    }

    pub fn type_(&self, balances: &Balances, is_redeposit: bool) -> TransactionType {
        // TODO how do we label issuance tx?
        let negatives = balances.iter().filter(|(_, v)| **v < 0).count();
        let positives = balances.iter().filter(|(_, v)| **v > 0).count();
        if balances.is_empty() && self.is_elements() {
            TransactionType::NotUnblindable
        } else if is_redeposit {
            TransactionType::Redeposit
        } else if positives > 0 && negatives > 0 {
            TransactionType::Mixed
        } else if positives > 0 {
            TransactionType::Incoming
        } else {
            TransactionType::Outgoing
        }
    }

    /// Verify the given transaction input. Only supports the script types that
    /// can be managed using gdk-rust. Implemented for Bitcoin only.
    ///
    /// The `hashcache` argument should be initialized as None for every tx and
    /// reused for its inputs.
    pub fn verify_input_sig<'a>(
        &'a self,
        secp: &Secp256k1<impl secp256k1::Verification>,
        hashcache: &mut Option<SighashCache<&'a bitcoin::Transaction>>,
        inv: usize,
        public_key: &CompressedPublicKey,
        value: u64,
        script_type: ScriptType,
    ) -> Result<(), Error> {
        let tx = if let BETransaction::Bitcoin(tx) = self {
            tx
        } else {
            // Signature verification is currently only used on Bitcoin
            unimplemented!();
        };
        let mut sig = match script_type {
            ScriptType::P2wpkh | ScriptType::P2shP2wpkh => {
                tx.input[inv].witness.to_vec().get(0).cloned().ok_or(Error::InputValidationFailed)
            }
            ScriptType::P2pkh => match tx.input[inv].script_sig.instructions().next() {
                Some(Ok(Instruction::PushBytes(sig))) => Ok(sig.as_bytes().to_vec()),
                _ => Err(Error::InputValidationFailed),
            },
        }?;

        let sighash = sig.pop().ok_or_else(|| Error::InputValidationFailed)?;
        let sighash = bitcoin::sighash::EcdsaSighashType::from_standard(sighash as u32)?;

        let hash = if script_type.is_segwit() {
            let amount = Amount::from_sat(value);
            let script_pubkey =
                bitcoin::Address::p2wpkh(&public_key, bitcoin::Network::Bitcoin).script_pubkey();
            let hashcache = hashcache.get_or_insert_with(|| SighashCache::new(tx));
            hashcache.p2wpkh_signature_hash(inv, &script_pubkey, amount, sighash)?.to_byte_array()
        } else {
            let script_pubkey = p2pkh_script(public_key);
            let sighash_cache = SighashCache::new(tx);
            sighash_cache
                .legacy_signature_hash(inv, &script_pubkey, sighash.to_u32())?
                .to_byte_array()
        };
        let message = Message::from_digest(hash);

        secp.verify_ecdsa(&message, &Signature::from_der(&sig)?, &public_key.0)?;
        Ok(())
    }

    pub fn creates_script_pubkey(&self, script_pubkey: &BEScript) -> bool {
        (0..self.output_len() as u32).any(|vout| &self.output_script(vout) == script_pubkey)
    }

    pub fn spends_script_pubkey(&self, script_pubkey: &BEScript, all_txs: &BETransactions) -> bool {
        for (_, outpoint) in self.previous_sequence_and_outpoints() {
            if let Some(s) = all_txs.get_previous_output_script_pubkey(&outpoint) {
                if &s == script_pubkey {
                    return true;
                }
            }
        }
        false
    }
}

fn sum_inputs(tx: &bitcoin::Transaction, all_txs: &BETransactions) -> u64 {
    tx.input
        .iter()
        .map(|i| BEOutPoint::Bitcoin(i.previous_output))
        .filter_map(|o| all_txs.get_previous_output_value(&o, &HashMap::new())) //no need of unblinded since this fn is bitcoin only
        .sum()
}

#[derive(Default, Serialize, Deserialize)]
pub struct BETransactions(HashMap<BETxid, BETransactionEntry>);

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BETransactionEntry {
    pub tx: BETransaction,
    pub size: usize,
    pub weight: usize,
}

impl BETransactionEntry {
    pub fn fee_rate(&self, fee: u64) -> u64 {
        (fee as f64 / self.weight as f64 * 4000.0) as u64
    }
}

impl Deref for BETransactions {
    type Target = HashMap<BETxid, BETransactionEntry>;
    fn deref(&self) -> &<Self as Deref>::Target {
        &self.0
    }
}
impl DerefMut for BETransactions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl BETransactions {
    pub fn get_previous_output_script_pubkey(&self, outpoint: &BEOutPoint) -> Option<BEScript> {
        self.0.get(&outpoint.txid()).map(|txe| txe.tx.output_script(outpoint.vout()))
    }

    pub fn get_previous_output_address(
        &self,
        outpoint: &BEOutPoint,
        network: NetworkId,
    ) -> Option<String> {
        match self.0.get(&outpoint.txid()) {
            None => None,
            Some(txe) => txe.tx.output_address(outpoint.vout(), network),
        }
    }

    pub fn get_previous_output_value(
        &self,
        outpoint: &BEOutPoint,
        all_unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
    ) -> Option<u64> {
        match self.0.get(&outpoint.txid()) {
            None => None,
            Some(txe) => txe.tx.output_value(outpoint.vout(), &all_unblinded),
        }
    }

    pub fn get_previous_output_asset(
        &self,
        outpoint: elements::OutPoint,
        all_unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
    ) -> Option<elements::issuance::AssetId> {
        match self.0.get(&outpoint.txid.into()) {
            None => None,
            Some(txe) => txe.tx.output_asset(outpoint.vout, &all_unblinded),
        }
    }

    pub fn get_previous_output_assetblinder_hex(
        &self,
        outpoint: elements::OutPoint,
        all_unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
    ) -> Option<String> {
        match self.0.get(&outpoint.txid.into()) {
            None => None,
            Some(txe) => txe.tx.output_assetblinder_hex(outpoint.vout, &all_unblinded),
        }
    }

    pub fn get_previous_output_amountblinder_hex(
        &self,
        outpoint: elements::OutPoint,
        all_unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
    ) -> Option<String> {
        match self.0.get(&outpoint.txid.into()) {
            None => None,
            Some(txe) => txe.tx.output_amountblinder_hex(outpoint.vout, &all_unblinded),
        }
    }
}

impl From<BETransaction> for BETransactionEntry {
    fn from(tx: BETransaction) -> Self {
        let size = tx.serialize().len();
        let weight = tx.get_weight();
        Self {
            tx,
            size,
            weight,
        }
    }
}
