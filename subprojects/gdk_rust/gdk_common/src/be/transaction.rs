use crate::be::*;
use crate::error::Error;
use crate::model::Balances;
use crate::scripts::{p2pkh_script, ScriptType};
use crate::NetworkId;
use crate::{bail, ensure};
use bitcoin::blockdata::script::Instruction;
use bitcoin::consensus::encode::deserialize as btc_des;
use bitcoin::consensus::encode::serialize as btc_ser;
use bitcoin::hashes::hex::ToHex;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, Message, Secp256k1, Signature};
use bitcoin::util::bip143::SigHashCache;
use bitcoin::{PublicKey, SigHashType};
use elements::confidential;
use elements::confidential::{Asset, Value};
use elements::encode::deserialize as elm_des;
use elements::encode::serialize as elm_ser;
use elements::{TxInWitness, TxOutWitness};
use log::{info, trace};
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

pub const DUST_VALUE: u64 = 546;

// 52-bit rangeproof size
const DEFAULT_RANGEPROOF_SIZE: usize = 4174;
// 3-input ASP size
const DEFAULT_SURJECTIONPROOF_SIZE: usize = 135;

#[derive(Debug, Clone, Serialize, Deserialize, Hash)]
pub enum BETransaction {
    Bitcoin(bitcoin::Transaction),
    Elements(elements::Transaction),
}

impl BETransaction {
    pub fn new(id: NetworkId) -> Self {
        match id {
            NetworkId::Bitcoin(_) => BETransaction::Bitcoin(bitcoin::Transaction {
                version: 2,
                lock_time: 0,
                input: vec![],
                output: vec![],
            }),
            NetworkId::Elements(_) => BETransaction::Elements(elements::Transaction {
                version: 2,
                lock_time: 0,
                input: vec![],
                output: vec![],
            }),
        }
    }

    pub fn from_hex(hex: &str, id: NetworkId) -> Result<Self, crate::error::Error> {
        Self::deserialize(&hex::decode(hex)?, id)
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

    /// strip witness from the transaction, txid doesn't change
    pub fn strip_witness(&mut self) {
        let before_hash = self.txid();
        match self {
            Self::Bitcoin(tx) => {
                for input in tx.input.iter_mut() {
                    input.witness.clear();
                }
            }
            Self::Elements(tx) => {
                for input in tx.input.iter_mut() {
                    input.witness = TxInWitness::default();
                }
                for output in tx.output.iter_mut() {
                    output.witness = TxOutWitness::default();
                }
            }
        }
        assert_eq!(self.txid(), before_hash, "hash doesn't match after stripping witness");
    }

    pub fn txid(&self) -> BETxid {
        match self {
            Self::Bitcoin(tx) => tx.txid().into(),
            Self::Elements(tx) => tx.txid().into(),
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
                        && i.previous_output.txid == Default::default())
                })
                .map(|i| i.previous_output.txid.into())
                .collect(),
        }
    }

    pub fn input_len(&self) -> usize {
        match self {
            Self::Bitcoin(tx) => tx.input.len(),
            Self::Elements(tx) => tx.input.len(),
        }
    }

    pub fn output_len(&self) -> usize {
        match self {
            Self::Bitcoin(tx) => tx.output.len(),
            Self::Elements(tx) => tx.output.len(),
        }
    }

    pub fn output_value(
        &self,
        vout: u32,
        all_unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
    ) -> Option<u64> {
        match self {
            Self::Bitcoin(tx) => Some(tx.output[vout as usize].value),
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
                bitcoin::Address::from_script(script, net).map(|a| a.to_string())
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

    pub fn get_weight(&self) -> usize {
        match self {
            Self::Bitcoin(tx) => tx.get_weight(),
            Self::Elements(tx) => tx.get_weight(),
        }
    }

    pub fn get_size(&self) -> usize {
        match self {
            Self::Bitcoin(tx) => tx.get_size(),
            Self::Elements(tx) => tx.get_size(),
        }
    }

    /// asset is none for bitcoin, in liquid must be Some
    pub fn add_output(
        &mut self,
        address: &str,
        value: u64,
        asset: Option<elements::issuance::AssetId>,
        id: NetworkId,
    ) -> Result<(), Error> {
        match (self, id) {
            (BETransaction::Bitcoin(tx), NetworkId::Bitcoin(_)) => {
                let script_pubkey = bitcoin::Address::from_str(&address)?.script_pubkey();
                let new_out = bitcoin::TxOut {
                    script_pubkey,
                    value,
                };
                tx.output.push(new_out);
            }
            (BETransaction::Elements(tx), NetworkId::Elements(net)) => {
                let address = elements::Address::parse_with_params(&address, net.address_params())
                    .map_err(|_| Error::InvalidAddress)?;
                let blinding_pubkey = address.blinding_pubkey.ok_or(Error::InvalidAddress)?;
                let asset_id =
                    asset.expect("add_output must be called with a non empty asset in liquid");
                let new_out = elements::TxOut {
                    asset: confidential::Asset::Explicit(asset_id),
                    value: confidential::Value::Explicit(value),
                    nonce: confidential::Nonce::Confidential(blinding_pubkey),
                    script_pubkey: address.script_pubkey(),
                    witness: TxOutWitness::default(),
                };
                tx.output.push(new_out);
            }
            _ => panic!("Invalid BETransaction and NetworkId combination"),
        }
        Ok(())
    }

    pub fn scramble(&mut self) {
        let mut rng = thread_rng();
        match self {
            BETransaction::Bitcoin(tx) => {
                tx.input.shuffle(&mut rng);
                tx.output.shuffle(&mut rng);
            }
            BETransaction::Elements(tx) => {
                tx.input.shuffle(&mut rng);
                tx.output.shuffle(&mut rng);
            }
        }
    }

    /// estimates the fee of the final transaction given the `fee_rate`
    /// called when the tx is being built and miss things like signatures and changes outputs.
    pub fn estimated_fee(&self, fee_rate: f64, more_changes: u8, script_type: ScriptType) -> u64 {
        let dummy_tx = self.clone();
        match dummy_tx {
            BETransaction::Bitcoin(mut tx) => {
                for input in tx.input.iter_mut() {
                    input.witness = script_type.mock_witness();
                    input.script_sig = script_type.mock_script_sig().into();
                }
                for _ in 0..more_changes {
                    tx.output.push(bitcoin::TxOut {
                        value: 0,
                        script_pubkey: script_type.mock_script_pubkey().into(),
                    })
                }
                let vbytes = tx.get_weight() as f64 / 4.0;
                let fee_val = (vbytes * fee_rate * 1.02) as u64; // increasing estimated fee by 2% to stay over relay fee TODO improve fee estimation and lower this
                info!(
                    "DUMMYTX inputs:{} outputs:{} num_changes:{} vbytes:{} fee_val:{}",
                    tx.input.len(),
                    tx.output.len(),
                    more_changes,
                    vbytes,
                    fee_val
                );
                fee_val
            }
            BETransaction::Elements(mut tx) => {
                for input in tx.input.iter_mut() {
                    let mut tx_wit = TxInWitness::default();
                    tx_wit.script_witness = script_type.mock_witness();
                    input.witness = tx_wit;
                    input.script_sig = script_type.mock_script_sig().into();
                }
                let mock_asset = confidential::Asset::Confidential(mock_asset());
                let mock_value = confidential::Value::Confidential(mock_value());
                let mock_nonce = confidential::Nonce::Confidential(mock_pubkey());
                for _ in 0..more_changes {
                    let new_out = elements::TxOut {
                        asset: mock_asset,
                        value: mock_value,
                        nonce: mock_nonce,
                        script_pubkey: script_type.mock_script_pubkey().into(),
                        ..Default::default()
                    };
                    tx.output.push(new_out);
                }

                let proofs_size = (DEFAULT_RANGEPROOF_SIZE + DEFAULT_SURJECTIONPROOF_SIZE)
                    * tx.output.iter().filter(|o| o.witness.is_empty()).count();

                tx.output.push(elements::TxOut::new_fee(
                    0,
                    elements::issuance::AssetId::from_slice(&[0u8; 32]).unwrap(),
                )); // mockup for the explicit fee output
                let vbytes = (tx.get_weight() + proofs_size) as f64 / 4.0;
                let fee_val = (vbytes * fee_rate * 1.03) as u64; // increasing estimated fee by 3% to stay over relay fee, TODO improve fee estimation and lower this
                info!(
                    "DUMMYTX inputs:{} outputs:{} num_changes:{} vbytes:{} fee_val:{}",
                    tx.input.len(),
                    tx.output.len(),
                    more_changes,
                    vbytes,
                    fee_val
                );
                fee_val
            }
        }
    }

    pub fn estimated_changes(
        &self,
        send_all: bool,
        all_txs: &BETransactions,
        unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
    ) -> u8 {
        match self {
            Self::Bitcoin(_) => 1u8 - send_all as u8,
            Self::Elements(tx) => {
                let mut different_assets = HashSet::new();
                for input in tx.input.iter() {
                    let asset = all_txs
                        .get_previous_output_asset(input.previous_output, unblinded)
                        .unwrap();
                    different_assets.insert(asset);
                }
                if different_assets.is_empty() {
                    0
                } else {
                    different_assets.len() as u8 - send_all as u8
                }
            }
        }
    }

    /// return a Vector with the amount needed for this transaction to be valid
    /// for bitcoin it contains max 1 element eg ("btc", 100)
    /// for elements could contain more than 1 element, 1 for each asset, with the policy asset last
    pub fn needs(
        &self,
        fee_rate: f64,
        no_change: bool,
        policy_asset: Option<elements::issuance::AssetId>,
        all_txs: &BETransactions,
        unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
        script_type: ScriptType,
    ) -> Vec<AssetValue> {
        match self {
            Self::Bitcoin(tx) => {
                let sum_inputs = sum_inputs(tx, all_txs);
                let sum_outputs: u64 = tx.output.iter().map(|o| o.value).sum();
                let estimated_fee = self.estimated_fee(
                    fee_rate,
                    self.estimated_changes(no_change, all_txs, unblinded),
                    script_type,
                ); // send all does not create change
                if sum_outputs + estimated_fee > sum_inputs {
                    vec![AssetValue::new_bitcoin(sum_outputs + estimated_fee - sum_inputs)]
                } else {
                    vec![]
                }
            }
            Self::Elements(tx) => {
                let policy_asset = policy_asset.expect("policy asset empty in elements");
                let mut outputs: HashMap<elements::issuance::AssetId, u64> = HashMap::new();
                for output in tx.output.iter() {
                    match (output.asset, output.value) {
                        (Asset::Explicit(asset), Value::Explicit(value)) => {
                            *outputs.entry(asset.clone()).or_insert(0) += value;
                        }
                        _ => panic!("asset and value should be explicit here"),
                    }
                }

                let mut inputs: HashMap<elements::issuance::AssetId, u64> = HashMap::new();

                for input in tx.input.iter() {
                    let asset = all_txs
                        .get_previous_output_asset(input.previous_output, unblinded)
                        .unwrap();
                    let value = all_txs
                        .get_previous_output_value(
                            &BEOutPoint::Elements(input.previous_output),
                            unblinded,
                        )
                        .unwrap();
                    *inputs.entry(asset).or_insert(0) += value;
                }

                let estimated_fee = self.estimated_fee(
                    fee_rate,
                    self.estimated_changes(no_change, all_txs, unblinded),
                    script_type,
                );
                *outputs.entry(policy_asset.clone()).or_insert(0) += estimated_fee;

                let mut result = vec![];
                for (asset, value) in outputs.iter() {
                    if let Some(sum) = value.checked_sub(inputs.remove(asset).unwrap_or(0)) {
                        if sum > 0 {
                            result.push(AssetValue::new(*asset, sum));
                        }
                    }
                }

                if let Some(index) = result.iter().position(|e| e.asset == Some(policy_asset)) {
                    let last_index = result.len() - 1;
                    if index != last_index {
                        result.swap(index, last_index); // put the policy asset last
                    }
                }
                result
            }
        }
    }

    /// return a Vector with changes of this transaction
    /// requires inputs are greater than outputs for earch asset
    pub fn changes(
        &self,
        estimated_fee: u64,
        policy_asset: Option<elements::issuance::AssetId>,
        all_txs: &BETransactions,
        unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
    ) -> Vec<AssetValue> {
        match self {
            Self::Bitcoin(tx) => {
                let sum_inputs = sum_inputs(tx, all_txs);
                let sum_outputs: u64 = tx.output.iter().map(|o| o.value).sum();
                let change_value = sum_inputs - sum_outputs - estimated_fee;
                if change_value > DUST_VALUE {
                    vec![AssetValue::new_bitcoin(change_value)]
                } else {
                    vec![]
                }
            }
            Self::Elements(tx) => {
                let mut outputs_asset_amounts: HashMap<elements::issuance::AssetId, u64> =
                    HashMap::new();
                for output in tx.output.iter() {
                    match (output.asset, output.value) {
                        (Asset::Explicit(asset), Value::Explicit(value)) => {
                            *outputs_asset_amounts.entry(asset).or_insert(0) += value;
                        }
                        _ => panic!("asset and value should be explicit here"),
                    }
                }

                let mut inputs_asset_amounts: HashMap<elements::issuance::AssetId, u64> =
                    HashMap::new();
                for input in tx.input.iter() {
                    let asset = all_txs
                        .get_previous_output_asset(input.previous_output, unblinded)
                        .unwrap();
                    let value = all_txs
                        .get_previous_output_value(
                            &BEOutPoint::Elements(input.previous_output),
                            unblinded,
                        )
                        .unwrap();
                    *inputs_asset_amounts.entry(asset).or_insert(0) += value;
                }
                let mut result = vec![];
                for (asset, value) in inputs_asset_amounts.iter() {
                    let mut sum = value - outputs_asset_amounts.remove(asset).unwrap_or(0);
                    if asset == &policy_asset.unwrap() {
                        // from a purely privacy perspective could make sense to always create the change output in liquid, so min change = 0
                        // however elements core use the dust anyway for 2 reasons: rebasing from core and economical considerations
                        sum -= estimated_fee;
                        if sum > DUST_VALUE {
                            // we apply dust rules for liquid bitcoin as elements do
                            result.push(AssetValue::new(*asset, sum));
                        }
                    } else if sum > 0 {
                        result.push(AssetValue::new(*asset, sum));
                    }
                }
                assert!(outputs_asset_amounts.is_empty());
                result
            }
        }
    }

    pub fn add_fee_if_elements(
        &mut self,
        value: u64,
        policy_asset: &Option<elements::issuance::AssetId>,
    ) -> Result<(), Error> {
        if let BETransaction::Elements(tx) = self {
            let policy_asset =
                policy_asset.ok_or_else(|| Error::Generic("Missing policy asset".into()))?;
            let new_out = elements::TxOut {
                asset: confidential::Asset::Explicit(policy_asset),
                value: confidential::Value::Explicit(value),
                ..Default::default()
            };
            tx.output.push(new_out);
        }
        Ok(())
    }

    pub fn add_input(&mut self, outpoint: BEOutPoint) {
        match (outpoint, self) {
            (BEOutPoint::Bitcoin(outpoint), BETransaction::Bitcoin(tx)) => {
                let new_in = bitcoin::TxIn {
                    previous_output: outpoint,
                    script_sig: bitcoin::Script::default(),
                    sequence: 0xffff_fffd, // nSequence is disabled, nLocktime is enabled, RBF is signaled.
                    witness: vec![],
                };
                tx.input.push(new_in);
            }
            (BEOutPoint::Elements(outpoint), BETransaction::Elements(tx)) => {
                let new_in = elements::TxIn {
                    previous_output: outpoint,
                    is_pegin: false,
                    has_issuance: false,
                    script_sig: elements::Script::default(),
                    sequence: 0xffff_fffe, // nSequence is disabled, nLocktime is enabled, RBF is not signaled.
                    asset_issuance: Default::default(),
                    witness: TxInWitness::default(),
                };
                tx.input.push(new_in);
            }
            _ => panic!("unexpected mix of bitcoin and elements types"),
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
                if tx.is_coin_base() {
                    Ok(0)
                } else {
                    let sum_inputs = sum_inputs(tx, all_txs);
                    let sum_outputs: u64 = tx.output.iter().map(|o| o.value).sum();
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
            Self::Bitcoin(tx) => tx.input.iter().any(|e| e.sequence < 0xffff_fffe),
            Self::Elements(tx) => tx.input.iter().any(|e| e.sequence < 0xffff_fffe),
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
                    .map(|o| o.value as i64)
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

    /// Return a copy of the transaction with the outputs matched by `f` only
    pub fn filter_outputs<F>(
        &self,
        all_unblinded: &HashMap<elements::OutPoint, elements::TxOutSecrets>,
        mut f: F,
    ) -> BETransaction
    where
        F: FnMut(u32, BEScript, Option<elements::issuance::AssetId>) -> bool,
    {
        let mut vout = 0u32;
        let mut predicate = || {
            let matched = f(vout, self.output_script(vout), self.output_asset(vout, all_unblinded));
            vout += 1;
            matched
        };

        let mut stripped_tx = self.clone();
        match stripped_tx {
            Self::Bitcoin(ref mut tx) => tx.output.retain(|_| predicate()),
            Self::Elements(ref mut tx) => tx.output.retain(|_| predicate()),
        }
        stripped_tx
    }

    /// Verify the given transaction input. Only supports the script types that
    /// can be managed using gdk-rust. Implemented for Bitcoin only.
    ///
    /// The `hashcache` argument should be initialized as None for every tx and
    /// reused for its inputs.
    pub fn verify_input_sig<'a>(
        &'a self,
        secp: &Secp256k1<impl secp256k1::Verification>,
        hashcache: &mut Option<SigHashCache<&'a bitcoin::Transaction>>,
        inv: usize,
        public_key: &PublicKey,
        value: u64,
        script_type: ScriptType,
    ) -> Result<(), Error> {
        let tx = if let BETransaction::Bitcoin(tx) = self {
            tx
        } else {
            // Signature verification is currently only used on Bitcoin
            unimplemented!();
        };
        let script_code = p2pkh_script(public_key);
        let hash = if script_type.is_segwit() {
            let hashcache = hashcache.get_or_insert_with(|| SigHashCache::new(tx));
            hashcache.signature_hash(inv, &script_code, value, SigHashType::All)
        } else {
            tx.signature_hash(inv, &script_code, SigHashType::All as u32)
        };
        let message = Message::from_slice(&hash.into_inner()[..]).unwrap();
        let mut sig = match script_type {
            ScriptType::P2wpkh | ScriptType::P2shP2wpkh => {
                tx.input[inv].witness.get(0).cloned().ok_or(Error::InputValidationFailed)
            }
            ScriptType::P2pkh => match tx.input[inv].script_sig.instructions().next() {
                Some(Ok(Instruction::PushBytes(sig))) => Ok(sig.to_vec()),
                _ => Err(Error::InputValidationFailed),
            },
        }?;

        // We only ever create SIGHASH_ALL transactions
        ensure!(sig.pop() == Some(SigHashType::All as u8), Error::InputValidationFailed);

        secp.verify(&message, &Signature::from_der(&sig)?, &public_key.key)?;
        Ok(())
    }
}

fn mock_pubkey() -> secp256k1::PublicKey {
    secp256k1::PublicKey::from_slice(&[2u8; 33]).unwrap()
}

fn mock_asset() -> elements::secp256k1_zkp::Generator {
    let mut mock_asset = [2u8; 33];
    mock_asset[0] = 10;
    elements::secp256k1_zkp::Generator::from_slice(&mock_asset).unwrap()
}

fn mock_value() -> elements::secp256k1_zkp::PedersenCommitment {
    let mut mock_value = [2u8; 33];
    mock_value[0] = 8;
    elements::secp256k1_zkp::PedersenCommitment::from_slice(&mock_value).unwrap()
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
    fn from(mut tx: BETransaction) -> Self {
        let size = tx.serialize().len();
        let weight = tx.get_weight();
        tx.strip_witness();
        Self {
            tx,
            size,
            weight,
        }
    }
}

//TODO remove this, `fn needs` could return BTreeMap<String, u64> instead
#[derive(Debug)]
pub struct AssetValue {
    pub asset: Option<elements::issuance::AssetId>,
    pub satoshi: u64,
}

impl AssetValue {
    fn new_bitcoin(satoshi: u64) -> Self {
        AssetValue {
            asset: None,
            satoshi,
        }
    }
    fn new(asset: elements::issuance::AssetId, satoshi: u64) -> Self {
        AssetValue {
            asset: Some(asset),
            satoshi,
        }
    }
}
