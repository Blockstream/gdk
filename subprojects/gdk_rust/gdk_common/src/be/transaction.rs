use crate::be::*;
use crate::error::Error;
use crate::model::Balances;
use crate::NetworkId;
use bitcoin::consensus::encode::deserialize as btc_des;
use bitcoin::consensus::encode::serialize as btc_ser;
use bitcoin::hash_types::Txid;
use bitcoin::hashes::{sha256d, Hash};
use bitcoin::Script;
use elements::confidential;
use elements::encode::deserialize as elm_des;
use elements::encode::serialize as elm_ser;
use elements::{TxInWitness, TxOutWitness};
use rand::seq::SliceRandom;
use rand::thread_rng;
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use elements::confidential::{Asset, Value};
use log::info;
use crate::wally::asset_surjectionproof_size;

#[derive(Debug, Clone, Serialize, Deserialize)]
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

    pub fn txid(&self) -> Txid {
        match self {
            Self::Bitcoin(tx) => tx.txid(),
            Self::Elements(tx) => tx.txid(),
        }
    }

    pub fn previous_outputs(&self) -> Vec<BEOutPoint> {
        match self {
            Self::Bitcoin(tx) => {
                tx.input.iter().map(|i| BEOutPoint::Bitcoin(i.previous_output.clone())).collect()
            }
            Self::Elements(tx) => {
                tx.input.iter().map(|i| BEOutPoint::Elements(i.previous_output.clone())).collect()
            }
        }
    }

    pub fn previous_output_txids(&self) -> Vec<Txid> {
        match self {
            Self::Bitcoin(tx) => tx.input.iter().map(|i| i.previous_output.txid.clone()).collect(),
            Self::Elements(tx) => tx.input.iter().map(|i| i.previous_output.txid.clone()).collect(),
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
        all_unblinded: &HashMap<elements::OutPoint, Unblinded>,
    ) -> u64 {
        match self {
            Self::Bitcoin(tx) => tx.output[vout as usize].value,
            Self::Elements(tx) => {
                let outpoint = elements::OutPoint {
                    txid: tx.txid(),
                    vout,
                };
                all_unblinded.get(&outpoint).unwrap().value // TODO return Result<u64>?
            }
        }
    }

    pub fn output_script(&self, vout: u32) -> Script {
        match self {
            Self::Bitcoin(tx) => tx.output[vout as usize].script_pubkey.clone(),
            Self::Elements(tx) => tx.output[vout as usize].script_pubkey.clone(),
        }
    }
    pub fn output_asset_hex(&self, vout: u32, all_unblinded: &HashMap<elements::OutPoint, Unblinded>) -> Option<String> {
        match self {
            Self::Bitcoin(_) => None,
            Self::Elements(tx) => {
                let outpoint = elements::OutPoint {
                    txid: tx.txid(),
                    vout,
                };
                Some(all_unblinded.get(&outpoint).unwrap().asset_hex())
            },
        }
    }

    pub fn get_weight(&self) -> usize {
        match self {
            Self::Bitcoin(tx) => tx.get_weight(),
            Self::Elements(tx) => tx.get_weight(),
        }
    }

    /// asset is none for bitcoin, in liquid must be Some
    pub fn add_output(
        &mut self,
        address: &str,
        value: u64,
        asset_hex: Option<String>,
    ) -> Result<(), Error> {
        match self {
            BETransaction::Bitcoin(tx) => {
                let script_pubkey = bitcoin::Address::from_str(&address)?.script_pubkey();
                let new_out = bitcoin::TxOut {
                    script_pubkey,
                    value,
                };
                tx.output.push(new_out);
            }
            BETransaction::Elements(tx) => {
                let address = elements::Address::from_str(&address).map_err(|_| Error::InvalidAddress)?;
                let blinding_pubkey = address.blinding_pubkey.ok_or(Error::InvalidAddress)?;
                let bytes = blinding_pubkey.serialize();
                let byte32: [u8; 32] = bytes[1..].as_ref().try_into().unwrap();
                let asset = asset_hex.expect("add_output must be called with a non empty asset in liquid");
                let asset = asset_to_bin(&asset).expect("invalid asset hex");
                let new_out = elements::TxOut {
                    asset: confidential::Asset::Explicit(sha256d::Hash::from_inner(  asset)),
                    value: confidential::Value::Explicit(value),
                    nonce: confidential::Nonce::Confidential(bytes[0], byte32),
                    script_pubkey: address.script_pubkey(),
                    witness: TxOutWitness::default(),
                };
                tx.output.push(new_out);
            }
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
    pub fn estimated_fee(&self, fee_rate: f64, more_outputs: u8) -> u64 {
        let dummy_tx = self.clone();
        match dummy_tx {
            BETransaction::Bitcoin(mut tx) => {
                for input in tx.input.iter_mut() {
                    input.witness = vec![vec![0u8; 105]];  // considering signature sizes (72) and compressed public key (33)
                    input.script_sig =  vec![0u8; 23].into();  // p2shwpkh redeem script size
                }
                for _ in 0..more_outputs {
                    tx.output.push(bitcoin::TxOut {
                        value: 0,
                        script_pubkey: vec![0u8; 21].into(),  //  p2shwpkh output is 1 + hash(20)
                    })
                }
                let vbytes = tx.get_weight() as f64 / 4.0;
                let fee_val = (vbytes * fee_rate * 1.02) as u64; // increasing estimated fee by 2% to stay over relay fee TODO improve fee estimation and lower this
                info!("DUMMYTX inputs:{} outputs:{} num_changes:{} vbytes:{} fee_val:{}", tx.input.len(), tx.output.len(), more_outputs, vbytes, fee_val);
                fee_val
            }
            BETransaction::Elements(mut tx) => {
                for input in tx.input.iter_mut() {
                    let mut tx_wit = TxInWitness::default();
                    tx_wit.script_witness = vec![vec![0u8; 105]];  // considering signature sizes (72) and compressed public key (33)
                    input.witness = tx_wit;
                    input.script_sig =  vec![0u8; 23].into();  // p2shwpkh redeem script size
                }
                for _ in 0..more_outputs {
                    let new_out = elements::TxOut {
                        asset: confidential::Asset::Confidential(0u8, [0u8; 32]),
                        value: confidential::Value::Confidential(0u8, [0u8; 32]),
                        nonce: confidential::Nonce::Confidential(0u8, [0u8; 32]),
                        ..Default::default()
                    };
                    tx.output.push(new_out);
                }
                let sur_size = asset_surjectionproof_size(std::cmp::max(1,tx.input.len()) );
                for output in tx.output.iter_mut() {
                    output.witness = TxOutWitness {
                        surjection_proof: vec![0u8; sur_size],
                        rangeproof: vec![0u8; 4174],
                    };
                    output.script_pubkey = vec![0u8; 21].into();
                }

                tx.output.push(elements::TxOut::default()); // mockup for the explicit fee output
                let vbytes = tx.get_weight() as f64 / 4.0;
                let fee_val = (vbytes * fee_rate * 1.03) as u64; // increasing estimated fee by 3% to stay over relay fee, TODO improve fee estimation and lower this
                info!("DUMMYTX inputs:{} outputs:{} num_changes:{} vbytes:{} sur_size:{} fee_val:{}", tx.input.len(), tx.output.len(), more_outputs, vbytes, sur_size, fee_val );
                fee_val
            }
        }
    }

    pub fn estimated_changes(&self, send_all: bool, wallet_data: &WalletData) -> u8 {
        match self {
            Self::Bitcoin(_) => {
                1u8 - send_all as u8
            }
            Self::Elements(tx) => {
                let mut different_assets = HashSet::new();
                for input in tx.input.iter() {
                    let asset_hex = wallet_data.all_txs.get_previous_output_asset_hex(input.previous_output, &wallet_data.all_unblinded).unwrap();
                    different_assets.insert(asset_hex.clone());
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
        policy_asset: Option<String>,
        wallet_data: &WalletData,
    ) -> Vec<AssetValue> {
        match self {
            Self::Bitcoin(tx) => {
                let sum_inputs= sum_inputs(tx, &wallet_data.all_txs);
                let sum_outputs: u64 = tx.output.iter().map(|o| o.value).sum();
                let estimated_fee = self.estimated_fee(fee_rate, self.estimated_changes(no_change, wallet_data));  // send all does not create change
                if sum_outputs + estimated_fee > sum_inputs {
                    vec![ AssetValue::new_bitcoin(sum_outputs + estimated_fee - sum_inputs) ]
                } else {
                    vec![]
                }
            }
            Self::Elements(tx) => {
                let policy_asset = policy_asset.expect("policy asset empty in elements");
                let mut outputs: HashMap<String, u64> = HashMap::new();
                for output in tx.output.iter() {
                    match (output.asset, output.value) {
                        (Asset::Explicit(asset), Value::Explicit(value)) => {
                            let asset_hex = asset_to_hex(& asset.into_inner());
                            *outputs.entry(asset_hex).or_insert(0) += value;
                        }
                        _ => panic!("asset and value should be explicit here"),
                    }
                }

                let mut inputs: HashMap<String, u64> = HashMap::new();

                for input in tx.input.iter() {
                    let asset_hex = wallet_data.all_txs.get_previous_output_asset_hex(input.previous_output, &wallet_data.all_unblinded).unwrap();
                    let value = wallet_data.all_txs.get_previous_output_value(&BEOutPoint::Elements(input.previous_output), &wallet_data.all_unblinded).unwrap();
                    *inputs.entry(asset_hex).or_insert(0) += value;
                }

                let estimated_fee = self.estimated_fee(fee_rate, self.estimated_changes(no_change, wallet_data) );
                *outputs.entry(policy_asset.clone()).or_insert(0) += estimated_fee;

                let mut result = vec![];
                for (asset,value) in outputs.iter() {
                    if let Some(sum) = value.checked_sub(inputs.remove(asset).unwrap_or(0)) {
                        if sum > 0 {
                            result.push(AssetValue::new(asset.to_string(), sum));
                        }
                    }
                }

                if let Some(index) = result.iter().position(|e| e.asset==policy_asset) {
                    let last_index = result.len() - 1;
                    if index != last_index {
                        result.swap(index, last_index);  // put the policy asset last
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
        policy_asset: Option<String>,
        wallet_data: &WalletData,
    ) -> Vec<AssetValue> {
        match self {
            Self::Bitcoin(tx) => {
                let sum_inputs= sum_inputs(tx, &wallet_data.all_txs);
                let sum_outputs: u64 = tx.output.iter().map(|o| o.value).sum();
                let change_value = sum_inputs - sum_outputs - estimated_fee;
                if change_value > 546 {
                    vec![AssetValue::new_bitcoin(change_value)]
                } else {
                    vec![]
                }
            }
            Self::Elements(tx) => {
                let mut outputs: HashMap<String, u64> = HashMap::new();
                for output in tx.output.iter() {
                    match (output.asset, output.value) {
                        (Asset::Explicit(asset), Value::Explicit(value)) => {
                            let asset_hex = asset_to_hex(& asset.into_inner());
                            *outputs.entry(asset_hex).or_insert(0) += value;
                        }
                        _ => panic!("asset and value should be explicit here"),
                    }
                }

                let mut inputs: HashMap<String, u64> = HashMap::new();
                for input in tx.input.iter() {
                    let asset_hex = wallet_data.all_txs.get_previous_output_asset_hex(input.previous_output, &wallet_data.all_unblinded).unwrap();
                    let value = wallet_data.all_txs.get_previous_output_value(&BEOutPoint::Elements(input.previous_output), &wallet_data.all_unblinded).unwrap();
                    *inputs.entry(asset_hex).or_insert(0) += value;
                }
                let mut result = vec![];
                for (asset,value) in inputs.iter() {
                    let mut sum = value - outputs.remove(asset).unwrap_or(0);
                    if asset == policy_asset.as_ref().unwrap() {
                        // from a purely privacy perspective could make sense to always create the change output in liquid, so min change = 0
                        // however elements core use the dust anyway for 2 reasons: rebasing from core and economical considerations
                        // another reason, specific to this wallet, is that the send_all algorithm could reason in steps greater than 1, making it not too slow
                        sum -= estimated_fee;
                        if sum > 546 {
                            result.push(AssetValue::new(asset.to_string(), sum));
                        }
                    } else {
                        result.push(AssetValue::new(asset.to_string(),sum));
                    }
                }
                assert!(outputs.is_empty());
                result
            }
        }
    }

    pub fn add_fee_if_elements(&mut self, value: u64, policy_asset: &str) {
        if let BETransaction::Elements(tx) = self {
            let asset = asset_to_bin(policy_asset).unwrap();
            let new_out = elements::TxOut {
                asset: confidential::Asset::Explicit(sha256d::Hash::from_inner(asset)),
                value: confidential::Value::Explicit(value),
                ..Default::default()
            };
            tx.output.push(new_out);
        }
    }

    pub fn add_input(&mut self, outpoint: BEOutPoint) {
        match (outpoint, self) {
            (BEOutPoint::Bitcoin(outpoint), BETransaction::Bitcoin(tx)) => {
                let new_in = bitcoin::TxIn {
                    previous_output: outpoint,
                    script_sig: Script::default(),
                    sequence: 0xfffffffd, // nSequence is disabled, nLocktime is enabled, RBF is signaled.
                    witness: vec![],
                };
                tx.input.push(new_in);
            }
            (BEOutPoint::Elements(outpoint), BETransaction::Elements(tx)) => {
                let new_in = elements::TxIn {
                    previous_output: outpoint,
                    is_pegin: false,
                    has_issuance: false,
                    script_sig: Script::default(),
                    sequence: 0xfffffffe, // nSequence is disabled, nLocktime is enabled, RBF is not signaled.
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
        all_unblinded: &HashMap<elements::OutPoint, Unblinded>,
    ) -> u64 {
        match self {
            Self::Bitcoin(tx) => {
                let sum_inputs= sum_inputs(tx, all_txs);
                let sum_outputs: u64 = tx.output.iter().map(|o| o.value).sum();
                sum_inputs - sum_outputs
            }
            Self::Elements(tx) => {
                let has_fee = tx.output.iter().any(|o| o.is_fee());
                if has_fee {
                    tx.output
                        .iter()
                        .filter(|o| o.is_fee()) // TODO should check the asset is the policy asset
                        .map(|o| o.minimum_value()) // minimum_value used for extracting the explicit value (value is always explicit for fee)
                        .sum::<u64>()
                } else {
                    // while we are not filtering assets, the following holds for valid tx because
                    // sum of input assets = sum of output assets
                    let sum_outputs: u64 = tx.output.iter().map(|o| o.minimum_value()).sum();
                    let sum_inputs: u64 = tx
                        .input
                        .iter()
                        .map(|i| BEOutPoint::Elements(i.previous_output.clone()))
                        .filter_map(|o| all_txs.get_previous_output_value(&o, all_unblinded))
                        .sum();

                    sum_inputs - sum_outputs
                }
            }
        }
    }

    pub fn is_redeposit(&self, all_scripts: &HashSet<Script>, all_txs: &BETransactions) -> bool {
        match self {
            Self::Bitcoin(tx) => {
                let previous_scripts: Vec<Script> = tx
                    .input
                    .iter()
                    .filter_map(|i| {
                        all_txs.get_previous_output_script_pubkey(&i.previous_output.into())
                    })
                    .collect();

                previous_scripts.len() == tx.input.len()
                    && previous_scripts.iter().all(|i| all_scripts.contains(i))
                    && tx.output.iter().all(|o| all_scripts.contains(&o.script_pubkey))
            }
            Self::Elements(tx) => {
                let previous_scripts: Vec<Script> = tx
                    .input
                    .iter()
                    .filter_map(|i| {
                        all_txs.get_previous_output_script_pubkey(&i.previous_output.into())
                    })
                    .collect();

                previous_scripts.len() == tx.input.len()
                    && previous_scripts.iter().all(|i| all_scripts.contains(i))
                    && tx
                        .output
                        .iter()
                        .filter(|o| !o.is_fee())
                        .all(|o| all_scripts.contains(&o.script_pubkey))
            }
        }
    }

    pub fn my_balances(
        &self,
        all_txs: &BETransactions,
        all_scripts: &HashSet<Script>,
        all_unblinded: &HashMap<elements::OutPoint, Unblinded>
    ) -> Balances {
        match self {
            Self::Bitcoin(tx) => {
                let mut result = HashMap::new();
                let mut my_out: i64 = 0;
                for input in tx.input.iter() {
                    let outpoint = input.previous_output.clone().into();
                    let script = all_txs.get_previous_output_script_pubkey(&outpoint);
                    if let Some(script) = script {
                        if all_scripts.contains(&script) {
                            my_out += all_txs
                                .get_previous_output_value(&outpoint, &all_unblinded)
                                .unwrap_or(0) as i64;
                        }
                    }
                }
                let my_in: i64 = tx
                    .output
                    .iter()
                    .filter(|o| all_scripts.contains(&o.script_pubkey))
                    .map(|o| o.value as i64)
                    .sum();
                result.insert("btc".to_string(), my_in - my_out);
                result
            }
            Self::Elements(tx) => {
                let mut result = HashMap::new();
                for input in tx.input.iter() {
                    let outpoint = input.previous_output.clone();
                    if let Some(unblinded) = all_unblinded.get(&outpoint) {
                        let asset_id_str = unblinded.asset_hex();
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
                        let asset_id_str = unblinded.asset_hex();
                        *result.entry(asset_id_str).or_default() += unblinded.value as i64;
                        // TODO check overflow
                    }
                }

                result
            }
        }
    }
}

fn sum_inputs(tx: &bitcoin::Transaction, all_txs: &BETransactions) -> u64 {
    tx.input
        .iter()
        .map(|i| BEOutPoint::Bitcoin(i.previous_output.clone()))
        .filter_map(|o| all_txs.get_previous_output_value(&o, &HashMap::new())) //no need of unblinded since this fn is bitcoin only
        .sum()
}

pub struct BETransactions(HashMap<Txid, BETransaction>);
impl Default for BETransactions {
    fn default() -> Self {
        BETransactions(HashMap::new())
    }
}
impl Deref for BETransactions {
    type Target = HashMap<Txid, BETransaction>;
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
    pub fn get_previous_output_script_pubkey(&self, outpoint: &BEOutPoint) -> Option<Script> {
        self.0.get(&outpoint.txid()).map(|tx| tx.output_script(outpoint.vout()))
    }
    pub fn get_previous_output_value(
        &self,
        outpoint: &BEOutPoint,
        all_unblinded: &HashMap<elements::OutPoint, Unblinded>,
    ) -> Option<u64> {
        self.0.get(&outpoint.txid()).map(|tx| tx.output_value(outpoint.vout(), &all_unblinded))
    }

    pub fn get_previous_output_asset_hex(&self, outpoint: elements::OutPoint, all_unblinded: &HashMap<elements::OutPoint, Unblinded>) -> Option<String> {
        self.0.get(&outpoint.txid).map(|tx| tx.output_asset_hex(outpoint.vout, &all_unblinded).unwrap() )
    }
}

#[derive(Debug)]
pub struct AssetValue {
    pub asset: String,  // None is for bitcoin, in elements MUST be Some
    pub satoshi: u64,
}

impl AssetValue {
    fn new_bitcoin(satoshi: u64) -> Self {
        let asset = "btc".to_string();
        AssetValue {asset, satoshi}
    }
    fn new(asset: String, satoshi: u64) -> Self {
        AssetValue {asset, satoshi}
    }
}