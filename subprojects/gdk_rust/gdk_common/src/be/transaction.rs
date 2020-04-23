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
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;
use rand::thread_rng;
use rand::seq::SliceRandom;

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

    pub fn get_weight(&self) -> usize {
        match self {
            Self::Bitcoin(tx) => tx.get_weight(),
            Self::Elements(tx) => tx.get_weight(),
        }
    }

    pub fn add_output(
        &mut self,
        address: &str,
        value: u64,
        asset: Option<AssetId>,
    ) -> Result<usize, Error> {
        match self {
            BETransaction::Bitcoin(tx) => {
                let script_pubkey = bitcoin::Address::from_str(&address)?.script_pubkey();
                let new_out = bitcoin::TxOut {
                    script_pubkey,
                    value,
                };
                let len = btc_ser(&new_out).len();
                tx.output.push(new_out);
                Ok(len)
            }
            BETransaction::Elements(tx) => {
                let address =
                    elements::Address::from_str(&address).map_err(|_| Error::InvalidAddress)?;
                let blinding_pubkey = address.blinding_pubkey.ok_or(Error::InvalidAddress)?;
                let bytes = blinding_pubkey.serialize();
                let byte32: [u8; 32] = bytes[1..].as_ref().try_into().unwrap();
                let new_out = elements::TxOut {
                    asset: confidential::Asset::Explicit(sha256d::Hash::from_inner(asset.unwrap())),
                    value: confidential::Value::Explicit(value),
                    nonce: confidential::Nonce::Confidential(bytes[0], byte32),
                    script_pubkey: address.script_pubkey(),
                    witness: TxOutWitness::default(),
                };
                let len = elm_ser(&new_out).len() + 1200; // 1200 is an estimate of the weight of surjproof and rangeproof
                tx.output.push(new_out);
                Ok(len)
            }
        }
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

    pub fn add_fee_if_elements(&mut self, value: u64, asset: Option<AssetId>) {
        if let BETransaction::Elements(tx) = self {
            let new_out = elements::TxOut {
                asset: confidential::Asset::Explicit(sha256d::Hash::from_inner(asset.unwrap())),
                value: confidential::Value::Explicit(value),
                ..Default::default()
            };
            tx.output.push(new_out);
        }
    }

    pub fn add_input(&mut self, outpoint: BEOutPoint) -> usize {
        match (outpoint, self) {
            (BEOutPoint::Bitcoin(outpoint), BETransaction::Bitcoin(tx)) => {
                let new_in = bitcoin::TxIn {
                    previous_output: outpoint,
                    script_sig: Script::default(),
                    sequence: 0xfffffffd, // nSequence is disabled, nLocktime is enabled, RBF is signaled.
                    witness: vec![],
                };
                let len = btc_ser(&new_in).len();
                tx.input.push(new_in);
                len
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
                let len = elm_ser(&new_in).len();
                tx.input.push(new_in);
                len
            }
            _ => panic!("unexpected mix of bitcoin and elements types"),
        }
    }

    pub fn fee(&self, all_txs: &BETransactions) -> u64 {
        match self {
            Self::Bitcoin(tx) => {
                let sum_inputs: u64 = tx
                    .input
                    .iter()
                    .map(|i| BEOutPoint::Bitcoin(i.previous_output.clone()))
                    .filter_map(|o| all_txs.get_previous_output_value(&o, &HashMap::new()))
                    .sum();
                let sum_outputs: u64 = tx.output.iter().map(|o| o.value).sum();
                sum_inputs - sum_outputs
            }
            Self::Elements(tx) => {
                tx.output
                    .iter()
                    .filter(|o| o.is_fee()) // TODO should check the asset is the policy asset
                    .map(|o| o.minimum_value()) // minimum_value used for extracting the explicit value (value is always explicit for fee)
                    .sum::<u64>()
            }
        }
    }

    pub fn my_balances(
        &self,
        all_txs: &BETransactions,
        all_scripts: &HashSet<Script>,
        all_unblinded: &HashMap<elements::OutPoint, Unblinded>,
        policy_asset: Option<&String>,
    ) -> Balances {
        match self {
            Self::Bitcoin(tx) => {
                let mut result = HashMap::new();
                let mut my_out: i64 = 0;
                for input in tx.input.iter() {
                    let outpoint = BEOutPoint::Bitcoin(input.previous_output.clone());
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
                        let asset_id_str = unblinded.asset_hex(policy_asset);
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
                        let asset_id_str = unblinded.asset_hex(policy_asset);
                        *result.entry(asset_id_str).or_default() += unblinded.value as i64;
                        // TODO check overflow
                    }
                }

                result
            }
        }
    }
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
}
