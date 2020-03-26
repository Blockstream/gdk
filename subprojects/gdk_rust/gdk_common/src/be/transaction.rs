use crate::be::*;
use crate::model::Balances;
use crate::NetworkId;
use bitcoin::hash_types::Txid;
use bitcoin::Script;
use serde_derive::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::ops::{Deref, DerefMut};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BETransaction {
    Bitcoin(bitcoin::Transaction),
    Elements(elements::Transaction),
}

impl BETransaction {
    pub fn serialize(&self) -> Vec<u8> {
        match self {
            Self::Bitcoin(tx) => bitcoin::consensus::encode::serialize(tx),
            Self::Elements(tx) => elements::encode::serialize(tx),
        }
    }

    pub fn deserialize(bytes: &[u8], id: NetworkId) -> Result<Self, crate::error::Error> {
        Ok(match id {
            NetworkId::Bitcoin(_) => Self::Bitcoin(bitcoin::consensus::encode::deserialize(bytes)?),
            NetworkId::Elements(_) => Self::Elements(elements::encode::deserialize(bytes)?),
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
                    .find(|o| o.is_fee())
                    .unwrap() // safe to unwrap since one output fee is mandatory
                    .minimum_value() // minimum_value used for extracting the explicit value
            }
        }
    }

    pub fn my_balances(
        &self,
        all_txs: &BETransactions,
        all_scripts: &HashSet<Script>,
        all_unblinded: &HashMap<elements::OutPoint, Unblinded>,
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
                        let asset_id_str = hex::encode(unblinded.asset);
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
                        let asset_id_str = hex::encode(unblinded.asset);
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
