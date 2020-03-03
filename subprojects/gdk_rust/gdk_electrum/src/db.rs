use bitcoin::blockdata::script::Script;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::util::bip32::ChildNumber;
use bitcoin::{OutPoint, TxOut, Txid};
use log::{debug, info};
use serde_json::json;
use sled::{Batch, Db, IVec, Tree};
use std::collections::HashSet;
use std::convert::TryInto;
use std::ops::Drop;

use crate::error::Error;
use crate::model::*;

pub trait GetTree {
    fn get_tree(&self, wallet_name: &str) -> Result<WalletDB, Error>;
}

impl GetTree for Db {
    fn get_tree(&self, wallet_name: &str) -> Result<WalletDB, Error> {
        debug!("opening tree {}", wallet_name);
        Ok(WalletDB::from(self.open_tree(wallet_name)?))
    }
}

#[derive(Debug)]
pub struct WalletDB {
    tree: Tree,
}

impl From<Tree> for WalletDB {
    fn from(tree: Tree) -> Self {
        WalletDB {
            tree,
        }
    }
}

impl Drop for WalletDB {
    fn drop(&mut self) {
        self.tree.flush().unwrap();
    }
}

impl WalletDB {
    // TODO: we should have an higher-level api maybe
    pub fn apply_batch(&self, batch: Batch) -> Result<(), Error> {
        self.tree.apply_batch(batch)?;
        Ok(())
    }

    pub fn flush(&self) -> Result<usize, Error> {
        self.tree.flush().map_err(Into::into)
    }

    pub fn iter_script_pubkeys(&self) -> impl DoubleEndedIterator<Item = Script> {
        let scan_key: &[u8] = b"d";
        self.tree.range(scan_key..).values().map(|el| Script::from(el.unwrap().as_ref().to_vec()))
    }

    pub fn iter_utxos(&self) -> impl DoubleEndedIterator<Item = (OutPoint, TxOut)> {
        let scan_key: &[u8] = b"u";
        self.tree.range(scan_key..).map(|el| {
            let (key, value) = el.unwrap();
            (deserialize(&key[1..]).unwrap(), deserialize(&value).unwrap())
        })
    }

    pub fn save_tx(&self, tx: TransactionMeta, batch: &mut Batch) -> Result<(), Error> {
        let mut key = vec!['t' as u8];
        key.append(&mut hex::decode(&tx.txid)?);

        batch.insert(key, serde_json::to_vec(&tx)?);
        Ok(())
    }

    pub fn get_tx(&self, txid: &String) -> Result<Option<TransactionMeta>, Error> {
        let mut key = vec!['t' as u8];
        key.append(&mut hex::decode(txid)?);

        Ok(self.tree.get(key)?.and_then(|data| serde_json::from_slice(&data).unwrap()))
    }

    pub fn save_spent(&self, outpoint: &OutPoint, batch: &mut Batch) -> Result<(), Error> {
        let mut key = vec!['s' as u8];
        key.append(&mut serialize(outpoint));

        batch.insert(key, &[]);
        Ok(())
    }

    pub fn get_spent(&self) -> Result<HashSet<OutPoint>, Error> {
        let r = self.tree.scan_prefix(b"s");

        Ok(r.keys().map(|e| deserialize(&e.unwrap()[1..]).unwrap()).collect())
    }

    pub fn list_tx(&self) -> Result<Vec<TransactionMeta>, Error> {
        let r = self.tree.scan_prefix(b"t");

        Ok(r.values().map(|e| serde_json::from_slice(&e.unwrap()).unwrap()).collect())
    }
    fn insert_prefix(&self, prefix: u8, key: Vec<u8>, value: Vec<u8>) -> Result<(), Error> {
        let mut prefix_key = Vec::with_capacity(1 + key.len());
        prefix_key.push(prefix);
        prefix_key.extend(key);
        self.tree.insert(prefix_key, value).map(|_| ()).map_err(|e| e.into())
    }
    pub fn set_external_index(&self, num: u32) -> Result<(), Error> {
        self.insert_prefix('e' as u8, vec![], serde_json::to_vec(&json!(num)).unwrap())
    }

    pub fn set_internal_index(&self, num: u32) -> Result<(), Error> {
        self.insert_prefix('i' as u8, vec![], serde_json::to_vec(&json!(num)).unwrap())
    }
    fn get_index(&self, key: &[u8]) -> Result<u32, Error> {
        let data = self.tree.get(key)?;

        match data {
            Some(bytes) => Ok(serde_json::from_slice(&bytes).unwrap()),
            None => Ok(0),
        }
    }

    fn get_internal_index(&self) -> Result<u32, Error> {
        self.get_index(b"i")
    }

    fn get_extenral_index(&self) -> Result<u32, Error> {
        self.get_index(b"e")
    }
    pub fn set_script_pubkey_by_path(
        &self,
        path: Vec<ChildNumber>,
        script_pubkey: Script,
        batch: &mut Batch,
    ) -> Result<(), Error> {
        let key = path_key(path);
        batch.insert(key, script_pubkey.into_bytes());
        Ok(())
    }

    pub fn get_script_pubkey_by_path(&self, path: Vec<ChildNumber>) -> Result<Option<IVec>, Error> {
        Ok(self.tree.get(path_key(path))?)
    }
    pub fn set_path_by_script_pubkey(
        &self,
        script_pubkey: Script,
        path: Vec<ChildNumber>,
        batch: &mut Batch,
    ) -> Result<(), Error> {
        let key = script_pubkey_key(script_pubkey);
        let mut value = vec![];
        path.iter()
            .map(|cn| u32::from(*cn).to_be_bytes())
            .for_each(|bytes| value.extend(&bytes[..]));

        batch.insert(key, value);
        Ok(())
    }

    pub fn get_path_by_script_pubkey(
        &self,
        script_pubkey: Script,
    ) -> Result<Option<Vec<ChildNumber>>, Error> {
        Ok(match self.tree.get(script_pubkey_key(script_pubkey))? {
            Some(path_bytes) => {
                let path_bytes = &path_bytes[..];
                let path = path_bytes
                    .chunks(4)
                    .map(|e| u32::from_be_bytes(e.try_into().unwrap()))
                    .map(|u| ChildNumber::from(u))
                    .collect();
                Some(path)
            }
            None => None,
        })
    }

    pub fn del_utxo_by_outpoint(&self, outpoint: OutPoint) -> Result<(), Error> {
        let mut key = vec!['u' as u8];
        key.append(&mut serialize(&outpoint));
        self.tree.remove(key)?;
        Ok(())
    }

    pub fn set_utxo_by_outpoint(&self, outpoint: OutPoint, output: TxOut) -> Result<(), Error> {
        let mut key = vec!['u' as u8];
        key.append(&mut serialize(&outpoint));
        self.tree.insert(key, serialize(&output))?;
        Ok(())
    }

    pub fn set_tx_by_hash(&self, tx: TransactionMeta) -> Result<(), Error> {
        let mut key = vec!['t' as u8];
        key.append(&mut serialize(&tx.transaction.txid()));
        info!("Saving on {}", hex::encode(&key));

        self.tree.insert(key, serde_json::to_vec(&tx)?)?;
        Ok(())
    }

    pub fn get_tx_by_hash(&self, txid: &Txid) -> Result<Option<TransactionMeta>, Error> {
        let mut key = vec!['t' as u8];
        key.append(&mut serialize(txid));
        info!("Getting on {}", hex::encode(&key));

        Ok(self.tree.get(key)?.and_then(|data| {
            serde_json::from_slice(&data).expect("get_tx_by_hash fail deserialize")
        }))
    }

    fn increment_index(&self, key: &[u8]) -> Result<u32, Error> {
        let data = self.tree.update_and_fetch(key, |old| {
            let num = match old {
                Some(bytes) => {
                    let val: u32 = serde_json::from_slice(bytes).unwrap();
                    val + 1
                }
                None => 0,
            };
            debug!("increment_index, returning {}", num);

            Some(serde_json::to_vec(&json!(num)).unwrap())
        });

        Ok(serde_json::from_slice(&data?.unwrap()).unwrap())
    }

    pub fn increment_internal_index(&self) -> Result<u32, Error> {
        self.increment_index(b"i")
    }

    pub fn increment_external_index(&self) -> Result<u32, Error> {
        self.increment_index(b"e")
    }

    // TODO: only in debug
    pub fn dump(&self) -> Result<(), Error> {
        let r = self.tree.scan_prefix(&[]);
        for e in r {
            let e = e.unwrap();
            debug!("{:?} {:?}", hex::encode(&e.0), std::str::from_utf8(&e.1));
        }

        Ok(())
    }
}

fn script_pubkey_key(script: Script) -> Vec<u8> {
    let mut key = vec!['p' as u8];
    key.extend(script.into_bytes());
    key
}

fn path_key(path: Vec<ChildNumber>) -> Vec<u8> {
    let mut key = vec!['d' as u8];
    path.iter().map(|cn| u32::from(*cn).to_be_bytes()).for_each(|bytes| key.extend(&bytes[..]));
    key
}
