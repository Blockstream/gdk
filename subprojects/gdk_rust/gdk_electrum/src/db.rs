use bitcoin::blockdata::script::Script;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::util::bip32::ChildNumber;
use bitcoin::{OutPoint, TxOut, Txid};
use gdk_common::model::TransactionMeta;
use log::{debug, info};
use serde_json::json;
use sled::{Batch, Db, IVec, Tree};
use std::collections::HashSet;
use std::convert::TryInto;
use std::ops::Drop;

use crate::error::Error;

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
        self.tree.flush().expect("can't flush db");
    }
}

impl WalletDB {
    pub fn apply_batch(&self, batch: Batch) -> Result<(), Error> {
        self.tree.apply_batch(batch)?;
        Ok(())
    }

    pub fn flush(&self) -> Result<usize, Error> {
        self.tree.flush().map_err(Into::into)
    }

    pub fn iter_script_pubkeys(&self) -> Result<Vec<Script>, Error> {
        let scan_key: &[u8] = b"d";
        let mut vec = vec![];
        for el in self.tree.range(scan_key..).values() {
            let script = Script::from(el?.as_ref().to_vec());
            vec.push(script);
        }
        Ok(vec)
    }

    pub fn iter_utxos(&self) -> Result<Vec<(OutPoint, TxOut)>, Error> {
        let scan_key: &[u8] = b"u";
        let mut vec = vec![];
        for tuple in self.tree.range(scan_key..) {
            let (key, value) = tuple?;
            vec.push((deserialize(&key[1..])?, deserialize(&value)?));
        }
        Ok(vec)
    }

    pub fn save_tx(&self, tx: TransactionMeta, batch: &mut Batch) -> Result<(), Error> {
        let mut key = vec!['t' as u8];
        key.append(&mut hex::decode(&tx.txid)?);

        batch.insert(key, serde_json::to_vec(&tx)?);
        Ok(())
    }

    pub fn save_spent(&self, outpoint: &OutPoint, batch: &mut Batch) -> Result<(), Error> {
        let mut key = vec!['s' as u8];
        key.append(&mut serialize(outpoint));

        batch.insert(key, &[]);
        Ok(())
    }

    pub fn get_spent(&self) -> Result<HashSet<OutPoint>, Error> {
        let r = self.tree.scan_prefix(b"s");
        let mut set = HashSet::new();
        for key in r.keys() {
            set.insert(deserialize(&key?[1..])?);
        }
        Ok(set)
    }

    pub fn list_tx(&self) -> Result<Vec<TransactionMeta>, Error> {
        let r = self.tree.scan_prefix(b"t");
        let mut vec = vec![];
        for value in r.values() {
            vec.push(serde_json::from_slice(&value?)?);
        }
        vec.sort_by(|a: &TransactionMeta, b: &TransactionMeta| b.timestamp.cmp(&a.timestamp));

        Ok(vec)
    }

    fn insert_prefix(&self, prefix: u8, key: Vec<u8>, value: Vec<u8>) -> Result<(), Error> {
        let mut prefix_key = Vec::with_capacity(1 + key.len());
        prefix_key.push(prefix);
        prefix_key.extend(key);
        self.tree.insert(prefix_key, value).map(|_| ()).map_err(|e| e.into())
    }

    pub fn set_external_index(&self, num: u32) -> Result<(), Error> {
        self.insert_prefix('e' as u8, vec![], serde_json::to_vec(&json!(num))?)
    }

    pub fn set_internal_index(&self, num: u32) -> Result<(), Error> {
        self.insert_prefix('i' as u8, vec![], serde_json::to_vec(&json!(num))?)
    }

    fn get_index(&self, key: &[u8]) -> Result<u32, Error> {
        self.tree
            .get(key)?
            .map(|b| -> Result<_, Error> {
                let array: [u8; 4] = b.as_ref().try_into()?;
                let val = u32::from_be_bytes(array);
                Ok(val)
            })
            .unwrap_or(Ok(0))
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
                let mut vec = vec![];
                for chunk in path_bytes.chunks(4) {
                    let n = u32::from_be_bytes(chunk.try_into()?);
                    vec.push(ChildNumber::from(n));
                }
                Some(vec)
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
        let data = self.tree.update_and_fetch(key, increment)?;

        data.map_or(Ok(0), |b| -> Result<_, Error> {
            let array: [u8; 4] = b.as_ref().try_into()?;
            let val = u32::from_be_bytes(array);
            Ok(val)
        })
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
            let e = e?;
            debug!("{:?} {:?}", hex::encode(&e.0), std::str::from_utf8(&e.1));
        }

        Ok(())
    }
}

fn increment(old: Option<&[u8]>) -> Option<Vec<u8>> {
    let number = match old {
        Some(bytes) => {
            let array: [u8; 4] = bytes.try_into().unwrap_or([0; 4]);
            let number = u32::from_be_bytes(array);
            number + 1
        }
        None => 0,
    };

    Some(number.to_be_bytes().to_vec())
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
