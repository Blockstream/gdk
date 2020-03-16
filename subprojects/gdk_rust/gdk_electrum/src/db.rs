use crate::error::{fn_err, Error};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPubKey};
use bitcoin::{Address, BlockHeader, Network, OutPoint, Script, Transaction, TxOut, Txid};
use gdk_common::model::Settings;
use log::debug;
use sled::{self, Tree};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

const BATCH_SIZE: u32 = 20;

/// DB
/// Txid, Transaction      contains all my tx and all prevouts
/// Txid, Height           contains only my tx heights
/// Height, BlockHeader    contains all headers at the height of my txs
/// Script, Path           contains all my script up to an empty batch of BATCHSIZE
/// Path, Script           inverse of the previous

pub struct Forest {
    txs: Tree,
    paths: Tree,
    heights: Tree,
    headers: Tree,
    scripts: Tree,
    singles: Tree,
    secp: Secp256k1<All>,
    xpub: ExtendedPubKey,
}

#[derive(Clone, Copy)]
pub enum Index {
    External = 0,
    Internal = 1,
}

impl Index {
    pub fn from(value: i32) -> Result<Self, Error> {
        Ok(match value {
            0 => Index::External,
            1 => Index::Internal,
            _ => return Err(Error::Generic("only 0 or 1 allowed".into())),
        })
    }
}

impl Forest {
    pub fn new<P: AsRef<std::path::Path>>(path: P, xpub: ExtendedPubKey) -> Result<Self, Error> {
        let db = sled::open(path)?;
        Ok(Forest {
            txs: db.open_tree("txs")?,
            paths: db.open_tree("paths")?,
            heights: db.open_tree("heights")?,
            headers: db.open_tree("headers")?,
            scripts: db.open_tree("scripts")?,
            singles: db.open_tree("singles")?,
            secp: Secp256k1::new(),
            xpub,
        })
    }

    pub fn get_my(&self) -> Result<Vec<(Txid, Option<u32>)>, Error> {
        let mut heights = vec![];
        for keyvalue in self.heights.iter() {
            let (key, value) = keyvalue?;
            let txid = Txid::from_slice(&key)?;
            let height = Height::from_slice(&value)?.1;
            let height = if height == 0 {
                None
            } else {
                Some(height)
            };
            heights.push((txid, height));
        }
        Ok(heights)
    }

    pub fn get_only_heights(&self) -> Result<HashSet<u32>, Error> {
        Ok(self.get_my()?.into_iter().filter_map(|t| t.1).collect())
    }

    pub fn get_only_txids(&self) -> Result<HashSet<Txid>, Error> {
        Ok(self.get_my()?.into_iter().map(|t| t.0).collect())
    }

    pub fn get_all_spent_and_txs(&self) -> Result<(HashSet<OutPoint>, Transactions), Error> {
        let mut txs = Transactions::default();
        let mut spent = HashSet::new();
        for keyvalue in self.txs.iter() {
            let (key, value) = keyvalue?;
            let txid = Txid::from_slice(&key)?;
            let tx: Transaction = deserialize(&value)?;
            for input in tx.input.iter() {
                spent.insert(input.previous_output);
            }
            txs.insert(txid, tx);
        }
        Ok((spent, txs))
    }

    pub fn get_all_txid(&self) -> Result<HashSet<Txid>, Error> {
        let mut set = HashSet::new();
        for keyvalue in self.txs.iter() {
            let (key, _) = keyvalue?;
            let txid = Txid::from_slice(&key)?;
            set.insert(txid);
        }
        Ok(set)
    }

    pub fn get_script_batch(
        &self,
        int_or_ext: Index,
        batch: u32,
        network: Network,
    ) -> Result<Vec<Script>, Error> {
        let mut result = vec![];
        let first_path = [ChildNumber::from(int_or_ext as u32)];
        let first_deriv = self.xpub.derive_pub(&self.secp, &first_path)?;

        let start = batch * BATCH_SIZE;
        let end = start + BATCH_SIZE;
        for j in start..end {
            let path = Path::new(int_or_ext as u32, j);
            let opt_script = self.get_script(&path)?;
            let script = match opt_script {
                Some(script) => script,
                None => {
                    let second_path = [ChildNumber::from(j)];
                    let second_deriv = first_deriv.derive_pub(&self.secp, &second_path)?;
                    let address = Address::p2shwpkh(&second_deriv.public_key, network);
                    debug!("address {}/{} is {}", int_or_ext as u32, j, address);
                    let script = address.script_pubkey();
                    self.insert_script(&path, &script)?;
                    self.insert_path(&script, &path)?;
                    script
                }
            };
            result.push(script);
        }
        Ok(result)
    }

    pub fn get_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
        self.txs.get(txid)?.map(|v| Ok(deserialize(&v)?)).transpose()
    }

    pub fn insert_tx(&self, txid: &Txid, tx: &Transaction) -> Result<(), Error> {
        Ok(self.txs.insert(txid, serialize(tx)).map(|_| ())?)
    }

    pub fn get_header(&self, height: u32) -> Result<Option<BlockHeader>, Error> {
        self.headers.get(Height::new(height))?.map(|v| Ok(deserialize(&v)?)).transpose()
    }

    pub fn insert_header(&self, height: u32, header: &BlockHeader) -> Result<(), Error> {
        Ok(self.headers.insert(Height::new(height), serialize(header)).map(|_| ())?)
    }

    pub fn remove_height(&self, txid: &Txid) -> Result<(), Error> {
        Ok(self.heights.remove(txid).map(|_| ())?)
    }

    pub fn insert_height(&self, txid: &Txid, height: u32) -> Result<(), Error> {
        Ok(self.heights.insert(txid, Height::new(height).as_ref()).map(|_| ())?)
    }

    pub fn get_script(&self, path: &Path) -> Result<Option<Script>, Error> {
        self.scripts.get(path)?.map(|v| Ok(deserialize(&v)?)).transpose()
    }

    pub fn insert_script(&self, path: &Path, script: &Script) -> Result<(), Error> {
        Ok(self.scripts.insert(path, serialize(script)).map(|_| ())?)
    }

    pub fn get_path(&self, script: &Script) -> Result<Option<Path>, Error> {
        self.paths.get(script.as_bytes())?.map(|v| Ok(Path::from_slice(&v)?)).transpose()
    }

    pub fn insert_path(&self, script: &Script, path: &Path) -> Result<(), Error> {
        Ok(self.paths.insert(script.as_bytes(), path.as_ref()).map(|_| ())?)
    }

    pub fn insert_index(&self, int_or_ext: Index, value: u32) -> Result<(), Error> {
        Ok(self.singles.insert([int_or_ext as u8], &value.to_be_bytes()).map(|_| ())?)
    }

    pub fn get_index(&self, int_or_ext: Index) -> Result<u32, Error> {
        let ivec = self.singles.get([int_or_ext as u8])?.ok_or_else(fn_err("no index"))?;
        let bytes: [u8; 4] = ivec.as_ref().try_into()?;
        Ok(u32::from_be_bytes(bytes))
    }

    pub fn increment_index(&self, int_or_ext: Index) -> Result<u32, Error> {
        //TODO should be done atomically
        let new_index = self.get_index(int_or_ext)? + 1;
        self.insert_index(int_or_ext, new_index)?;
        Ok(new_index)
    }

    pub fn insert_settings(&self, settings: &Settings) -> Result<(), Error> {
        Ok(self.singles.insert(b"s", serde_json::to_vec(settings)?).map(|_| ())?)
    }

    pub fn get_settings(&self) -> Result<Option<Settings>, Error> {
        self.singles.get(b"s")?.map(|v| Ok(serde_json::from_slice::<Settings>(&v)?)).transpose()
    }

    pub fn is_mine(&self, script: &Script) -> bool {
        match self.get_path(script) {
            Ok(p) => p.is_some(),
            Err(_) => false,
        }
    }
}

pub struct Transactions(HashMap<Txid, Transaction>);
impl Default for Transactions {
    fn default() -> Self {
        Transactions(HashMap::new())
    }
}
impl Deref for Transactions {
    type Target = HashMap<Txid, Transaction>;
    fn deref(&self) -> &<Self as Deref>::Target {
        &self.0
    }
}
impl DerefMut for Transactions {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Transactions {
    pub fn get_previous_output(&self, outpoint: &OutPoint) -> Option<TxOut> {
        self.0.get(&outpoint.txid).map(|tx| tx.output[outpoint.vout as usize].clone())
    }
    pub fn get_previous_value(&self, outpoint: &OutPoint) -> Option<u64> {
        self.get_previous_output(outpoint).map(|o| o.value)
    }
}

struct Height([u8; 4], u32);
impl AsRef<[u8]> for Height {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}
impl Height {
    fn new(height: u32) -> Self {
        Height(height.to_be_bytes(), height)
    }
    fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        let i: [u8; 4] = slice[..].try_into()?;
        Ok(Height(i, u32::from_be_bytes(i)))
    }
}

//DerivationPath hasn't AsRef<[u8]>
#[derive(Debug, PartialEq)]
pub struct Path {
    bytes: [u8; 8],
    pub i: u32,
    pub j: u32,
}
impl AsRef<[u8]> for Path {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Path {
    fn new(i: u32, j: u32) -> Self {
        let value = ((i as u64) << 32) + j as u64;
        let bytes = value.to_be_bytes();
        Path {
            bytes,
            i,
            j,
        }
    }

    fn from_slice(slice: &[u8]) -> Result<Self, Error> {
        let i: [u8; 4] = slice[..4].try_into()?;
        let j: [u8; 4] = slice[4..].try_into()?;

        Ok(Path::new(u32::from_be_bytes(i), u32::from_be_bytes(j)))
    }

    pub fn to_derivation_path(self) -> Result<DerivationPath, Error> {
        Ok(DerivationPath::from_str(&format!("m/{}/{}", self.i, self.j))?)
    }
}

#[cfg(test)]
mod test {
    use crate::Path;

    #[test]
    fn test_path() {
        let path = Path::new(0, 0);
        assert_eq!(path, Path::from_slice(path.as_ref()));
        let path = Path::new(0, 220);
        assert_eq!(path, Path::from_slice(path.as_ref()));
        let path = Path::new(1, 220);
        assert_eq!(path, Path::from_slice(path.as_ref()));
        let path = Path::new(1, 0);
        assert_eq!(path, Path::from_slice(path.as_ref()));
    }
}
