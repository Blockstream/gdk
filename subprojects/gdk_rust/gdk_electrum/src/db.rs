use crate::error::{fn_err, Error};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPubKey};
use bitcoin::{Address, OutPoint, Script, Transaction, TxOut, Txid};
use elements::AddressParams;
use gdk_common::be::*;
use gdk_common::model::Settings;
use gdk_common::util::p2shwpkh_script;
use gdk_common::wally::{
    asset_blinding_key_to_ec_private_key, ec_public_key_from_private_key, MasterBlindingKey,
};
use gdk_common::{ElementsNetwork, NetworkId};
use log::{debug, trace};
use serde_json::Value;
use sled::{self, Batch, Tree};
use std::collections::{HashMap, HashSet};
use std::convert::TryInto;
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

pub const BATCH_SIZE: u32 = 20;

/// DB
/// Txid, Transaction      contains all my tx and all prevouts
/// Txid, Height           contains only my tx heights
/// Height, BlockHeader    contains all headers at the height of my txs
/// Script, Path           contains all my script up to an empty batch of BATCHSIZE
/// Path, Script           inverse of the previous
/// OutPoint, Unblinded    unblinded values (only for liquid)

#[derive(Debug, Clone)]
pub struct Forest {
    txs: Tree,
    paths: Tree,
    heights: Tree,
    headers: Tree,
    scripts: Tree,
    singles: Tree,
    unblinded: Tree,
    secp: Secp256k1<All>,
    xpub: ExtendedPubKey,
    master_blinding: Option<MasterBlindingKey>,
    id: NetworkId,
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
    pub fn new<P: AsRef<std::path::Path>>(
        path: P,
        xpub: ExtendedPubKey,
        master_blinding: Option<MasterBlindingKey>,
        id: NetworkId,
    ) -> Result<Self, Error> {
        let db = sled::open(path)?;
        Ok(Forest {
            txs: db.open_tree("txs")?,
            paths: db.open_tree("paths")?,
            heights: db.open_tree("heights")?,
            headers: db.open_tree("headers")?,
            scripts: db.open_tree("scripts")?,
            singles: db.open_tree("singles")?,
            unblinded: db.open_tree("unblinded")?,
            secp: Secp256k1::new(),
            master_blinding,
            xpub,
            id,
        })
    }

    /// returns Txid of my wallet transactions, with height if confirmed
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

    pub fn get_all_spent_and_txs(&self) -> Result<(HashSet<BEOutPoint>, BETransactions), Error> {
        debug!("get_all_spent_and_txs");
        let mut txs = BETransactions::default();
        let mut spent = HashSet::new();
        for keyvalue in self.txs.iter() {
            let (key, value) = keyvalue?;
            let txid = Txid::from_slice(&key)?;
            let tx: BETransaction = BETransaction::deserialize(&value, self.id)?;
            for prevout in tx.previous_outputs() {
                spent.insert(prevout);
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

    pub fn get_all_scripts(&self) -> Result<HashSet<Script>, Error> {
        debug!("get_all_scripts");
        let mut set = HashSet::new();
        for keyvalue in self.scripts.iter() {
            let (_, value) = keyvalue?;
            let script = deserialize(&value)?;
            set.insert(script);
        }
        Ok(set)
    }

    pub fn get_script_batch(&self, int_or_ext: Index, batch: u32) -> Result<Vec<Script>, Error> {
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
                    // Note we are using regtest here because we are not interested in the address, only in script construction
                    let script = match self.id {
                        NetworkId::Bitcoin(network) => {
                            let address = Address::p2shwpkh(&second_deriv.public_key, network);
                            trace!("{}/{} {}", int_or_ext as u32, j, address);
                            address.script_pubkey()
                        }
                        NetworkId::Elements(network) => {
                            let params = match network {
                                ElementsNetwork::Liquid => &AddressParams::LIQUID,
                                ElementsNetwork::ElementsRegtest => &AddressParams::ELEMENTS,
                            };

                            let script = p2shwpkh_script(&second_deriv.public_key);
                            let blinding_key = asset_blinding_key_to_ec_private_key(
                                self.master_blinding.as_ref().ok_or_else(fn_err(
                                    "missing master blinding in elements session",
                                ))?,
                                &script,
                            );
                            let public_key = ec_public_key_from_private_key(blinding_key);
                            let blinder = Some(public_key);

                            let address = elements::Address::p2shwpkh(
                                &second_deriv.public_key,
                                blinder,
                                params,
                            );
                            trace!(
                                "{}/{} blinded address {}  blinder {:?}",
                                int_or_ext as u32,
                                j,
                                address,
                                blinder
                            );
                            assert_eq!(script, address.script_pubkey());
                            address.script_pubkey()
                        }
                    };
                    self.insert_script(&path, &script)?;
                    self.insert_path(&script, &path)?;
                    script
                }
            };
            result.push(script);
        }
        Ok(result)
    }

    pub fn get_tx(&self, txid: &Txid) -> Result<Option<BETransaction>, Error> {
        self.txs.get(txid)?.map(|v| Ok(BETransaction::deserialize(&v, self.id)?)).transpose()
    }
    pub fn get_bitcoin_tx(&self, txid: &Txid) -> Result<Option<Transaction>, Error> {
        match self.get_tx(txid) {
            Ok(Some(BETransaction::Bitcoin(tx))) => Ok(Some(tx)),
            _ => Err(Error::Generic("exptected bitcoin tx".to_string())),
        }
    }

    pub fn get_liquid_tx(&self, txid: &Txid) -> Result<Option<elements::Transaction>, Error> {
        match self.get_tx(txid) {
            Ok(Some(BETransaction::Elements(tx))) => Ok(Some(tx)),
            _ => Err(Error::Generic("exptected liquid tx".to_string())),
        }
    }

    pub fn insert_tx(&self, txid: &Txid, tx: &BETransaction) -> Result<(), Error> {
        Ok(self.txs.insert(txid, tx.serialize()).map(|_| ())?)
    }

    pub fn insert_unblinded(
        &self,
        outpoint: &elements::OutPoint,
        asset_value: &Unblinded,
    ) -> Result<(), Error> {
        Ok(self
            .unblinded
            .insert(elements::encode::serialize(outpoint), asset_value.serialize())
            .map(|_| ())?)
    }

    pub fn get_unblinded(&self, outpoint: &elements::OutPoint) -> Result<Option<Unblinded>, Error> {
        self.unblinded
            .get(elements::encode::serialize(outpoint))?
            .map(|v| Ok(Unblinded::deserialize(&v)?))
            .transpose()
    }

    pub fn get_all_unblinded(&self) -> Result<HashMap<elements::OutPoint, Unblinded>, Error> {
        debug!("get_all_unblinded");
        let mut map = HashMap::new();
        for keyvalue in self.unblinded.iter() {
            let (key, value) = keyvalue?;
            let outpoint = elements::encode::deserialize(&key)?;
            let unblinded = Unblinded::deserialize(&value)?;
            map.insert(outpoint, unblinded);
        }
        Ok(map)
    }

    pub fn get_header(&self, height: u32) -> Result<Option<BEBlockHeader>, Error> {
        self.headers
            .get(Height::new(height))?
            .map(|v| Ok(BEBlockHeader::deserialize(&v, self.id)?))
            .transpose()
    }

    pub fn insert_header(&self, height: u32, header: &BEBlockHeader) -> Result<(), Error> {
        Ok(self.headers.insert(Height::new(height), header.serialize()).map(|_| ())?)
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
        match self.singles.get([int_or_ext as u8])? {
            Some(ivec) => {
                let bytes: [u8; 4] = ivec.as_ref().try_into()?;
                Ok(u32::from_be_bytes(bytes))
            }
            None => Ok(0),
        }
    }
    pub fn increment_index(&self, int_or_ext: Index, increment: u32) -> Result<u32, Error> {
        //TODO should be done atomically
        let new_index = self.get_index(int_or_ext)? + increment;
        self.insert_index(int_or_ext, new_index)?;
        Ok(new_index)
    }

    pub fn insert_settings(&self, settings: &Settings) -> Result<(), Error> {
        Ok(self.singles.insert(b"s", serde_json::to_vec(settings)?).map(|_| ())?)
    }
    pub fn get_settings(&self) -> Result<Option<Settings>, Error> {
        self.singles.get(b"s")?.map(|v| Ok(serde_json::from_slice::<Settings>(&v)?)).transpose()
    }

    pub fn insert_tip(&self, height: u32) -> Result<(), Error> {
        Ok(self.singles.insert(b"t", &height.to_be_bytes()).map(|_| ())?)
    }
    pub fn get_tip(&self) -> Result<u32, Error> {
        match self.singles.get(b"t")? {
            Some(ivec) => {
                let bytes: [u8; 4] = ivec.as_ref().try_into()?;
                Ok(u32::from_be_bytes(bytes))
            }
            None => Ok(0),
        }
    }

    pub fn get_asset_icons(&self) -> Result<Option<Value>, Error> {
        self.singles.get(b"i")?.map(|v| Ok(serde_json::from_slice::<Value>(&v)?)).transpose()
    }
    pub fn insert_asset_icons(&self, asset_icons: &Value) -> Result<(), Error> {
        Ok(self.singles.insert(b"i", serde_json::to_vec(asset_icons)?).map(|_| ())?)
    }

    pub fn get_asset_registry(&self) -> Result<Option<Value>, Error> {
        self.singles.get(b"r")?.map(|v| Ok(serde_json::from_slice::<Value>(&v)?)).transpose()
    }
    pub fn insert_asset_registry(&self, asset_registry: &Value) -> Result<(), Error> {
        Ok(self.singles.insert(b"r", serde_json::to_vec(asset_registry)?).map(|_| ())?)
    }

    pub fn is_mine(&self, script: &Script) -> bool {
        match self.get_path(script) {
            Ok(p) => p.is_some(),
            Err(_) => false,
        }
    }

    pub fn apply_txs_batch(&self, batch: Batch) -> Result<(), Error> {
        Ok(self.txs.apply_batch(batch)?)
    }

    pub fn flush(&self) -> Result<usize, Error> {
        let mut bytes_flushed = 0;
        bytes_flushed += self.txs.flush()?;
        bytes_flushed += self.paths.flush()?;
        bytes_flushed += self.heights.flush()?;
        bytes_flushed += self.headers.flush()?;
        bytes_flushed += self.scripts.flush()?;
        bytes_flushed += self.singles.flush()?;
        bytes_flushed += self.unblinded.flush()?;
        Ok(bytes_flushed)
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

    pub fn into_derivation_path(self) -> Result<DerivationPath, Error> {
        Ok(DerivationPath::from_str(&format!("m/{}/{}", self.i, self.j))?)
    }
}
