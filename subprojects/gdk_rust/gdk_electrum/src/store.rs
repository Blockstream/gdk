use crate::spv::CrossValidationResult;
use crate::Error;
use aes_gcm_siv::aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPubKey};
use bitcoin::{Address, BlockHash, Script, Transaction, Txid};
use elements::{AddressParams, OutPoint};
use gdk_common::be::{BEBlockHeader, BEOutPoint, BETransaction, BETransactions};
use gdk_common::be::{ScriptBatch, Unblinded};
use gdk_common::error::fn_err;
use gdk_common::model::{FeeEstimate, SPVVerifyResult, Settings};
use gdk_common::scripts::p2shwpkh_script;
use gdk_common::wally::{
    asset_blinding_key_to_ec_private_key, ec_public_key_from_private_key, MasterBlindingKey,
};
use gdk_common::{ElementsNetwork, NetworkId};
use log::{info, trace, warn};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

pub const BATCH_SIZE: u32 = 20;

pub type Store = Arc<RwLock<StoreMeta>>;

/// RawCache is a persisted and encrypted cache of wallet data, contains stuff like wallet transactions
/// It is fully reconstructable from xpub and data from electrum server (plus master blinding for elements)
#[derive(Default, Serialize, Deserialize)]
pub struct RawCache {
    /// contains all my tx and all prevouts
    pub all_txs: BETransactions,

    /// contains all my script up to an empty batch of BATCHSIZE
    pub paths: HashMap<Script, DerivationPath>,

    /// inverse of `paths`
    pub scripts: HashMap<DerivationPath, Script>, // TODO use DerivationPath once Hash gets merged

    /// contains only my wallet txs with the relative heights (None if unconfirmed)
    pub heights: HashMap<Txid, Option<u32>>,

    /// contains headers at the height of my txs (used to show tx timestamps)
    pub headers: HashMap<u32, BEBlockHeader>,

    /// unblinded values (only for liquid)
    pub unblinded: HashMap<OutPoint, Unblinded>,

    /// verification status of Txid (could be only Verified or NotVerified, absence means InProgress)
    pub txs_verif: HashMap<Txid, SPVVerifyResult>,

    /// cached fee_estimates
    pub fee_estimates: Vec<FeeEstimate>,

    /// height and hash of tip of the blockchain
    pub tip: (u32, BlockHash),

    /// max used indexes for external derivation /0/* and internal derivation /1/* (change)
    pub indexes: Indexes,

    /// registry assets last modified, used when making the http request
    pub assets_last_modified: String,

    /// registry icons last modified, used when making the http request
    pub icons_last_modified: String,

    /// the result of the last spv cross-validation execution
    pub cross_validation_result: Option<CrossValidationResult>,
}

/// RawStore contains data that are not extractable from xpub+blockchain
/// like wallet settings and memos
#[derive(Default, Serialize, Deserialize)]
pub struct RawStore {
    /// wallet settings
    settings: Option<Settings>,

    /// transaction memos
    memos: HashMap<Txid, String>,
}

pub struct StoreMeta {
    pub cache: RawCache,
    pub store: RawStore,
    master_blinding: Option<MasterBlindingKey>,
    secp: Secp256k1<All>,
    id: NetworkId,
    path: PathBuf,
    cipher: Aes256GcmSiv,
    first_deriv: [ExtendedPubKey; 2],
}

impl Drop for StoreMeta {
    fn drop(&mut self) {
        self.flush().unwrap();
    }
}

#[derive(Debug, PartialEq, Eq, Default, Clone, Serialize, Deserialize)]
pub struct Indexes {
    pub external: u32, // m/0/*
    pub internal: u32, // m/1/*
}

impl RawCache {
    /// create a new RawCache, loading data from a file if any and if there is no error in reading
    /// errors such as corrupted file or model change in the db, result in a empty store that will be repopulated
    fn new<P: AsRef<Path>>(path: P, cipher: &Aes256GcmSiv) -> Self {
        Self::try_new(path, cipher).unwrap_or_else(|e| {
            warn!("Initialize cache as default {:?}", e);
            Default::default()
        })
    }

    fn try_new<P: AsRef<Path>>(path: P, cipher: &Aes256GcmSiv) -> Result<Self, Error> {
        let decrypted = load_decrypt("cache", path, cipher)?;
        let store = serde_cbor::from_slice(&decrypted)?;
        Ok(store)
    }
}

impl RawStore {
    /// create a new RawStore, loading data from a file if any and if there is no error in reading
    /// errors such as corrupted file or model change in the db, result in a empty store that will be repopulated
    fn new<P: AsRef<Path>>(path: P, cipher: &Aes256GcmSiv) -> Self {
        Self::try_new(path, cipher).unwrap_or_else(|e| {
            warn!("Initialize store as default {:?}", e);
            Default::default()
        })
    }

    fn try_new<P: AsRef<Path>>(path: P, cipher: &Aes256GcmSiv) -> Result<Self, Error> {
        let decrypted = load_decrypt("store", path, cipher)?;
        let store = serde_cbor::from_slice(&decrypted)?;
        Ok(store)
    }
}

fn load_decrypt<P: AsRef<Path>>(
    name: &str,
    path: P,
    cipher: &Aes256GcmSiv,
) -> Result<Vec<u8>, Error> {
    let now = Instant::now();
    let mut store_path = PathBuf::from(path.as_ref());
    store_path.push(name);
    if !store_path.exists() {
        return Err(Error::Generic(format!("{:?} do not exist", store_path)));
    }
    let mut file = File::open(&store_path)?;
    let mut nonce_bytes = [0u8; 12];
    file.read_exact(&mut nonce_bytes)?;
    let nonce = GenericArray::from_slice(&nonce_bytes);
    let mut ciphertext = vec![];
    file.read_to_end(&mut ciphertext)?;

    cipher.decrypt_in_place(nonce, b"", &mut ciphertext)?;
    let plaintext = ciphertext;

    info!("loading {:?} took {}ms", &store_path, now.elapsed().as_millis());
    Ok(plaintext)
}

impl StoreMeta {
    pub fn new<P: AsRef<Path>>(
        path: P,
        xpub: ExtendedPubKey,
        master_blinding: Option<MasterBlindingKey>,
        id: NetworkId,
    ) -> Result<StoreMeta, Error> {
        let mut enc_key_data = vec![];
        enc_key_data.extend(&xpub.public_key.to_bytes());
        enc_key_data.extend(&xpub.chain_code.to_bytes());
        enc_key_data.extend(&xpub.network.magic().to_be_bytes());
        let key_bytes = sha256::Hash::hash(&enc_key_data).into_inner();
        let key = GenericArray::from_slice(&key_bytes);
        let cipher = Aes256GcmSiv::new(&key);
        let cache = RawCache::new(path.as_ref(), &cipher);
        let store = RawStore::new(path.as_ref(), &cipher);
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
        }
        let secp = Secp256k1::new();

        let first_deriv = [
            xpub.derive_pub(&secp, &[ChildNumber::from(0)])?,
            xpub.derive_pub(&secp, &[ChildNumber::from(1)])?,
        ];

        Ok(StoreMeta {
            cache,
            store,
            master_blinding,
            id,
            cipher,
            secp,
            path,
            first_deriv,
        })
    }

    fn flush_serializable<T: serde::Serialize>(&self, name: &str, value: &T) -> Result<(), Error> {
        let now = Instant::now();
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let mut plaintext = serde_cbor::to_vec(value)?;

        self.cipher.encrypt_in_place(nonce, b"", &mut plaintext)?;
        let ciphertext = plaintext;

        let mut store_path = self.path.clone();
        store_path.push(name);
        //TODO should avoid rewriting if not changed? it involves saving plaintext (or struct hash)
        // in the front of the file
        let mut file = File::create(&store_path)?;
        file.write(&nonce_bytes)?;
        file.write(&ciphertext)?;
        info!(
            "flushing {} bytes on {:?} took {}ms",
            ciphertext.len() + 16,
            &store_path,
            now.elapsed().as_millis()
        );
        Ok(())
    }

    fn flush_store(&self) -> Result<(), Error> {
        self.flush_serializable("store", &self.store)?;
        Ok(())
    }

    fn flush_cache(&self) -> Result<(), Error> {
        self.flush_serializable("cache", &self.cache)?;
        Ok(())
    }

    pub fn flush(&self) -> Result<(), Error> {
        self.flush_store()?;
        self.flush_cache()?;
        Ok(())
    }

    fn read(&self, name: &str) -> Result<Option<Value>, Error> {
        let mut path = self.path.clone();
        path.push(name);
        if path.exists() {
            let mut file = File::open(path)?;
            let mut buffer = vec![];
            info!("start read from {}", name);
            file.read_to_end(&mut buffer)?;
            info!("end read from {}, start parsing json", name);
            let value = serde_json::from_slice(&buffer)?;
            info!("end parsing json {}", name);
            Ok(Some(value))
        } else {
            Ok(None)
        }
    }

    fn write(&self, name: &str, value: &Value) -> Result<(), Error> {
        let mut path = self.path.clone();
        path.push(name);
        let mut file = File::create(path)?;
        let vec = serde_json::to_vec(value)?;
        info!("start write {} bytes to {}", vec.len(), name);
        file.write(&vec)?;
        info!("end write {} bytes to {}", vec.len(), name);
        Ok(())
    }

    pub fn read_asset_icons(&self) -> Result<Option<Value>, Error> {
        self.read("asset_icons")
    }

    /// write asset icons to a local file
    /// it is stored out of the encrypted area since it's public info
    pub fn write_asset_icons(&self, asset_icons: &Value) -> Result<(), Error> {
        self.write("asset_icons", asset_icons)
    }

    pub fn read_asset_registry(&self) -> Result<Option<Value>, Error> {
        self.read("asset_registry")
    }

    /// write asset registry to a local file
    /// it is stored out of the encrypted area since it's public info
    pub fn write_asset_registry(&self, asset_registry: &Value) -> Result<(), Error> {
        self.write("asset_registry", asset_registry)
    }

    pub fn get_script_batch(&self, int_or_ext: u32, batch: u32) -> Result<ScriptBatch, Error> {
        let mut result = ScriptBatch::default();
        result.cached = true;

        //TODO cache m/0 and m/1
        let first_deriv = &self.first_deriv[int_or_ext as usize];

        let start = batch * BATCH_SIZE;
        let end = start + BATCH_SIZE;
        for j in start..end {
            let path = DerivationPath::from_str(&format!("m/{}/{}", int_or_ext, j))?;
            let opt_script = self.cache.scripts.get(&path);
            let script = match opt_script {
                Some(script) => script.clone(),
                None => {
                    result.cached = false;
                    let second_path = [ChildNumber::from(j)];
                    let second_deriv = first_deriv.derive_pub(&self.secp, &second_path)?;
                    // Note we are using regtest here because we are not interested in the address, only in script construction
                    let script = match self.id {
                        NetworkId::Bitcoin(network) => {
                            let address =
                                Address::p2shwpkh(&second_deriv.public_key, network).unwrap();
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

                    script
                }
            };
            result.value.push((script, path));
        }
        Ok(result)
    }

    pub fn get_bitcoin_tx(&self, txid: &Txid) -> Result<Transaction, Error> {
        match self.cache.all_txs.get(txid) {
            Some(BETransaction::Bitcoin(tx)) => Ok(tx.clone()),
            _ => Err(Error::Generic("expected bitcoin tx".to_string())),
        }
    }

    pub fn get_liquid_tx(&self, txid: &Txid) -> Result<elements::Transaction, Error> {
        match self.cache.all_txs.get(txid) {
            Some(BETransaction::Elements(tx)) => Ok(tx.clone()),
            _ => Err(Error::Generic("expected liquid tx".to_string())),
        }
    }

    pub fn spent(&self) -> Result<HashSet<BEOutPoint>, Error> {
        let mut result = HashSet::new();
        for tx in self.cache.all_txs.values() {
            let outpoints: Vec<BEOutPoint> = match tx {
                BETransaction::Bitcoin(tx) => {
                    tx.input.iter().map(|i| BEOutPoint::Bitcoin(i.previous_output)).collect()
                }
                BETransaction::Elements(tx) => {
                    tx.input.iter().map(|i| BEOutPoint::Elements(i.previous_output)).collect()
                }
            };
            result.extend(outpoints.into_iter());
        }
        Ok(result)
    }

    pub fn fee_estimates(&self) -> Vec<FeeEstimate> {
        if self.cache.fee_estimates.is_empty() {
            let min_fee = match self.id {
                NetworkId::Bitcoin(_) => 1000,
                NetworkId::Elements(_) => 100,
            };
            vec![FeeEstimate(min_fee); 25]
        } else {
            self.cache.fee_estimates.clone()
        }
    }

    pub fn insert_memo(&mut self, txid: Txid, memo: &str) -> Result<(), Error> {
        self.store.memos.insert(txid, memo.to_string());
        self.flush_store()?;
        Ok(())
    }

    pub fn get_memo(&self, txid: &Txid) -> Option<&String> {
        self.store.memos.get(txid)
    }

    pub fn insert_settings(&mut self, settings: Option<Settings>) -> Result<(), Error> {
        self.store.settings = settings;
        self.flush_store()?;
        Ok(())
    }

    pub fn get_settings(&self) -> Option<Settings> {
        self.store.settings.clone()
    }

    pub fn spv_verification_status(&self, txid: &Txid) -> SPVVerifyResult {
        match &self.cache.cross_validation_result {
            Some(cv_result) if !cv_result.is_valid() => SPVVerifyResult::NotLongest,
            _ => self.cache.txs_verif.get(txid).cloned().unwrap_or(SPVVerifyResult::InProgress),
        }
    }
}

impl StoreMeta {
    pub fn export_cache(&self) -> Result<RawCache, Error> {
        self.flush_cache()?;
        RawCache::try_new(&self.path, &self.cipher)
    }
}

#[cfg(test)]
mod tests {
    use crate::store::StoreMeta;
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::util::bip32::ExtendedPubKey;
    use bitcoin::{Network, Txid};
    use gdk_common::NetworkId;
    use std::str::FromStr;
    use tempdir::TempDir;

    #[test]
    fn test_db_roundtrip() {
        let mut dir = TempDir::new("unit_test").unwrap().into_path();
        dir.push("store");
        let xpub = ExtendedPubKey::from_str("tpubD6NzVbkrYhZ4YfG9CySHqKHFbaLcD7hSDyqRUtCmMKNim5fkiJtTnFeqKsRHMHSK5ddFrhqRr3Ghv1JtuWkBzikuBqKu1xCpjQ9YxoPGgqU").unwrap();
        let txid =
            Txid::from_hex("f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16")
                .unwrap();

        let id = NetworkId::Bitcoin(Network::Testnet);
        let mut store = StoreMeta::new(&dir, xpub, None, id).unwrap();
        store.cache.heights.insert(txid, Some(1));
        drop(store);

        let store = StoreMeta::new(&dir, xpub, None, id).unwrap();
        assert_eq!(store.cache.heights.get(&txid), Some(&Some(1)));
    }
}
