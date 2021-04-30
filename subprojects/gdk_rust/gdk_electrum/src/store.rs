use crate::spv::CrossValidationResult;
use crate::Error;
use aes_gcm_siv::aead::{generic_array::GenericArray, AeadInPlace, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use bitcoin::hashes::{sha256, Hash};
use bitcoin::util::bip32::{DerivationPath, ExtendedPubKey};
use bitcoin::Transaction;
use gdk_common::be::{BEBlockHash, BEBlockHeader, BEScript, BETransaction, BETransactions, BETxid};
use gdk_common::be::{BETxidConvert, Unblinded};
use gdk_common::model::{AccountSettings, FeeEstimate, SPVVerifyResult, Settings};
use gdk_common::NetworkId;
use log::{info, warn};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;

pub const BATCH_SIZE: u32 = 20;

pub type Store = Arc<RwLock<StoreMeta>>;

/// RawCache is a persisted and encrypted cache of wallet data, contains stuff like wallet transactions
/// It is fully reconstructable from xpub and data from electrum server (plus master blinding for elements)
#[derive(Default, Serialize, Deserialize)]
pub struct RawCache {
    /// account-specific information (transactions, scripts, history, indexes, unblinded)
    pub accounts: HashMap<u32, RawAccountCache>,

    /// contains headers at the height of my txs (used to show tx timestamps)
    pub headers: HashMap<u32, BEBlockHeader>,

    /// verification status of Txid (could be only Verified or NotVerified, absence means InProgress)
    pub txs_verif: HashMap<BETxid, SPVVerifyResult>,

    /// cached fee_estimates
    pub fee_estimates: Vec<FeeEstimate>,

    /// height and hash of tip of the blockchain
    pub tip: (u32, BEBlockHash),

    /// registry assets last modified, used when making the http request
    pub assets_last_modified: String,

    /// registry icons last modified, used when making the http request
    pub icons_last_modified: String,

    /// the result of the last spv cross-validation execution
    pub cross_validation_result: Option<CrossValidationResult>,

    /// whether BIP 44 account recovery was already run for this wallet
    pub accounts_recovered: bool,
}

#[derive(Default, Serialize, Deserialize)]
pub struct RawAccountCache {
    /// contains all my tx and all prevouts
    pub all_txs: BETransactions,

    /// contains all my script up to an empty batch of BATCHSIZE
    pub paths: HashMap<BEScript, DerivationPath>,

    /// inverse of `paths`
    pub scripts: HashMap<DerivationPath, BEScript>,

    /// contains only my wallet txs with the relative heights (None if unconfirmed)
    pub heights: HashMap<BETxid, Option<u32>>,

    /// unblinded values (only for liquid)
    pub unblinded: HashMap<elements::OutPoint, Unblinded>,

    /// max used indexes for external derivation /0/* and internal derivation /1/* (change)
    pub indexes: Indexes,
}

/// RawStore contains data that are not extractable from xpub+blockchain
/// like wallet settings and memos
#[derive(Default, Serialize, Deserialize)]
pub struct RawStore {
    /// wallet settings
    settings: Option<Settings>,

    /// transaction memos (account_num -> txid -> memo)
    memos: HashMap<bitcoin::Txid, String>,

    // additional fields should always be appended at the end as an `Option` to retain db backwards compatibility.
    /// account settings
    accounts_settings: Option<HashMap<u32, AccountSettings>>,
}

pub struct StoreMeta {
    pub cache: RawCache,
    pub store: RawStore,
    id: NetworkId,
    path: PathBuf,
    cipher: Aes256GcmSiv,
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
    /// create a new RawCache, try to load data from a file or a fallback file
    /// errors such as corrupted file or model change in the db, result in a empty store that will be repopulated
    fn new<P: AsRef<Path>>(
        path: P,
        cipher: &Aes256GcmSiv,
        fallback_path: Option<&Path>,
        fallback_cipher: Option<&Aes256GcmSiv>,
    ) -> Self {
        Self::try_new(path, cipher).unwrap_or_else(|e| {
            if let (Some(fpath), Some(fcipher)) = (fallback_path, fallback_cipher) {
                if let Ok(store) = Self::try_new(fpath, &fcipher) {
                    return store;
                };
            };
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
    /// create a new RawStore, try to load data from a file or a fallback file
    /// errors such as corrupted file or model change in the db, result in a empty store that will be repopulated
    fn new<P: AsRef<Path>>(
        path: P,
        cipher: &Aes256GcmSiv,
        fallback_path: Option<&Path>,
        fallback_cipher: Option<&Aes256GcmSiv>,
    ) -> Self {
        Self::try_new(path, cipher).unwrap_or_else(|e| {
            if let (Some(fpath), Some(fcipher)) = (fallback_path, fallback_cipher) {
                if let Ok(store) = Self::try_new(fpath, &fcipher) {
                    return store;
                };
            };
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

fn get_cipher(xpub: &ExtendedPubKey) -> Aes256GcmSiv {
    let mut enc_key_data = vec![];
    enc_key_data.extend(&xpub.public_key.to_bytes());
    enc_key_data.extend(&xpub.chain_code.to_bytes());
    enc_key_data.extend(&xpub.network.magic().to_be_bytes());
    let key_bytes = sha256::Hash::hash(&enc_key_data).into_inner();
    let key = GenericArray::from_slice(&key_bytes);
    Aes256GcmSiv::new(&key)
}

impl StoreMeta {
    pub fn new<P: AsRef<Path>>(
        path: P,
        xpub: ExtendedPubKey,
        fallback_path: Option<&Path>,
        fallback_xpub: Option<ExtendedPubKey>,
        id: NetworkId,
    ) -> Result<StoreMeta, Error> {
        let cipher = get_cipher(&xpub);
        let fallback_cipher = &fallback_xpub.and_then(|xpub| Some(get_cipher(&xpub)));
        let mut cache =
            RawCache::new(path.as_ref(), &cipher, fallback_path, fallback_cipher.as_ref());
        let mut store =
            RawStore::new(path.as_ref(), &cipher, fallback_path, fallback_cipher.as_ref());
        let path = path.as_ref().to_path_buf();
        if !path.exists() {
            std::fs::create_dir_all(&path)?;
        }

        cache.accounts.entry(0).or_default();
        store.accounts_settings.get_or_insert_with(|| Default::default());

        Ok(StoreMeta {
            cache,
            store,
            id,
            cipher,
            path,
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

    pub fn account_cache(&self, account_num: u32) -> Result<&RawAccountCache, Error> {
        self.cache.accounts.get(&account_num).ok_or_else(|| Error::InvalidSubaccount(account_num))
    }

    pub fn account_cache_mut(&mut self, account_num: u32) -> Result<&mut RawAccountCache, Error> {
        self.cache
            .accounts
            .get_mut(&account_num)
            .ok_or_else(|| Error::InvalidSubaccount(account_num))
    }

    pub fn make_account_cache(&mut self, account_num: u32) -> &mut RawAccountCache {
        self.cache.accounts.entry(account_num).or_default()
    }

    pub fn account_nums(&self) -> HashSet<u32> {
        self.cache.accounts.keys().copied().collect()
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

    pub fn insert_memo(&mut self, txid: BETxid, memo: &str) -> Result<(), Error> {
        // Coerced into a bitcoin::Txid to retain database compatibility
        let txid = txid.into_bitcoin();
        self.store.memos.insert(txid, memo.to_string());
        self.flush_store()?;
        Ok(())
    }

    pub fn get_memo(&self, txid: &BETxid) -> Option<&String> {
        self.store.memos.get(&txid.into_bitcoin())
    }

    pub fn insert_settings(&mut self, settings: Option<Settings>) -> Result<(), Error> {
        self.store.settings = settings;
        self.flush_store()?;
        Ok(())
    }

    pub fn get_settings(&self) -> Option<Settings> {
        self.store.settings.clone()
    }

    pub fn get_accounts_settings(&self) -> &HashMap<u32, AccountSettings> {
        // This field is an Option to retain backwards compatibility with the db serialization,
        // but is guaranteed to be initialized as a Some (via StoreMeta::new).
        self.store.accounts_settings.as_ref().expect("set during initialization")
    }

    pub fn get_account_settings(&self, account_num: u32) -> Option<&AccountSettings> {
        self.get_accounts_settings().get(&account_num)
    }

    pub fn get_account_name(&self, account_num: u32) -> Option<&String> {
        self.get_account_settings(account_num).map(|s| &s.name)
    }

    pub fn set_account_settings(&mut self, account_num: u32, settings: AccountSettings) {
        self.store.accounts_settings.as_mut().unwrap().insert(account_num, settings);
    }

    pub fn spv_verification_status(&self, account_num: u32, txid: &BETxid) -> SPVVerifyResult {
        let acc_store = match self.account_cache(account_num) {
            Ok(store) => store,
            Err(_) => return SPVVerifyResult::NotVerified,
        };

        if let Some(height) = acc_store.heights.get(txid).unwrap_or(&None) {
            match &self.cache.cross_validation_result {
                Some(CrossValidationResult::Invalid(inv)) if *height > inv.common_ancestor => {
                    // Report an SPV validation failure if the transaction was confirmed after the forking point
                    SPVVerifyResult::NotLongest
                }
                _ => self.cache.txs_verif.get(txid).cloned().unwrap_or(SPVVerifyResult::InProgress),
            }
        } else {
            SPVVerifyResult::Unconfirmed
        }
    }

    pub fn export_cache(&self) -> Result<RawCache, Error> {
        self.flush_cache()?;
        RawCache::try_new(&self.path, &self.cipher)
    }
}

impl RawAccountCache {
    pub fn get_bitcoin_tx(&self, txid: &bitcoin::Txid) -> Result<Transaction, Error> {
        match self.all_txs.get(&txid.into_be()) {
            Some(BETransaction::Bitcoin(tx)) => Ok(tx.clone()),
            _ => Err(Error::Generic("expected bitcoin tx".to_string())),
        }
    }

    pub fn get_liquid_tx(&self, txid: &elements::Txid) -> Result<elements::Transaction, Error> {
        match self.all_txs.get(&txid.into_be()) {
            Some(BETransaction::Elements(tx)) => Ok(tx.clone()),
            _ => Err(Error::Generic("expected liquid tx".to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::util::bip32::ExtendedPubKey;
    use bitcoin::Network;
    use gdk_common::{be::BETxid, NetworkId};
    use std::str::FromStr;
    use tempdir::TempDir;

    #[test]
    fn test_db_roundtrip() {
        let id = NetworkId::Bitcoin(Network::Testnet);
        let mut dir = TempDir::new("unit_test").unwrap().into_path();
        dir.push("store");
        // abandon ... M/49'/0'/0'
        let xpub = ExtendedPubKey::from_str("tpubD97UxEEcrMpkE8yG3NQveraWveHzTAJx3KwPsUycx9ABfxRjMtiwfm6BtrY5yhF9yF2eyMg2hyDtGDYXx6gVLBox1m2Mq4u8zB2NXFhUZmm").unwrap();
        let txid = BETxid::from_hex(
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            id,
        )
        .unwrap();
        let txid_btc = txid.ref_bitcoin().unwrap();

        {
            let mut store = StoreMeta::new(&dir, xpub, None, None, id).unwrap();
            store.account_cache_mut(0).unwrap().heights.insert(txid, Some(1));
            store.store.memos.insert(*txid_btc, "memo".to_string());
        }

        let store = StoreMeta::new(&dir, xpub, None, None, id).unwrap();
        assert_eq!(store.account_cache(0).unwrap().heights.get(&txid), Some(&Some(1)));
        assert_eq!(store.store.memos.get(txid_btc), Some(&"memo".to_string()));

        let mut dir2 = TempDir::new("unit_test_2").unwrap().into_path();
        dir2.push("store");
        // abandon ... M (master_xpub)
        let xpub2 = ExtendedPubKey::from_str("tpubD6NzVbkrYhZ4XYa9MoLt4BiMZ4gkt2faZ4BcmKu2a9te4LDpQmvEz2L2yDERivHxFPnxXXhqDRkUNnQCpZggCyEZLBktV7VaSmwayqMJy1s").unwrap();

        // Before creating a new empty store, attempt recovery from fallback path
        {
            let mut store = StoreMeta::new(&dir2, xpub2, Some(&dir), Some(xpub), id).unwrap();
            assert_eq!(store.account_cache_mut(0).unwrap().heights.get(&txid), Some(&Some(1)));
            assert_eq!(store.store.memos.get(txid_btc), Some(&"memo".to_string()));
            // Persist data in new path
        }

        let store = StoreMeta::new(&dir2, xpub2, None, None, id).unwrap();
        assert_eq!(store.account_cache(0).unwrap().heights.get(&txid), Some(&Some(1)));
        assert_eq!(store.store.memos.get(txid_btc), Some(&"memo".to_string()));
    }

    #[test]
    fn test_db_upgrade() {
        #[derive(Serialize, Deserialize)]
        struct RawStoreV0 {
            settings: Option<Settings>,
            memos: HashMap<bitcoin::Txid, String>,
        }

        type RawStoreV1 = RawStore;

        let store_v0 = RawStoreV0 {
            settings: Some(Settings::default()),
            memos: {
                let mut memos = HashMap::new();
                memos.insert(bitcoin::Txid::default(), "Foobar".into());
                memos
            },
        };

        let blob = serde_cbor::to_vec(&store_v0).unwrap();
        let store_v1: RawStoreV1 = serde_cbor::from_slice(&blob).unwrap();

        assert_eq!(store_v0.settings, store_v1.settings);
        assert_eq!(store_v0.memos, store_v1.memos);

        let blob = serde_cbor::to_vec(&store_v1).unwrap();
        let store_v0: RawStoreV0 = serde_cbor::from_slice(&blob).unwrap();
        assert_eq!(store_v0.settings, store_v1.settings);
        assert_eq!(store_v0.memos, store_v1.memos);
    }
}
