use crate::account::xpubs_equivalent;
use crate::spv::CrossValidationResult;
use crate::Error;
use aes_gcm_siv::aead::{AeadInPlace, NewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use bitcoin::hashes::{sha256, Hash};
use bitcoin::util::bip32::{DerivationPath, ExtendedPubKey};
use bitcoin::Transaction;
use elements::TxOutSecrets;
use gdk_common::be::BETxidConvert;
use gdk_common::be::{
    BEBlockHash, BEBlockHeader, BEScript, BETransaction, BETransactionEntry, BETransactions, BETxid,
};
use gdk_common::model::{AccountSettings, FeeEstimate, SPVVerifyTxResult, Settings};
use gdk_common::wally::MasterBlindingKey;
use gdk_common::NetworkId;
use log::{info, warn};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use std::collections::{hash_map::Entry, HashMap, HashSet};
use std::fmt::{Display, Formatter};
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
    pub txs_verif: HashMap<BETxid, SPVVerifyTxResult>,

    /// cached fee_estimates
    pub fee_estimates: Vec<FeeEstimate>,

    /// height and hash of tip of the blockchain
    #[deprecated(note = "Deprecated, use `tip_` instead")]
    pub tip: (u32, BEBlockHash),

    /// height and block header of tip of the blockchain
    ///
    /// Note: Option and trailing underscore are for backward compatibility reasons.
    pub tip_: Option<(u32, BEBlockHeader)>,

    #[deprecated(note = "Not used anymore since gdk-registry lib is used")]
    /// registry assets last modified, used when making the http request
    pub assets_last_modified: String,

    #[deprecated(note = "Not used anymore since gdk-registry lib is used")]
    /// registry icons last modified, used when making the http request
    pub icons_last_modified: String,

    /// the result of the last spv cross-validation execution
    pub cross_validation_result: Option<CrossValidationResult>,

    /// whether BIP 44 account recovery was already run for this wallet
    pub accounts_recovered: bool, // TODO deprecated, remove when cache breaking change should happen

    /// The master blinding key, available only in liquid
    pub master_blinding: Option<MasterBlindingKey>,
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
    pub unblinded: HashMap<elements::OutPoint, TxOutSecrets>,

    /// max used indexes for external derivation /0/* and internal derivation /1/* (change)
    pub indexes: Indexes,

    /// the xpub of the account
    ///
    /// This field is optional to avoid breaking the cache,
    /// but it should always be set.
    pub xpub: Option<ExtendedPubKey>,

    /// Whether the subaccount was discovered through bip44 subaccount discovery
    ///
    /// If an account is discovered through bip44, then it has at least one transaction. This is
    /// used to establish if an account has some transactions without waiting for the syncer to
    /// download transactions.
    /// If None, the account was created before the addition of this field.
    pub bip44_discovered: Option<bool>,
}

/// RawStore contains data that are not extractable from xpub+blockchain
/// like wallet settings and memos
#[derive(Default, Serialize, Deserialize)]
pub struct RawStore {
    /// wallet settings
    settings: Option<Settings>,

    /// transaction memos (account_num -> txid -> memo)
    memos: HashMap<bitcoin::Txid, String>,

    // additional fields should always be appended at the end as an `Option` to retain db backwards compatibility
    /// account settings
    accounts_settings: Option<HashMap<u32, AccountSettings>>,
}

pub struct StoreMeta {
    pub cache: RawCache,
    pub store: RawStore,
    id: NetworkId,
    path: PathBuf,
    cipher: Aes256GcmSiv,
    last: HashMap<Kind, sha256::Hash>,
    to_remove: bool,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Cache,
    Store,
}

impl Display for Kind {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Kind::Store => write!(f, "store"),
            Kind::Cache => write!(f, "cache"),
        }
    }
}

impl Drop for StoreMeta {
    fn drop(&mut self) {
        if self.to_remove && self.path.exists() {
            self.remove_file(Kind::Store);
            self.remove_file(Kind::Cache);
            std::fs::remove_dir(&self.path).unwrap();
        } else {
            self.flush().unwrap();
        }
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
    fn new<P: AsRef<Path>>(path: P, cipher: &Aes256GcmSiv) -> Self {
        Self::try_new(path, cipher).unwrap_or_else(|e| {
            warn!("Initialize cache as default {:?}", e);
            Default::default()
        })
    }

    fn try_new<P: AsRef<Path>>(path: P, cipher: &Aes256GcmSiv) -> Result<Self, Error> {
        let decrypted = load_decrypt(Kind::Cache, path, cipher)?;
        let store = serde_cbor::from_slice(&decrypted)?;
        Ok(store)
    }

    // The following 3 functions are needed to handle the missing `tip_`.
    // This should be happening at most once when upgrading the cache.
    #[allow(deprecated)]
    pub fn tip_height(&self) -> u32 {
        match &self.tip_ {
            None => self.tip.0,
            Some((height, _)) => *height,
        }
    }

    #[allow(deprecated)]
    pub fn tip_block_hash(&self) -> BEBlockHash {
        match &self.tip_ {
            None => self.tip.1,
            Some((_, header)) => header.block_hash(),
        }
    }

    pub fn tip_prev_block_hash(&self) -> BEBlockHash {
        match &self.tip_ {
            None => BEBlockHash::default(),
            Some((_, header)) => header.prev_block_hash(),
        }
    }
}

impl RawStore {
    /// create a new RawStore, try to load data from a file or a fallback file
    /// errors such as corrupted file or model change in the db, result in a empty store that will be repopulated
    fn new<P: AsRef<Path>>(path: P, cipher: &Aes256GcmSiv) -> Self {
        Self::try_new(path, cipher).unwrap_or_else(|e| {
            warn!("Initialize store as default {:?}", e);
            Default::default()
        })
    }

    fn try_new<P: AsRef<Path>>(path: P, cipher: &Aes256GcmSiv) -> Result<Self, Error> {
        let decrypted = load_decrypt(Kind::Store, path, cipher)?;
        let store = serde_cbor::from_slice(&decrypted)?;
        Ok(store)
    }
}

fn load_decrypt<P: AsRef<Path>>(
    kind: Kind,
    path: P,
    cipher: &Aes256GcmSiv,
) -> Result<Vec<u8>, Error> {
    let now = Instant::now();
    let mut store_path = PathBuf::from(path.as_ref());
    store_path.push(kind.to_string());
    if !store_path.exists() {
        return Err(Error::Generic(format!("{:?} do not exist", store_path)));
    }
    let mut file = File::open(&store_path)?;
    let mut nonce_bytes = [0u8; 12];
    file.read_exact(&mut nonce_bytes)?;
    let nonce = Nonce::from_slice(&nonce_bytes);
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
    let key = Key::from_slice(&key_bytes);
    Aes256GcmSiv::new(&key)
}

impl StoreMeta {
    pub fn new<P: AsRef<Path>>(
        path: P,
        xpub: &ExtendedPubKey,
        id: NetworkId,
    ) -> Result<StoreMeta, Error> {
        let cipher = get_cipher(xpub);
        let cache = RawCache::new(path.as_ref(), &cipher);

        let mut store = RawStore::new(path.as_ref(), &cipher);
        let path = path.as_ref().to_path_buf();

        std::fs::create_dir_all(&path)?; // does nothing if path exists

        store.accounts_settings.get_or_insert_with(|| Default::default());

        let store = StoreMeta {
            cache,
            store,
            id,
            cipher,
            path,
            last: HashMap::new(),
            to_remove: false,
        };
        Ok(store)
    }

    pub fn to_remove(&mut self) {
        self.to_remove = true;
    }

    fn file_path(&mut self, kind: Kind) -> PathBuf {
        let mut path = self.path.clone();
        path.push(kind.to_string());
        path
    }

    fn remove_file(&mut self, kind: Kind) {
        let path = self.file_path(kind);
        if path.exists() {
            std::fs::remove_file(&path).unwrap();
        }
    }

    fn flush_serializable(&mut self, kind: Kind) -> Result<(), Error> {
        let now = Instant::now();
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut plaintext = match kind {
            Kind::Store => serde_cbor::to_vec(&self.store),
            Kind::Cache => serde_cbor::to_vec(&self.cache),
        }?;

        let hash = sha256::Hash::hash(&plaintext);
        if let Some(last_hash) = self.last.get(&kind) {
            if last_hash == &hash {
                info!("latest serialization hash matches, no need to flush");
                return Ok(());
            }
        }
        self.last.insert(kind, hash);

        self.cipher.encrypt_in_place(nonce, b"", &mut plaintext)?;
        let ciphertext = plaintext;

        let store_path = self.file_path(kind);
        //TODO should avoid rewriting if not changed? it involves saving plaintext (or struct hash)
        // in the front of the file
        let mut file = File::create(&store_path)?;
        file.write_all(&nonce_bytes)?;
        file.write_all(&ciphertext)?;
        info!(
            "flushing {} bytes on {:?} took {}ms",
            ciphertext.len() + 16,
            &store_path,
            now.elapsed().as_millis()
        );
        Ok(())
    }

    fn flush_store(&mut self) -> Result<(), Error> {
        self.flush_serializable(Kind::Store)?;
        Ok(())
    }

    fn flush_cache(&mut self) -> Result<(), Error> {
        self.flush_serializable(Kind::Cache)?;
        Ok(())
    }

    pub fn flush(&mut self) -> Result<(), Error> {
        self.flush_store()?;
        self.flush_cache()?;
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

    /// Make an account entry
    /// Note that we need to insert an account entry both in the store and in the cache.
    pub fn make_account(
        &mut self,
        account_num: u32,
        account_xpub: ExtendedPubKey,
        discovered: bool,
    ) -> Result<(), Error> {
        self.store
            .accounts_settings
            .get_or_insert_with(|| Default::default())
            .entry(account_num)
            .or_default();
        match self.cache.accounts.entry(account_num) {
            Entry::Vacant(entry) => {
                let mut account = RawAccountCache::default();
                account.xpub = Some(account_xpub);
                account.bip44_discovered = Some(discovered);
                entry.insert(account);
            }
            Entry::Occupied(mut entry) => {
                match entry.get().xpub {
                    None => {
                        // This is a cache upgrade from a version that did not persist the xpub
                        entry.get_mut().xpub = Some(account_xpub);
                    }
                    Some(xpub) => xpubs_equivalent(&xpub, &account_xpub)?,
                }
            }
        }
        Ok(())
    }

    pub fn account_nums(&self) -> Vec<u32> {
        // Read the account nums from both the cache and store for backward compatibility.
        // Between version 0.0.48 and 0.0.49 some changes were done to split account
        // discovery from login, which is a necessary step for adding HWW support.
        // Among these changes we changed the way to get the accounts created, instead of
        // reading from the cache we read from the store.
        // However when upgrading from e.g. 0.0.48 to 0.0.49 the accounts in the store might
        // not have been populated, so we have to look at the cache as well.
        // It's worth noting that if a GDK upgrade also requires a cache reconstruction,
        // then it will miss the accounts from the cache.
        let store_account_nums = match &self.store.accounts_settings {
            None => HashSet::new(),
            Some(accounts) => accounts.keys().copied().collect(),
        };
        let cache_account_nums = self.cache.accounts.keys().copied().collect();

        let mut account_nums: Vec<_> =
            store_account_nums.union(&cache_account_nums).copied().collect();
        account_nums.sort_unstable();
        account_nums
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

    pub fn spv_verification_status(&self, account_num: u32, txid: &BETxid) -> SPVVerifyTxResult {
        let acc_store = match self.account_cache(account_num) {
            Ok(store) => store,
            Err(_) => return SPVVerifyTxResult::NotVerified,
        };

        if let Some(height) = acc_store.heights.get(txid).unwrap_or(&None) {
            match &self.cache.cross_validation_result {
                Some(CrossValidationResult::Invalid(inv)) if *height > inv.common_ancestor => {
                    // Report an SPV validation failure if the transaction was confirmed after the forking point
                    SPVVerifyTxResult::NotLongest
                }
                _ => {
                    self.cache.txs_verif.get(txid).cloned().unwrap_or(SPVVerifyTxResult::InProgress)
                }
            }
        } else {
            SPVVerifyTxResult::Unconfirmed
        }
    }

    pub fn export_cache(&mut self) -> Result<RawCache, Error> {
        self.flush_cache()?;
        RawCache::try_new(&self.path, &self.cipher)
    }

    pub fn get_tx_entry(&self, txid: &BETxid) -> Result<&BETransactionEntry, Error> {
        for acc_store in self.cache.accounts.values() {
            if let Some(tx_entry) = acc_store.all_txs.get(&txid) {
                return Ok(tx_entry);
            }
        }
        Err(Error::TxNotFound(txid.clone()))
    }
}

impl RawAccountCache {
    pub fn get_bitcoin_tx(&self, txid: &bitcoin::Txid) -> Result<Transaction, Error> {
        match self.all_txs.get(&txid.into_be()).map(|etx| &etx.tx) {
            Some(BETransaction::Bitcoin(tx)) => Ok(tx.clone()),
            _ => Err(Error::TxNotFound(BETxid::Bitcoin(txid.clone()))),
        }
    }

    pub fn get_liquid_tx(&self, txid: &elements::Txid) -> Result<elements::Transaction, Error> {
        match self.all_txs.get(&txid.into_be()).map(|etx| &etx.tx) {
            Some(BETransaction::Elements(tx)) => Ok(tx.clone()),
            _ => Err(Error::TxNotFound(BETxid::Elements(txid.clone()))),
        }
    }

    pub fn get_path(&self, script_pubkey: &BEScript) -> Result<&DerivationPath, Error> {
        self.paths.get(script_pubkey).ok_or_else(|| Error::ScriptPubkeyNotFound)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::util::bip32::ExtendedPubKey;
    use bitcoin::Network;
    use gdk_common::{be::BETxid, NetworkId};
    use std::str::FromStr;
    use tempfile::TempDir;

    #[test]
    fn test_db_roundtrip() {
        let id = NetworkId::Bitcoin(Network::Testnet);
        let mut dir = TempDir::new().unwrap().into_path();
        dir.push(Kind::Store.to_string());
        // abandon ... M/49'/0'/0'
        let xpub = ExtendedPubKey::from_str("tpubD97UxEEcrMpkE8yG3NQveraWveHzTAJx3KwPsUycx9ABfxRjMtiwfm6BtrY5yhF9yF2eyMg2hyDtGDYXx6gVLBox1m2Mq4u8zB2NXFhUZmm").unwrap();
        let txid = BETxid::from_hex(
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            id,
        )
        .unwrap();
        let txid_btc = txid.ref_bitcoin().unwrap();

        {
            let mut store = StoreMeta::new(&dir, &xpub, id).unwrap();
            store.make_account(0, xpub, true).unwrap(); // The xpub here is incorrect, but that's irrelevant for the sake of the test
            store.account_cache_mut(0).unwrap().heights.insert(txid, Some(1));
            store.store.memos.insert(*txid_btc, "memo".to_string());
        }

        let store = StoreMeta::new(&dir, &xpub, id).unwrap();

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
