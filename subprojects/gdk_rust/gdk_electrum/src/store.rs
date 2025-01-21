use crate::account::xpubs_equivalent;
use crate::spv::CrossValidationResult;
use crate::{Error, ScriptStatuses};
use gdk_common::aes::Aes256GcmSiv;
use gdk_common::be::BETxidConvert;
use gdk_common::be::{
    BEBlockHash, BEBlockHeader, BEScript, BETransactionEntry, BETransactions, BETxid,
};
use gdk_common::bitcoin::bip32::{DerivationPath, Xpub};
use gdk_common::bitcoin::hashes::{sha256, Hash};
use gdk_common::bitcoin::Txid;
use gdk_common::elements;
use gdk_common::elements::TxOutSecrets;
use gdk_common::log::{info, log, Level};
use gdk_common::model::{AccountSettings, FeeEstimate, SPVVerifyTxResult, Settings};
use gdk_common::serde_cbor;
use gdk_common::store::{Decryptable, Encryptable};
use gdk_common::util::MasterBlindingKey;
use gdk_common::NetworkId;
use serde::{Deserialize, Serialize};
use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::fmt::{Display, Formatter};
use std::fs::File;
use std::io::Write;
use std::ops::{Index, IndexMut};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

pub type Store = Arc<Mutex<StoreMeta>>;

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

#[derive(Serialize, Deserialize)]
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
    #[serde(rename = "indexes")]
    pub last_used: Indexes,

    /// the xpub of the account
    pub xpub: Xpub,

    /// Whether the subaccount was discovered through bip44 subaccount discovery
    ///
    /// If an account is discovered through bip44, then it has at least one transaction. This is
    /// used to establish if an account has some transactions without waiting for the syncer to
    /// download transactions.
    pub bip44_discovered: bool,

    /// Maps scripts to their current script status.
    ///
    /// NOTE: is Option to keep cache backwards-compatibility, remove if breaking cache
    pub script_statuses: Option<ScriptStatuses>,

    /// Counters of number of scripts returned to the caller
    ///
    /// These counters go up to gap_limit, then they start again from 0, looping in this set. When
    /// last_used is updated, this counters are decremented by the number of new addresses seen.
    ///
    /// NOTE: this is Option to keep cache backwards-compatibility, remove if breaking cache
    pub count_given: Option<Indexes>,
}

#[derive(Default, Clone, Serialize, Deserialize)]
pub struct ClientBlob {
    pub blob: String,
    pub client_id: String,
    pub hmac: String,
    pub requires_merge: bool,
}

/// RawStore contains data that are not extractable from xpub+blockchain
/// like wallet settings and memos
#[derive(Default, Serialize, Deserialize)]
pub struct RawStore {
    /// wallet settings
    settings: Option<Settings>,

    /// transaction memos (account_num -> txid -> memo)
    pub memos: HashMap<Txid, String>,

    // additional fields should always be appended at the end as an `Option` to retain db backwards compatibility
    /// account settings
    accounts_settings: Option<HashMap<u32, AccountSettings>>,

    pub client_blob: Option<ClientBlob>,
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

impl Index<bool> for Indexes {
    type Output = u32;

    fn index(&self, i: bool) -> &Self::Output {
        if i {
            &self.internal
        } else {
            &self.external
        }
    }
}

impl IndexMut<bool> for Indexes {
    fn index_mut(&mut self, i: bool) -> &mut Self::Output {
        if i {
            &mut self.internal
        } else {
            &mut self.external
        }
    }
}

impl RawCache {
    /// create a new RawCache, try to load data from a file or a fallback file
    /// errors such as corrupted file or model change in the db, result in a empty store that will be repopulated
    fn new<P: AsRef<Path>>(path: P, cipher: &Aes256GcmSiv) -> Self {
        Self::try_new(path.as_ref(), cipher).unwrap_or_else(|e| {
            log_initialization(e, path);
            Default::default()
        })
    }

    fn try_new<P: AsRef<Path>>(path: P, cipher: &Aes256GcmSiv) -> Result<Self, Error> {
        let decrypted = load_decrypt(Kind::Cache, path, cipher)?;
        let store = serde_cbor::from_reader(&decrypted[..])?;
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
        Self::try_new(path.as_ref(), cipher).unwrap_or_else(|e| {
            log_initialization(e, path);
            Default::default()
        })
    }

    fn try_new<P: AsRef<Path>>(path: P, cipher: &Aes256GcmSiv) -> Result<Self, Error> {
        let decrypted = load_decrypt(Kind::Store, path, cipher)?;
        let store = serde_cbor::from_reader(&decrypted[..])?;
        Ok(store)
    }
}

fn log_initialization<P: AsRef<Path>>(e: Error, path: P) {
    let level = match e {
        Error::FileNotExist(_) => Level::Info,
        _ => Level::Warn,
    };
    log!(level, "Initialize {:?} as default {:?}", path.as_ref(), e);
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
        return Err(Error::FileNotExist(store_path));
    }
    let mut file = File::open(&store_path)?;

    let plaintext = file.decrypt(cipher)?;

    info!("loading {:?} took {}ms", &store_path, now.elapsed().as_millis());
    Ok(plaintext)
}

impl StoreMeta {
    pub fn new<P: AsRef<Path>>(
        path: P,
        cipher: &Aes256GcmSiv,
        id: NetworkId,
    ) -> Result<StoreMeta, Error> {
        let cache = RawCache::new(path.as_ref(), &cipher);

        let mut store = RawStore::new(path.as_ref(), &cipher);
        let path = path.as_ref().to_path_buf();

        std::fs::create_dir_all(&path)?; // does nothing if path exists

        store.accounts_settings.get_or_insert_with(|| Default::default());

        let store = StoreMeta {
            cache,
            store,
            id,
            cipher: cipher.clone(),
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

        let plaintext = match kind {
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

        let (nonce_bytes, ciphertext) = plaintext.encrypt(&self.cipher)?;

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
        account_xpub: Xpub,
        discovered: bool,
    ) -> Result<(), Error> {
        self.store
            .accounts_settings
            .get_or_insert_with(|| Default::default())
            .entry(account_num)
            .or_default();

        match self.cache.accounts.entry(account_num) {
            Entry::Vacant(entry) => {
                let account = RawAccountCache::new(account_xpub, discovered);
                entry.insert(account);
            }
            Entry::Occupied(entry) => {
                // Should we `.unwrap()` instead?
                xpubs_equivalent(&entry.get().xpub, &account_xpub)?
            }
        }

        Ok(())
    }

    pub fn account_nums(&self) -> Vec<u32> {
        let store_account_nums = match &self.store.accounts_settings {
            None => HashSet::new(),
            Some(accounts) => accounts.keys().copied().collect(),
        };
        let mut account_nums = store_account_nums.into_iter().collect::<Vec<_>>();
        account_nums.sort_unstable();
        account_nums
    }

    pub fn min_fee_rate(&self) -> u64 {
        self.cache.fee_estimates.get(0).map_or_else(|| self.id.default_min_fee_rate(), |f| f.0)
    }

    pub fn fee_estimates(&self) -> Vec<FeeEstimate> {
        if self.cache.fee_estimates.is_empty() {
            let min_fee = self.id.default_min_fee_rate();
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

    pub fn set_account_settings(
        &mut self,
        account_num: u32,
        settings: AccountSettings,
    ) -> Result<(), Error> {
        self.store.accounts_settings.as_mut().unwrap().insert(account_num, settings);
        self.flush_store()?;
        Ok(())
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

    pub fn get_tx_entry(&self, txid: &BETxid) -> Result<&BETransactionEntry, Error> {
        for acc_store in self.cache.accounts.values() {
            if let Some(tx_entry) = acc_store.all_txs.get(&txid) {
                return Ok(tx_entry);
            }
        }
        Err(Error::TxNotFound(txid.clone()))
    }

    pub fn update_tip(&mut self, new_height: u32, new_header: BEBlockHeader) -> Result<(), Error> {
        self.cache.tip_ = Some((new_height, new_header));
        self.flush_cache()?;
        Ok(())
    }
}

impl RawAccountCache {
    pub fn new(xpub: Xpub, bip44_discovered: bool) -> Self {
        RawAccountCache {
            all_txs: Default::default(),
            paths: Default::default(),
            scripts: Default::default(),
            heights: Default::default(),
            script_statuses: Default::default(),
            unblinded: Default::default(),
            last_used: Default::default(),
            count_given: Some(Default::default()),
            xpub,
            bip44_discovered,
        }
    }
    pub fn get_path(&self, script_pubkey: &BEScript) -> Result<&DerivationPath, Error> {
        self.paths.get(script_pubkey).ok_or_else(|| Error::ScriptPubkeyNotFound)
    }

    pub fn get_both_last_used(&self) -> Indexes {
        self.last_used.clone()
    }

    pub fn set_both_last_used(&mut self, last_used: Indexes) {
        if self.last_used != last_used {
            // If last_used changed, reset count_given.
            // Do not repeat given addresses until the gap_limit is hit.
            let count_given = self.count_given.clone().unwrap_or_default();
            let internal =
                (self.last_used.internal + count_given.internal).saturating_sub(last_used.internal);
            let external =
                (self.last_used.external + count_given.external).saturating_sub(last_used.external);
            self.count_given = Some(Indexes {
                internal,
                external,
            });
        }
        self.last_used = last_used;
    }

    // TODO: once we can remove the Option from count_given, below things can be simplified.
    fn get_count_given(&self, is_internal: bool) -> u32 {
        self.count_given.as_ref().map_or(0, |c| c[is_internal])
    }

    /// Get the next address pointer
    pub fn get_next_pointer(&self, is_internal: bool) -> u32 {
        // last_used:   the pointer of the last script involved in a transaction
        // count_given: the number of pointer given (ranges from 0 to gap_limit-1 included)
        // +1:          we want the next one
        self.last_used[is_internal] + self.get_count_given(is_internal) + 1
    }

    /// Increment next pointer
    pub fn increment_pointer(&mut self, is_internal: bool, ignore_gap_limit: bool, gap_limit: u32) {
        if is_internal {
            let count_given = self.count_given.clone().unwrap_or_default();
            let mut internal = count_given.internal + 1;
            if !ignore_gap_limit {
                internal %= gap_limit;
            }
            self.count_given = Some(Indexes {
                internal,
                external: count_given.external,
            });
        } else {
            let count_given = self.count_given.clone().unwrap_or_default();
            let mut external = count_given.external + 1;
            if !ignore_gap_limit {
                external %= gap_limit;
            }
            self.count_given = Some(Indexes {
                internal: count_given.internal,
                external,
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use gdk_common::bitcoin::bip32::Xpub;
    use gdk_common::bitcoin::{Network, Txid};
    use gdk_common::store::ToCipher;
    use gdk_common::{be::BETxid, NetworkId};
    use std::str::FromStr;
    use tempfile::TempDir;

    #[test]
    fn test_db_roundtrip() {
        let id = NetworkId::Bitcoin(Network::Testnet);
        let mut dir = TempDir::new().unwrap().into_path();
        dir.push(Kind::Store.to_string());
        // abandon ... M/49'/0'/0'
        let xpub = Xpub::from_str("tpubD97UxEEcrMpkE8yG3NQveraWveHzTAJx3KwPsUycx9ABfxRjMtiwfm6BtrY5yhF9yF2eyMg2hyDtGDYXx6gVLBox1m2Mq4u8zB2NXFhUZmm").unwrap();
        let txid = BETxid::from_hex(
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            id,
        )
        .unwrap();
        let txid_btc = txid.ref_bitcoin().unwrap();

        let cipher = xpub.to_cipher().unwrap();
        {
            let mut store = StoreMeta::new(&dir, &cipher, id).unwrap();
            store.make_account(0, xpub, true).unwrap(); // The xpub here is incorrect, but that's irrelevant for the sake of the test
            store.account_cache_mut(0).unwrap().heights.insert(txid, Some(1));
            store.store.memos.insert(*txid_btc, "memo".to_string());
        }

        let store = StoreMeta::new(&dir, &cipher, id).unwrap();

        assert_eq!(store.account_cache(0).unwrap().heights.get(&txid), Some(&Some(1)));
        assert_eq!(store.store.memos.get(txid_btc), Some(&"memo".to_string()));
    }

    #[test]
    fn test_db_load_static() {
        let id = NetworkId::Bitcoin(Network::Testnet);
        // abandon ... M/49'/0'/0'
        let xpub = Xpub::from_str("tpubD97UxEEcrMpkE8yG3NQveraWveHzTAJx3KwPsUycx9ABfxRjMtiwfm6BtrY5yhF9yF2eyMg2hyDtGDYXx6gVLBox1m2Mq4u8zB2NXFhUZmm").unwrap();
        let txid = BETxid::from_hex(
            "f4184fc596403b9d638783cf57adfe4c75c605f6356fbc91338530e9831e9e16",
            id,
        )
        .unwrap();
        let txid_btc = txid.ref_bitcoin().unwrap();

        let temp_dir = TempDir::new().unwrap().into_path();
        let data_dir: PathBuf = "test_data/store".into();
        for el in ["store", "cache"] {
            let mut curr_temp = temp_dir.clone();
            let mut curr_data = data_dir.clone();
            curr_temp.push(el);
            curr_data.push(el);
            std::fs::copy(curr_data, curr_temp).unwrap();
        }

        let cipher = xpub.to_cipher().unwrap();
        let store = StoreMeta::new(temp_dir, &cipher, id).unwrap();

        assert_eq!(store.account_cache(0).unwrap().heights.get(&txid), Some(&Some(1)));
        assert_eq!(store.store.memos.get(txid_btc), Some(&"memo".to_string()));
    }

    #[test]
    fn test_db_upgrade() {
        #[derive(Serialize, Deserialize)]
        struct RawStoreV0 {
            settings: Option<Settings>,
            memos: HashMap<Txid, String>,
        }

        type RawStoreV1 = RawStore;

        let store_v0 = RawStoreV0 {
            settings: Some(Settings::default()),
            memos: {
                let mut memos = HashMap::new();
                memos.insert(Txid::all_zeros(), "Foobar".into());
                memos
            },
        };

        let blob = serde_cbor::to_vec(&store_v0).unwrap();
        let store_v1: RawStoreV1 = serde_cbor::from_reader(&blob[..]).unwrap();

        assert_eq!(store_v0.settings, store_v1.settings);
        assert_eq!(store_v0.memos, store_v1.memos);

        let blob = serde_cbor::to_vec(&store_v1).unwrap();
        let store_v0: RawStoreV0 = serde_cbor::from_reader(&blob[..]).unwrap();
        assert_eq!(store_v0.settings, store_v1.settings);
        assert_eq!(store_v0.memos, store_v1.memos);
    }

    #[test]
    fn test_cache_upgrade() {
        #[derive(Serialize, Deserialize)]
        pub struct RawAccountCacheV0 {
            pub all_txs: BETransactions,
            pub paths: HashMap<BEScript, DerivationPath>,
            pub scripts: HashMap<DerivationPath, BEScript>,
            pub heights: HashMap<BETxid, Option<u32>>,
            pub unblinded: HashMap<elements::OutPoint, TxOutSecrets>,
            pub indexes: Indexes,
            pub xpub: Xpub,
            pub bip44_discovered: bool,
        }
        type RawAccountCacheV1 = RawAccountCache;

        let cache_v0 = RawAccountCacheV0 {
            all_txs: Default::default(),
            paths: Default::default(),
            scripts: Default::default(),
            heights: Default::default(),
            unblinded: Default::default(),
            indexes: Default::default(),
            xpub: Xpub::from_str("xpub67tVq9TC3jGc93MFouaJsne9ysbJTgd2z283AhzbJnJBYLaSgd7eCneb917z4mCmt9NT1jrex9JwZnxSqMo683zUWgMvBXGFcep95TuSPo6").unwrap(),
            bip44_discovered: Default::default(),
        };

        let blob = serde_cbor::to_vec(&cache_v0).unwrap();
        let cache_v1: RawAccountCacheV1 = serde_cbor::from_reader(&blob[..])
            .expect("cache compatibility broke, not critical but think twice");

        assert_eq!(cache_v0.xpub, cache_v1.xpub);
    }
}
