use crate::Error;
use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use bitcoin::hashes::core::ops::Deref;
use bitcoin::hashes::sha256;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::bip32::{ChildNumber, ExtendedPubKey};
use bitcoin::{Address, Script, Transaction, Txid};
use elements::{AddressParams, OutPoint};
use gdk_common::be::{BEBlockHeader, BEOutPoint, BETransaction, BETransactions, Unblinded};
use gdk_common::be::{ScriptBatch, TwoLayerPath};
use gdk_common::error::fn_err;
use gdk_common::model::Settings;
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
use std::ops::DerefMut;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Instant;

pub const BATCH_SIZE: u32 = 20;

pub type Store = Arc<RwLock<StoreMeta>>;

/// Store is a persisted and encrypted cache of wallet data, contains stuff like wallet transactions
/// It is fully reconstructable from xpub and data from electrum server (plus master blinding for elements)
#[derive(Default, Serialize, Deserialize)]
pub struct RawStore {
    /// contains all my tx and all prevouts
    pub all_txs: BETransactions,

    /// contains all my script up to an empty batch of BATCHSIZE
    pub paths: HashMap<Script, TwoLayerPath>,

    /// inverse of `paths`
    pub scripts: HashMap<TwoLayerPath, Script>, // TODO use DerivationPath once Hash gets merged

    /// contains only my wallet txs with the relative heights (None if unconfirmed)
    pub heights: HashMap<Txid, Option<u32>>,

    /// contains headers at the height of my txs (used to show tx timestamps)
    pub headers: HashMap<u32, BEBlockHeader>,

    /// unblinded values (only for liquid)
    pub unblinded: HashMap<OutPoint, Unblinded>,

    /// if key is present, tx has been verified through SPV
    pub txs_verif: HashSet<Txid>,

    /// wallet settings
    pub settings: Option<Settings>,

    /// height of the blockchain
    pub tip: u32,

    /// max used indexes for external derivation /0/* and internal derivation /1/* (change)
    pub indexes: Indexes,
}

pub struct StoreMeta {
    store: RawStore,
    master_blinding: Option<MasterBlindingKey>,
    secp: Secp256k1<All>,
    id: NetworkId,
    path: PathBuf,
    cipher: Aes256GcmSiv,
    first_deriv: [ExtendedPubKey; 2],
}

impl Deref for StoreMeta {
    type Target = RawStore;

    fn deref(&self) -> &Self::Target {
        &self.store
    }
}
impl DerefMut for StoreMeta {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.store
    }
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

impl RawStore {
    /// create a new Store, loading data from a file if any and if there is no error in reading
    /// errors such as corrupted file or model change in the db, result in a empty store that will be repopulated
    fn new<P: AsRef<Path>>(path: P, cipher: &Aes256GcmSiv) -> Self {
        Self::try_new(path, cipher).unwrap_or_else(|e| {
            warn!("Initialize store as default {:?}", e);
            Default::default()
        })
    }

    fn try_new<P: AsRef<Path>>(path: P, cipher: &Aes256GcmSiv) -> Result<Self, Error> {
        let now = Instant::now();
        let mut store_path = PathBuf::from(path.as_ref());
        store_path.push("store");
        if !store_path.exists() {
            return Err(Error::Generic("file do not exist".into()));
        }
        let mut file = File::open(store_path)?;
        let mut nonce_bytes = [0u8; 12];
        file.read_exact(&mut nonce_bytes)?;
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let mut contents = vec![];
        file.read_to_end(&mut contents)?;
        let decrypted = cipher.decrypt(nonce, contents.as_ref())?;
        let store = serde_cbor::from_slice(&decrypted)?;
        info!("loading store took {}ms", now.elapsed().as_millis());
        Ok(store)
    }
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
            store,
            master_blinding,
            id,
            cipher,
            secp,
            path,
            first_deriv,
        })
    }

    pub fn flush(&self) -> Result<(), Error> {
        let now = Instant::now();
        let mut nonce_bytes = [0u8; 12];
        thread_rng().fill(&mut nonce_bytes);
        let nonce = GenericArray::from_slice(&nonce_bytes);
        //TODO is possible to avoid allocs with writer?
        let plaintext = serde_cbor::to_vec(&self.store)?;
        let ciphertext = self.cipher.encrypt(nonce, plaintext.as_ref())?;
        let mut store_path = self.path.clone();
        store_path.push("store");
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

    fn read(&self, name: &str) -> Result<Option<Value>, Error> {
        let mut path = self.path.clone();
        path.push(name);
        if path.exists() {
            let file = File::open(path)?;
            Ok(Some(serde_json::from_reader(file)?))
        } else {
            Ok(None)
        }
    }

    fn write(&self, name: &str, value: &Value) -> Result<(), Error> {
        let mut path = self.path.clone();
        path.push(name);
        let mut file = File::create(path)?;
        file.write(&serde_json::to_vec(value)?)?;
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
            let path = TwoLayerPath::new(int_or_ext, j);
            let opt_script = self.store.scripts.get(&path);
            let script = match opt_script {
                Some(script) => script.clone(),
                None => {
                    result.cached = false;
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

                    script
                }
            };
            result.value.push((path, script));
        }
        Ok(result)
    }

    pub fn get_bitcoin_tx(&self, txid: &Txid) -> Result<Transaction, Error> {
        match self.all_txs.get(txid) {
            Some(BETransaction::Bitcoin(tx)) => Ok(tx.clone()),
            _ => Err(Error::Generic("expected bitcoin tx".to_string())),
        }
    }

    pub fn get_liquid_tx(&self, txid: &Txid) -> Result<elements::Transaction, Error> {
        match self.all_txs.get(txid) {
            Some(BETransaction::Elements(tx)) => Ok(tx.clone()),
            _ => Err(Error::Generic("expected liquid tx".to_string())),
        }
    }

    pub fn spent(&self) -> Result<HashSet<BEOutPoint>, Error> {
        let mut result = HashSet::new();
        for tx in self.store.all_txs.values() {
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
        let mut store = StoreMeta::new(&dir, xpub, None, id);
        store.heights.insert(txid, Some(1));
        drop(store);

        let store = StoreMeta::new(&dir, xpub, None, id);
        assert_eq!(store.heights.get(&txid), Some(Some(&1)));
    }
}
