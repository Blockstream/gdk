use crate::determine_electrum_url;
use crate::error::Error;
use crate::headers::bitcoin::{HeadersChain, HEADERS_FILE_MUTEX};
use crate::headers::liquid::Verifier;
use ::bitcoin::hashes::hex::ToHex;
use ::bitcoin::hashes::{sha256, sha256d, Hash};
use aes_gcm_siv::aead::{Aead, NewAead};
use aes_gcm_siv::{Aes256GcmSiv, Key, Nonce};
use electrum_client::{Client, ElectrumApi, GetMerkleRes};
use gdk_common::be::{BETxid, BETxidConvert};
use gdk_common::model::{
    SPVCommonParams, SPVDownloadHeadersParams, SPVDownloadHeadersResult, SPVVerifyTxParams,
    SPVVerifyTxResult,
};
use gdk_common::NetworkId;
use log::{debug, info, warn};
use rand::{thread_rng, Rng};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

pub mod bitcoin;
pub mod liquid;

pub enum ChainOrVerifier {
    /// used for bitcoin networks
    Chain(HeadersChain),

    /// used for elements networks
    Verifier(Verifier),
}

/// compute the merkle root from the merkle path of a tx in electrum format (note the hash.reverse())
fn compute_merkle_root<T, N>(txid: &T, merkle: GetMerkleRes) -> Result<N, Error>
where
    T: Hash<Inner = [u8; 32]>, // bitcoin::Txid or elements::Txid
    N: Hash<Inner = [u8; 32]>, // bitcoin::TxMerkleNode or elements::TxMerkleNode
{
    let mut pos = merkle.pos;
    let mut current = txid.into_inner();

    for mut hash in merkle.merkle {
        let mut engine = sha256d::Hash::engine();
        hash.reverse();
        if pos % 2 == 0 {
            engine.write(&current)?;
            engine.write(&hash)?;
        } else {
            engine.write(&hash)?;
            engine.write(&current)?;
        }
        current = sha256d::Hash::from_engine(engine).into_inner();
        pos /= 2;
    }

    Ok(N::from_slice(&current)?)
}

trait ParamsMethods {
    fn build_client(&self) -> Result<Client, Error>;
    fn headers_chain(&self) -> Result<HeadersChain, Error>;
    fn verified_cache(&self) -> Result<VerifiedCache, Error>;
    fn bitcoin_network(&self) -> Option<::bitcoin::Network>;
}

impl ParamsMethods for SPVCommonParams {
    fn build_client(&self) -> Result<Client, Error> {
        let url = determine_electrum_url(&self.network)?;
        url.build_client(self.network.proxy.as_deref(), self.timeout)
    }
    fn headers_chain(&self) -> Result<HeadersChain, Error> {
        let network = self.bitcoin_network().expect("headers_chain available only on bitcoin");
        Ok(HeadersChain::new(&self.network.state_dir, network)?)
    }
    fn verified_cache(&self) -> Result<VerifiedCache, Error> {
        Ok(VerifiedCache::new(&self.network.state_dir, self.network.id(), &self.encryption_key))
    }
    fn bitcoin_network(&self) -> Option<::bitcoin::Network> {
        self.network.id().get_bitcoin_network()
    }
}

/// Download headers and persist locally, needed to verify tx with `spv_verify_tx`.
///
/// Used to expose SPV functionality through C interface
pub fn download_headers(
    input: &SPVDownloadHeadersParams,
) -> Result<SPVDownloadHeadersResult, Error> {
    let network =
        input.params.bitcoin_network().expect("download_headers only in bitcoin networks");
    let _lock = HEADERS_FILE_MUTEX
        .get(&network)
        .expect("unreachable because map populate with every enum variants")
        .lock()?;
    debug!("download_headers {:?}", input);
    let client = input.params.build_client()?;
    let mut chain = input.params.headers_chain()?;
    let headers_to_download = input.headers_to_download.unwrap_or(2016);
    let headers = client.block_headers(chain.height() as usize + 1, headers_to_download)?.headers;
    info!("height:{} downloaded_headers:{}", chain.height(), headers.len());
    let mut reorg_happened = false;
    if let Err(Error::InvalidHeaders) = chain.push(headers) {
        warn!(
            "invalid headers, possible reorg, invalidating latest headers and latest verified tx"
        );
        let mut cache = input.params.verified_cache()?;
        chain.remove(input.params.network.max_reorg_blocks.unwrap_or(144))?;
        cache.remove(input.params.network.max_reorg_blocks.unwrap_or(144))?;
        reorg_happened = true;
    }
    info!("downloaded {:?}", chain.height());

    Ok(SPVDownloadHeadersResult {
        height: chain.height(),
        reorg: reorg_happened,
    })
}

/// Verify that the given transaction identified by `input.txid` is included in a headers chain
/// downloaded with `download_headers`.
///
/// A network call to download the inclusion proof will be performed if the tx is not already present
/// in the cache and verified previously.
///
/// used to expose SPV functionality through C interface
pub fn spv_verify_tx(input: &SPVVerifyTxParams) -> Result<SPVVerifyTxResult, Error> {
    let mut _lock;
    if let NetworkId::Bitcoin(network) = input.params.network.id() {
        // Liquid hasn't a shared headers chain file
        _lock = HEADERS_FILE_MUTEX
            .get(&network)
            .expect("unreachable because map populate with every enum variants")
            .lock()?;
    }
    debug!("spv_verify_tx {:?}", input);
    let txid = BETxid::from_hex(&input.txid, input.params.network.id())?;

    let mut cache = input.params.verified_cache()?;
    if cache.contains(&txid, input.height)? {
        info!("verified cache hit for {}", txid);
        return Ok(SPVVerifyTxResult::Verified);
    }

    let client = input.params.build_client()?;

    match input.params.network.id() {
        NetworkId::Bitcoin(_bitcoin_network) => {
            let chain = input.params.headers_chain().expect("match verified we are bitcoin type");

            if input.height <= chain.height() {
                let btxid = txid.ref_bitcoin().unwrap();
                info!("chain height ({}) enough to verify, downloading proof", chain.height());
                let proof = match client.transaction_get_merkle(btxid, input.height as usize) {
                    Ok(proof) => proof,
                    Err(e) => {
                        warn!("failed fetching merkle inclusion proof for {}: {:?}", txid, e);
                        return Ok(SPVVerifyTxResult::NotVerified);
                    }
                };
                if chain.verify_tx_proof(btxid, input.height, proof).is_ok() {
                    cache.write(&txid, input.height)?;
                    Ok(SPVVerifyTxResult::Verified)
                } else {
                    Ok(SPVVerifyTxResult::NotVerified)
                }
            } else {
                info!(
                    "chain height ({}) not enough to verify tx at height {}",
                    chain.height(),
                    input.height
                );

                Ok(SPVVerifyTxResult::InProgress)
            }
        }
        NetworkId::Elements(elements_network) => {
            let proof =
                match client.transaction_get_merkle(&txid.into_bitcoin(), input.height as usize) {
                    Ok(proof) => proof,
                    Err(e) => {
                        warn!("failed fetching merkle inclusion proof for {}: {:?}", txid, e);
                        return Ok(SPVVerifyTxResult::NotVerified);
                    }
                };
            let verifier = Verifier::new(elements_network);
            let header_bytes = client.block_header_raw(input.height as usize)?;
            let header: elements::BlockHeader = elements::encode::deserialize(&header_bytes)?;
            if verifier.verify_tx_proof(txid.ref_elements().unwrap(), proof, &header).is_ok() {
                cache.write(&txid, input.height)?;
                Ok(SPVVerifyTxResult::Verified)
            } else {
                Ok(SPVVerifyTxResult::NotVerified)
            }
        }
    }
}

struct VerifiedCache {
    set: HashSet<(BETxid, u32)>,
    store: Option<Store>,
}

struct Store {
    filepath: PathBuf,
    cipher: Aes256GcmSiv,
}

impl VerifiedCache {
    /// If an `encription_key` is provided try to load a persisted cache of verified tx inside
    /// given `path` in a file name dependent on the given `network`
    fn new<P: AsRef<Path>>(path: P, network: NetworkId, encription_key: &Option<String>) -> Self {
        std::fs::create_dir_all(path.as_ref()).expect("given path should be writeable");
        match encription_key {
            Some(key) => {
                let mut filepath: PathBuf = path.as_ref().into();
                let filename_preimage = format!("{:?}{}", network, key);
                let filename = sha256::Hash::hash(filename_preimage.as_bytes()).as_ref().to_hex();
                let key_bytes = sha256::Hash::hash(key.as_bytes()).into_inner();
                filepath.push(format!("verified_cache_{}", filename));
                let cipher = Aes256GcmSiv::new(Key::from_slice(&key_bytes));
                let set = match VerifiedCache::read_and_decrypt(&mut filepath, &cipher) {
                    Ok(set) => set,
                    Err(_) => HashSet::new(),
                };
                let store = Some(Store {
                    filepath,
                    cipher,
                });
                VerifiedCache {
                    set,
                    store,
                }
            }
            None => VerifiedCache {
                set: HashSet::new(),
                store: None,
            },
        }
    }

    fn read_and_decrypt(
        filepath: &mut PathBuf,
        cipher: &Aes256GcmSiv,
    ) -> Result<HashSet<(BETxid, u32)>, Error> {
        let mut file = File::open(&filepath)?;
        let mut nonce_bytes = [0u8; 12]; // 96 bits
        file.read_exact(&mut nonce_bytes)?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let mut ciphertext = vec![];
        file.read_to_end(&mut ciphertext)?;
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
        Ok(serde_cbor::from_slice(&plaintext)?)
    }

    fn contains(&self, txid: &BETxid, height: u32) -> Result<bool, Error> {
        Ok(self.set.contains(&(txid.clone(), height)))
    }

    fn write(&mut self, txid: &BETxid, height: u32) -> Result<(), Error> {
        self.set.insert((txid.clone(), height));
        self.flush()
    }

    /// remove all verified txid with height greater than given height
    fn remove(&mut self, height: u32) -> Result<(), Error> {
        self.set = self.set.iter().filter(|e| e.1 < height).cloned().collect();
        self.flush()
    }

    fn flush(&mut self) -> Result<(), Error> {
        if let Some(store) = &self.store {
            let mut file = File::create(&store.filepath)?;
            let mut nonce_bytes = [0u8; 12]; // 96 bits
            thread_rng().fill(&mut nonce_bytes);
            let plaintext = serde_cbor::to_vec(&self.set)?;
            let nonce = Nonce::from_slice(&nonce_bytes);
            let ciphertext = store.cipher.encrypt(nonce, plaintext.as_ref())?;
            file.write(&nonce)?;
            file.write(&ciphertext)?;
        }

        Ok(())
    }
}
