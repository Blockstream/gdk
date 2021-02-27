use crate::determine_electrum_url_from_net;
use crate::error::Error;
use crate::headers::bitcoin::HeadersChain;
use crate::headers::liquid::Verifier;
use ::bitcoin::hashes::{sha256, sha256d, Hash};
use aes_gcm_siv::aead::{generic_array::GenericArray, Aead, NewAead};
use aes_gcm_siv::Aes256GcmSiv;
use electrum_client::{ElectrumApi, GetMerkleRes};
use gdk_common::be::{BETxid, BETxidConvert};
use gdk_common::model::{SPVVerifyResult, SPVVerifyTx};
use gdk_common::NetworkId;
use log::{info, warn};
use rand::{thread_rng, Rng};
use std::collections::HashSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::Mutex;

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

lazy_static! {
    static ref SPV_MUTEX: Mutex<()> = Mutex::new(());
}

/// used to expose SPV functionality through C interface
pub fn spv_verify_tx(input: &SPVVerifyTx) -> Result<SPVVerifyResult, Error> {
    let _ = SPV_MUTEX.lock().unwrap();

    info!("spv_verify_tx {:?}", input);
    let txid = BETxid::from_hex(&input.txid, input.network.id())?;

    let mut cache: VerifiedCache =
        VerifiedCache::new(&input.path, input.network.id(), &input.encryption_key)?;
    if cache.contains(&txid)? {
        info!("verified cache hit for {}", txid);
        return Ok(SPVVerifyResult::Verified);
    }

    let url = determine_electrum_url_from_net(&input.network)?;
    let client = url.build_client()?;

    match input.network.id() {
        NetworkId::Bitcoin(bitcoin_network) => {
            let mut path: PathBuf = (&input.path).into();
            path.push(format!("headers_chain_{}", bitcoin_network));
            let mut chain = HeadersChain::new(path, bitcoin_network)?;

            if input.height <= chain.height() {
                let btxid = txid.ref_bitcoin().unwrap();
                info!("chain height ({}) enough to verify, downloading proof", chain.height());
                let proof = match client.transaction_get_merkle(btxid, input.height as usize) {
                    Ok(proof) => proof,
                    Err(e) => {
                        warn!("failed fetching merkle inclusion proof for {}: {:?}", txid, e);
                        return Ok(SPVVerifyResult::NotVerified);
                    }
                };
                if chain.verify_tx_proof(btxid, input.height, proof).is_ok() {
                    cache.write(&txid)?;
                    Ok(SPVVerifyResult::Verified)
                } else {
                    Ok(SPVVerifyResult::NotVerified)
                }
            } else {
                info!(
                    "chain height ({}) not enough to verify, downloading 2016 headers",
                    chain.height()
                );
                let headers_to_download = input.headers_to_download.unwrap_or(2016).min(2016);
                let headers =
                    client.block_headers(chain.height() as usize + 1, headers_to_download)?.headers;
                if let Err(Error::InvalidHeaders) = chain.push(headers) {
                    // handle reorgs
                    chain.remove(144)?;
                    cache.clear()?;
                    // XXX clear affected blocks/txs more surgically?
                }
                Ok(SPVVerifyResult::InProgress)
            }
        }
        NetworkId::Elements(elements_network) => {
            let proof =
                match client.transaction_get_merkle(&txid.into_bitcoin(), input.height as usize) {
                    Ok(proof) => proof,
                    Err(e) => {
                        warn!("failed fetching merkle inclusion proof for {}: {:?}", txid, e);
                        return Ok(SPVVerifyResult::NotVerified);
                    }
                };
            let verifier = Verifier::new(elements_network);
            let header_bytes = client.block_header_raw(input.height as usize)?;
            let header: elements::BlockHeader = elements::encode::deserialize(&header_bytes)?;
            if verifier.verify_tx_proof(txid.ref_elements().unwrap(), proof, &header).is_ok() {
                cache.write(&txid)?;
                Ok(SPVVerifyResult::Verified)
            } else {
                Ok(SPVVerifyResult::NotVerified)
            }
        }
    }
}

struct VerifiedCache {
    set: HashSet<BETxid>,
    filepath: PathBuf,
    cipher: Aes256GcmSiv,
}

impl VerifiedCache {
    fn new(path: &str, network: NetworkId, key: &str) -> Result<Self, Error> {
        let mut filepath: PathBuf = path.into();
        let filename_preimage = format!("{:?}{}", network, key);
        let filename = hex::encode(sha256::Hash::hash(filename_preimage.as_bytes()));
        let key_bytes = sha256::Hash::hash(key.as_bytes()).into_inner();
        filepath.push(format!("verified_cache_{}", filename));
        let cipher = Aes256GcmSiv::new(GenericArray::from_slice(&key_bytes));
        let set = match VerifiedCache::read_and_decrypt(&mut filepath, &cipher) {
            Ok(set) => set,
            Err(_) => HashSet::new(),
        };
        Ok(VerifiedCache {
            set,
            filepath,
            cipher,
        })
    }

    fn read_and_decrypt(
        filepath: &mut PathBuf,
        cipher: &Aes256GcmSiv,
    ) -> Result<HashSet<BETxid>, Error> {
        let mut file = File::open(&filepath)?;
        let mut nonce_bytes = [0u8; 12]; // 96 bits
        file.read_exact(&mut nonce_bytes)?;
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let mut ciphertext = vec![];
        file.read_to_end(&mut ciphertext)?;
        let plaintext = cipher.decrypt(nonce, ciphertext.as_ref())?;
        Ok(serde_cbor::from_slice(&plaintext)?)
    }

    fn contains(&self, txid: &BETxid) -> Result<bool, Error> {
        Ok(self.set.contains(txid))
    }

    fn write(&mut self, txid: &BETxid) -> Result<(), Error> {
        self.set.insert(txid.clone());
        self.flush()
    }

    fn clear(&mut self) -> Result<(), Error> {
        self.set.clear();
        self.flush()
    }

    fn flush(&mut self) -> Result<(), Error> {
        let mut file = File::create(&self.filepath)?;
        let mut nonce_bytes = [0u8; 12]; // 96 bits
        thread_rng().fill(&mut nonce_bytes);
        let plaintext = serde_cbor::to_vec(&self.set)?;
        let nonce = GenericArray::from_slice(&nonce_bytes);
        let ciphertext = self.cipher.encrypt(nonce, plaintext.as_ref())?;
        file.write(&nonce)?;
        file.write(&ciphertext)?;
        Ok(())
    }
}
