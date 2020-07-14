use crate::error::Error;
use crate::headers::bitcoin::HeadersChain;
use crate::headers::liquid::Verifier;
use ::bitcoin::hashes::hex::FromHex;
use ::bitcoin::hashes::{sha256d, Hash};
use ::bitcoin::{TxMerkleNode, Txid};
use electrum_client::GetMerkleRes;
use gdk_common::model::{SPVVerifyResult, SPVVerifyTx};
use gdk_common::NetworkId;
use log::info;
use std::io::Write;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::{determine_electrum_url_from_net, ClientWrap};

pub mod bitcoin;
pub mod liquid;

pub enum ChainOrVerifier {
    Chain(HeadersChain),
    Verifier(Verifier),
}

fn compute_merkle_root(txid: &Txid, merkle: GetMerkleRes) -> Result<TxMerkleNode, Error> {
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

    Ok(TxMerkleNode::from_slice(&current)?)
}

lazy_static! {
    static ref SPV_MUTEX: Mutex<()> = Mutex::new(());
}

pub fn spv_verify_tx(input: &SPVVerifyTx) -> Result<SPVVerifyResult, Error> {
    let _ = SPV_MUTEX.lock().unwrap();

    info!("spv_verify_tx {:?}", input);

    let txid = Txid::from_hex(&input.txid)?;

    let cache: VerifiedCache = VerifiedCache::new(&input.path, input.network.id())?;
    if cache.contains(&txid)? {
        info!("verified cache hit for {}", txid);
        return Ok(SPVVerifyResult::Verified);
    }

    let url = determine_electrum_url_from_net(&input.network)?;
    let mut client = ClientWrap::new(url)?;

    match input.network.id() {
        NetworkId::Bitcoin(bitcoin_network) => {
            let mut path: PathBuf = (&input.path).into();
            path.push(format!("headers_chain_{}", bitcoin_network));
            let mut chain = HeadersChain::new(path, bitcoin_network)?;

            if input.height < chain.height() {
                info!("chain height enough to verify, downloading proof");
                let proof = client.transaction_get_merkle(&txid, input.height as usize)?;
                if chain.verify_tx_proof(&txid, input.height, proof).is_ok() {
                    cache.write(&txid)?;
                    Ok(SPVVerifyResult::Verified)
                } else {
                    Ok(SPVVerifyResult::NotVerified)
                }
            } else {
                info!("chain height not enough to verify, downloading 2016 headers");
                let headers_to_download = input.headers_to_download.unwrap_or(2016).min(2016);
                let headers =
                    client.block_headers(chain.height() as usize + 1, headers_to_download)?.headers;
                if let Err(Error::InvalidHeaders) = chain.push(headers) {
                    // handle reorgs
                    chain.remove(144)?;
                }
                Ok(SPVVerifyResult::CallMeAgain)
            }
        }
        NetworkId::Elements(elements_network) => {
            let proof = client.transaction_get_merkle(&txid, input.height as usize)?;
            let verifier = Verifier::new(elements_network);
            let header_bytes = client.block_header_raw(input.height as usize)?;
            let header: elements::BlockHeader = elements::encode::deserialize(&header_bytes)?;
            if verifier.verify_tx_proof(&txid, proof, &header).is_ok() {
                cache.write(&txid)?;
                Ok(SPVVerifyResult::Verified)
            } else {
                Ok(SPVVerifyResult::NotVerified)
            }
        }
    }
}

struct VerifiedCache {
    db: sled::Db,
}

impl VerifiedCache {
    fn new(path: &str, network: NetworkId) -> Result<Self, Error> {
        let mut path: PathBuf = (path).into();
        path.push(format!("verified_cache_{:?}", network));
        let db = sled::open(path)?;
        Ok(VerifiedCache { db })
    }

    fn contains(&self, txid: &Txid) -> Result<bool, Error> {
        Ok(self.db.contains_key(&txid )?)
    }

    fn write(&self, txid: &Txid) -> Result<(), Error> {
        Ok(self.db.insert(&txid, &[]).map(|_| ())?)
    }
}
