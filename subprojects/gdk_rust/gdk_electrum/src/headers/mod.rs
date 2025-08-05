use crate::error::Error;
use crate::headers::bitcoin::HeadersChain;
use crate::headers::liquid::Verifier;
use electrum_client::GetMerkleRes;
use gdk_common::bitcoin::hashes::{sha256d, Hash};
use gdk_common::electrum_client;
use std::io::Write;

pub mod bitcoin;
pub mod liquid;

pub enum ChainOrVerifier {
    /// used for bitcoin networks
    Chain(HeadersChain),

    /// used for elements networks
    Verifier(Verifier),
}

/// compute the merkle root from the merkle path of a tx in electrum format (note the hash.reverse())
fn compute_merkle_root(txid: [u8; 32], merkle: GetMerkleRes) -> Result<[u8; 32], Error> {
    let mut pos = merkle.pos;
    let mut current = txid;

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
        current = sha256d::Hash::from_engine(engine).to_byte_array();
        pos /= 2;
    }

    Ok(current)
}
