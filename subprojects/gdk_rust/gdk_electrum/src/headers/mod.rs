use crate::error::Error;
use crate::headers::bitcoin::HeadersChain;
use crate::headers::liquid::Verifier;
use ::bitcoin::hashes::{sha256d, Hash};
use ::bitcoin::{TxMerkleNode, Txid};
use electrum_client::GetMerkleRes;
use std::io::Write;

pub mod bitcoin;
pub mod liquid;

pub enum ChainOrVerifier {
    Chain(HeadersChain),
    Verifier(Verifier),
}

fn compute_merkle_path(txid: &Txid, merkle: GetMerkleRes) -> Result<TxMerkleNode, Error> {
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
