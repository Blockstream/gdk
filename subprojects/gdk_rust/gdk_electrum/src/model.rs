use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{OutPoint, Transaction, TxOut};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct WGEmpty {}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UTXO {
    pub outpoint: OutPoint,
    pub txout: TxOut,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct WGBalance {
    pub satoshi: u64,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WGAddress {
    pub address: String,
}
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct WGEstimateFeeReq {
    pub nblocks: u32,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct WGEstimateFeeRes {
    pub fee_perkb: f32,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WGSignReq {
    pub xprv: ExtendedPrivKey,
    pub transaction: Transaction,
    pub derivation_paths: Vec<DerivationPath>,
    //TODO: sighash: Vec<SigHashType>
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WGExtendedPrivKey {
    pub xprv: ExtendedPrivKey,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WGExtendedPubKey {
    pub xpub: ExtendedPubKey,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WGInit {
    pub path: String,
}
