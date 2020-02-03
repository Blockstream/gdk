use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxOut};
use bitcoin::util::address::Address;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct WGEmpty {}

#[derive(Serialize, Deserialize, Debug)]
pub struct WGSyncReq {
    pub xpub: ExtendedPubKey,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WGTransaction {
    pub transaction: Transaction,
    pub txid: String,
    pub timestamp: u64,
    pub received: u64,
    pub sent: u64,
    pub height: Option<u32>,
    pub is_mine: Vec<bool>,
    pub derivation_paths: Vec<Option<DerivationPath>>,
}

impl WGTransaction {
    pub fn new(
        transaction: Transaction,
        timestamp: u64,
        received: u64,
        sent: u64,
        height: Option<u32>,
        is_mine: Vec<bool>,
        derivation_paths: Vec<Option<DerivationPath>>,
    ) -> Self {
        let txid = transaction.txid().to_string();

        WGTransaction {
            transaction,
            txid,
            timestamp,
            received,
            sent,
            height,
            is_mine,
            derivation_paths,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WGUTXO {
    pub outpoint: OutPoint,
    pub txout: TxOut,
    pub height: Option<u32>,
    pub is_change: bool,
    pub derivation_path: DerivationPath,
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct WGBalance {
    pub satoshi: u64,
}

/*
#[derive(Serialize, Deserialize, Debug)]
pub struct WGPSBT {
    psbt: PartiallySignedTransaction
}
*/

#[derive(Serialize, Deserialize, Debug)]
pub struct WGAddress {
    pub address: Address,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct WGAddressAmount {
    pub address: Address,
    pub satoshi: u64,
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
pub struct WGCreateTxReq {
    pub utxo: Option<Vec<WGUTXO>>,
    pub addresses_amounts: Vec<WGAddressAmount>,
    pub fee_perkb: f32,
    pub xpub: ExtendedPubKey,
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
