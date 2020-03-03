use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxOut};
use bitcoin::util::address::Address;
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
pub struct WGEmpty {}

/*
#[derive(Serialize, Deserialize, Debug)]
pub struct TransactionMeta {
    pub transaction: Transaction,
    pub txid: String,
    pub timestamp: u64,
    pub received: u64,
    pub sent: u64,
    pub height: Option<u32>,
    pub is_mine: Vec<bool>,
    pub derivation_paths: Vec<Option<DerivationPath>>,
}
*/

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransactionMeta {
    #[serde(flatten)]
    pub create_transaction: Option<CreateTransaction>,
    pub transaction: Transaction,
    pub txid: String,
    pub height: Option<u32>,
    pub timestamp: Option<u64>,
    pub received: Option<u64>,
    pub sent: Option<u64>,
    pub error: String,
    pub addressees_have_assets: bool,
    pub is_sweep: bool,
    pub satoshi: u64, // TODO it looks a copy of create_transaction.addressees[0].amount
    pub fee: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct CreateTransaction {
    pub addressees: Vec<AddressAmount>,
    pub fee_rate: Option<f32>,
    pub subaccount: Option<u32>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AddressAmount {
    pub address: Address,
    pub satoshi: u64,
    pub asset_tag: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct UTXO {
    pub outpoint: OutPoint,
    pub txout: TxOut,
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

impl From<Transaction> for TransactionMeta {
    fn from(transaction: Transaction) -> Self {
        let txid = transaction.txid().to_string();
        TransactionMeta {
            create_transaction: None,
            transaction,
            height: None,
            timestamp: None,
            txid,
            received: None,
            sent: None,
            error: "".to_string(),
            addressees_have_assets: false,
            is_sweep: false,
            satoshi: 0,
            fee: 0,
        }
    }
}

impl TransactionMeta {
    pub fn new(transaction: Transaction, height: Option<u32>, sent: u64, received: u64) -> Self {
        let mut wgtx: TransactionMeta = transaction.into();
        wgtx.height = height;
        wgtx.sent = Some(sent);
        wgtx.received = Some(received);
        wgtx
    }
}
