use std::fmt;

use log::debug;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use bitcoin::{Transaction, Script};
use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};

use gdk_common::wally::MasterBlindingKey;
use gdk_common::{ElementsNetwork, Network, NetworkId};
use gdk_common::model::{AddressPointer, CreateTransaction, TransactionMeta, Balances, GetTransactionsOpt};
use gdk_common::be::{BEAddress, Utxos};

use crate::error::Error;
use crate::store::Store;

lazy_static! {
    static ref EC: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq, Hash)]
pub struct AccountNum(pub u32);

pub struct Account {
    account_num: AccountNum,
    path: DerivationPath,
    xpub: ExtendedPubKey,
    xprv: ExtendedPrivKey,
    network: Network,
    store: Store,
    // liquid only
    master_blinding: Option<MasterBlindingKey>,
}

impl Account {
    pub fn new(
        network: Network,
        master_xprv: &ExtendedPrivKey,
        master_blinding: Option<MasterBlindingKey>,
        store: Store,
        account_num: AccountNum,
    ) -> Result<Self, Error> {
        let path = get_account_path(account_num, &network)?;

        debug!("Using derivation path {} for account {}", path, account_num);

        let xprv = master_xprv.derive_priv(&EC, &path)?;
        let xpub = ExtendedPubKey::from_private(&EC, &xprv);

        Ok(Self {
            network,
            account_num,
            path,
            xpub,
            xprv,
            store,
            master_blinding,
        })
    }

    fn derive_address(&self, is_change: bool, index: u32) -> Result<BEAddress, Error> {
        unimplemented!()
    }

    pub fn get_address(&self) -> Result<AddressPointer, Error> {
        unimplemented!()
    }

    pub fn list_tx(&self, opt: &GetTransactionsOpt) -> Result<Vec<TransactionMeta>, Error> {
      unimplemented!()
    }

    pub fn utxos(&self) -> Result<Utxos, Error> {
        unimplemented!()
    }

    pub fn balance(&self) -> Result<Balances, Error> {
        unimplemented!()
    }

    pub fn create_tx(&self, request: &mut CreateTransaction) -> Result<TransactionMeta, Error> {
        unimplemented!()
    }

    fn internal_sign_bitcoin(
        &self,
        tx: &Transaction,
        input_index: usize,
        path: &DerivationPath,
        value: u64,
    ) -> (Script, Vec<Vec<u8>>) {
        unimplemented!()
    }

    fn internal_sign_elements(
        &self,
        tx: &elements::Transaction,
        input_index: usize,
        derivation_path: &DerivationPath,
        value: Value,
    ) -> (Script, Vec<Vec<u8>>) {
        unimplemented!()
    }

    pub fn sign(&self, request: &TransactionMeta) -> Result<TransactionMeta, Error> {
        unimplemented!()
    }

    fn blind_tx(&self, tx: &mut elements::Transaction) -> Result<(), Error> {
        unimplemented!()
    }
}

impl fmt::Display for AccountNum {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl From<u32> for AccountNum {
    fn from(num: u32) -> Self {
        AccountNum(num)
    }
}
impl From<usize> for AccountNum {
    fn from(num: usize) -> Self {
        AccountNum(num as u32)
    }
}
impl Into<u32> for AccountNum {
    fn into(self) -> u32 {
        self.0
    }
}

fn get_account_path(
    account_num: AccountNum,
    network: &Network,
) -> Result<DerivationPath, Error> {
    let coin_type = get_coin_type(network);
    let purpose = 49; // P2SH-P2WPKH
    // BIP44: m / purpose' / coin_type' / account' / change / address_index
    let path: DerivationPath =
        format!("m/{}'/{}'/{}'", purpose, coin_type, account_num).parse().unwrap();

    Ok(path)
}

fn get_coin_type(network: &Network) -> u32 {
    // coin_type = 0 bitcoin, 1 testnet, 1776 liquid bitcoin as defined in https://github.com/satoshilabs/slips/blob/master/slip-0044.md
    // slip44 suggest 1 for every testnet, so we are using it also for regtest
    match network.id() {
        NetworkId::Bitcoin(bitcoin_network) => match bitcoin_network {
            bitcoin::Network::Bitcoin => 0,
            bitcoin::Network::Testnet => 1,
            bitcoin::Network::Regtest => 1,
        },
        NetworkId::Elements(elements_network) => match elements_network {
            ElementsNetwork::Liquid => 1776,
            ElementsNetwork::ElementsRegtest => 1,
        },
    }
}
