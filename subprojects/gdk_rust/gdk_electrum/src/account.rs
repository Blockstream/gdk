use std::cmp::Ordering;
use std::fmt;

use log::{debug, info, trace};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::{Address, PublicKey, Script, Transaction, Txid};

use gdk_common::wally::{asset_blinding_key_to_ec_private_key, ec_public_key_from_private_key};

use gdk_common::be::{BEAddress, BEScript, BEScriptConvert, ScriptBatch, Utxos};
use gdk_common::error::fn_err;
use gdk_common::model::{
    AddressAmount, AddressPointer, Balances, CreateTransaction, GetTransactionsOpt,
    SPVVerifyResult, TransactionMeta,
};
use gdk_common::scripts::p2shwpkh_script;
use gdk_common::wally::MasterBlindingKey;
use gdk_common::{ElementsNetwork, Network, NetworkId};

use crate::error::Error;
use crate::store::{Store, BATCH_SIZE};

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
    chains: [ExtendedPubKey; 2],
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

        // cache internal/external chains
        let chains = [xpub.ckd_pub(&EC, 0.into())?, xpub.ckd_pub(&EC, 1.into())?];

        Ok(Self {
            network,
            account_num,
            path,
            xpub,
            xprv,
            chains,
            store,
            master_blinding,
        })
    }

    pub fn num(&self) -> AccountNum {
        self.account_num
    }

    pub fn derive_address(&self, is_change: bool, index: u32) -> Result<BEAddress, Error> {
        let chain_xpub = self.chains[is_change as usize];
        let derived = chain_xpub.ckd_pub(&EC, index.into())?;

        match self.network.id() {
            NetworkId::Bitcoin(network) => {
                Ok(BEAddress::Bitcoin(Address::p2shwpkh(&derived.public_key, network).unwrap()))
            }
            NetworkId::Elements(network) => {
                let master_blinding_key = self
                    .master_blinding
                    .as_ref()
                    .expect("we are in elements but master blinding is None");

                let address = liquid_address(&derived.public_key, master_blinding_key, network);
                Ok(BEAddress::Elements(address))
            }
        }
    }

    pub fn get_next_address(&self) -> Result<AddressPointer, Error> {
        let pointer = {
            let store = &mut self.store.write()?;
            let acc_store = store.account_store_mut(self.account_num)?;
            acc_store.indexes.external += 1;
            acc_store.indexes.external
        };
        let address = self.derive_address(false, pointer)?.to_string();
        Ok(AddressPointer {
            address,
            pointer,
        })
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

    pub fn get_script_batch(&self, is_change: bool, batch: u32) -> Result<ScriptBatch, Error> {
        let store = self.store.read()?;
        let acc_store = store.account_store(self.account_num)?;

        let mut result = ScriptBatch::default();
        result.cached = true;

        let chain_xpub = &self.chains[is_change as usize];

        let start = batch * BATCH_SIZE;
        let end = start + BATCH_SIZE;
        for j in start..end {
            let path = DerivationPath::from(&[(is_change as u32).into(), j.into()][..]);
            let script = acc_store.scripts.get(&path).cloned().map_or_else(
                || -> Result<BEScript, Error> {
                    result.cached = false;
                    Ok(self.derive_address(is_change, j)?.script_pubkey())
                },
                Ok,
            )?;
            result.value.push((script, path));
        }
        Ok(result)
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

impl AccountNum {
    pub fn as_u32(self) -> u32 {
        self.into()
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
            bitcoin::Network::Signet => 1,
        },
        NetworkId::Elements(elements_network) => match elements_network {
            ElementsNetwork::Liquid => 1776,
            ElementsNetwork::ElementsRegtest => 1,
        },
    }
}

fn liquid_address(
    public_key: &PublicKey,
    master_blinding_key: &MasterBlindingKey,
    net: ElementsNetwork,
) -> elements::Address {
    let script = p2shwpkh_script(public_key).into_elements();
    let blinding_key = asset_blinding_key_to_ec_private_key(&master_blinding_key, &script);
    let blinding_pub = ec_public_key_from_private_key(blinding_key);

    let addr_params = match net {
        ElementsNetwork::Liquid => &elements::AddressParams::LIQUID,
        ElementsNetwork::ElementsRegtest => &elements::AddressParams::ELEMENTS,
    };

    elements::Address::p2shwpkh(public_key, Some(blinding_pub), addr_params)
}
