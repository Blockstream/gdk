use hex;
use rand::Rng;
use std::convert::TryFrom;
use std::time::Instant;

use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::util::address::Address;
use bitcoin::util::bip143::SighashComponents;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::Txid;
use elements::{self, AddressParams};

use log::{debug, info};
use sled::{Batch, Db};

use gdk_common::mnemonic::Mnemonic;
use gdk_common::network::{ElementsNetwork, Network, NetworkId};
use gdk_common::util::p2shwpkh_script;
use gdk_common::wally::*;

use crate::db::{GetTree, WalletDB};
use crate::error::Error;
use crate::model::*;
use electrum_client::Client;
use std::io::{Read, Write};

pub struct WalletCtx {
    wallet_name: String,
    secp: Secp256k1<All>,
    network: Network,
    mnemonic: Mnemonic,
    db: WalletDB,
    xpub: ExtendedPubKey,
    master_blinding: Option<MasterBlindingKey>,
    change_max_deriv: u32,
}

#[derive(Debug)]
pub enum LiqOrBitAddress {
    Liquid(elements::Address),
    Bitcoin(bitcoin::Address),
}

impl LiqOrBitAddress {
    pub fn script_pubkey(&self) -> Script {
        match self {
            LiqOrBitAddress::Liquid(addr) => addr.script_pubkey(),
            LiqOrBitAddress::Bitcoin(addr) => addr.script_pubkey(),
        }
    }
}

impl ToString for LiqOrBitAddress {
    fn to_string(&self) -> String {
        match self {
            LiqOrBitAddress::Liquid(addr) => addr.to_string(),
            LiqOrBitAddress::Bitcoin(addr) => addr.to_string(),
        }
    }
}

pub enum ElectrumUrl {
    Tls(String),
    Plaintext(String),
}

impl WalletCtx {
    pub fn new(
        db_root: &str,
        wallet_name: String,
        mnemonic: Mnemonic,
        network: Network,
        xpub: ExtendedPubKey,
        master_blinding: Option<MasterBlindingKey>,
    ) -> Result<Self, Error> {
        debug!("opening sled db root path: {}", db_root);
        let db_ctx = Db::open(db_root)?;
        let db = db_ctx.get_tree(&wallet_name)?;

        Ok(WalletCtx {
            wallet_name,
            mnemonic,
            db,
            network, // TODO: from db
            secp: Secp256k1::gen_new(),
            xpub,
            master_blinding,
            change_max_deriv: 0,
        })
    }

    pub fn get_mnemonic(&self) -> &Mnemonic {
        &self.mnemonic
    }

    fn derive_address(
        &self,
        xpub: &ExtendedPubKey,
        path: &[u32; 2],
    ) -> Result<LiqOrBitAddress, Error> {
        let path: Vec<ChildNumber> = path
            .iter()
            .map(|x| ChildNumber::Normal {
                index: *x,
            })
            .collect();
        let derived = xpub.derive_pub(&self.secp, &path)?;
        if self.network.liquid {}
        match self.network.id() {
            NetworkId::Bitcoin(network) => {
                Ok(LiqOrBitAddress::Bitcoin(Address::p2shwpkh(&derived.public_key, network)))
            }
            NetworkId::Elements(network) => {
                let master_blinding_key = self
                    .master_blinding
                    .as_ref()
                    .expect("we are in elements but master blinding is None");
                let script = p2shwpkh_script(&derived.public_key);
                let blinding_key =
                    asset_blinding_key_to_ec_private_key(&master_blinding_key, &script);
                let public_key = ec_public_key_from_private_key(blinding_key);
                let blinder = Some(public_key);
                let addr = match network {
                    ElementsNetwork::Liquid => elements::Address::p2shwpkh(
                        &derived.public_key,
                        blinder,
                        &AddressParams::LIQUID,
                    ),
                    ElementsNetwork::ElementsRegtest => elements::Address::p2shwpkh(
                        &derived.public_key,
                        blinder,
                        &AddressParams::ELEMENTS,
                    ),
                };
                Ok(LiqOrBitAddress::Liquid(addr))
            }
        }
    }

    pub fn list_tx(&self) -> Result<Vec<TransactionMeta>, Error> {
        debug!("list_tx");
        self.db.list_tx()
    }

    fn is_mine(&self, script: Script) -> bool {
        self.db.get_path_by_script_pubkey(script).ok().is_some()
    }

    fn get_previous_output(&mut self, outpoint: OutPoint) -> Option<TxOut> {
        // TODO if the tx is in the same block there is a risk I visit them out of order not finding it,
        // also, when visiting change chain, we can visit tx newer of which previous output are not visited yet
        // this could cause wrong sent/received value, utxo should be adjusted in the utxo check step
        // one possible solution is to save also output scripts and check they are mine on that, if that is the
        // case I can get the previous tx for the amount from electrum API (even if it will be called also later should be a rare case)
        self.db
            .get_tx_by_hash(&outpoint.txid)
            .unwrap()
            .map(|previous_tx| previous_tx.transaction.output[outpoint.vout as usize].clone())
    }

    fn check_tx_and_descendant<S: Read + Write>(
        &mut self,
        txid: Txid,
        height: Option<u32>,
        cur_script: &Script,
        mut client: &mut Client<S>,
    ) -> Result<(), Error> {
        info!("check_tx_and_descendant of {}, height: {:?}, script: {}", txid, height, cur_script);
        if self.db.get_tx_by_hash(&txid).unwrap().is_some() {
            info!("already have {} in db skipping", txid);
            return Ok(());
        }

        let tx = client.transaction_get(&txid)?;

        let mut incoming: u64 = 0;
        let mut outgoing: u64 = 0;

        for (i, input) in tx.input.iter().enumerate() {
            let previous_output = self.get_previous_output(input.previous_output);
            if let Some(previous_output) = previous_output {
                if self.is_mine(previous_output.script_pubkey) {
                    outgoing += previous_output.value;
                    if height.is_some() {
                        info!("{} input #{} is mine, removing from utxo", txid, i);
                        self.db.del_utxo_by_outpoint(input.previous_output)?;
                    }
                }
            }
        }

        let mut to_check_later = vec![];
        for (i, output) in tx.output.iter().enumerate() {
            if let Some(path) = self.db.get_path_by_script_pubkey(output.script_pubkey.clone())? {
                info!("{} output #{} is mine, adding utxo", txid, i);
                self.db.set_utxo_by_outpoint(OutPoint::new(tx.txid(), i as u32), output.clone())?;
                incoming += output.value;
                if &output.script_pubkey != cur_script {
                    info!("{} output #{} script {} was not current script, adding script to be checked later", txid, i, output.script_pubkey);
                    to_check_later.push(output.script_pubkey.clone())
                }
                if u32::from(path[0]) == 0u32 {
                    if u32::from(path[1]) > self.change_max_deriv {
                        self.change_max_deriv = u32::from(path[1]);
                    }
                }
            }
        }

        let tx = TransactionMeta::new(tx, None, incoming, outgoing);
        info!("Saving tx {}", txid);
        self.db.set_tx_by_hash(tx)?;

        for script in to_check_later {
            self.check_history(&script, &mut client)?;
        }

        Ok(())
    }

    fn check_history<S: Read + Write>(
        &mut self,
        script_pubkey: &Script,
        mut client: &mut Client<S>,
    ) -> Result<bool, Error> {
        let txs = client.script_get_history(script_pubkey)?;
        info!("history of script {} has {} tx", script_pubkey, txs.len());
        info!("txs {:?}", txs);
        let have_txs = txs.len() > 0;
        for tx in txs {
            let height: Option<u32> = u32::try_from(tx.height).map(|el| Some(el)).unwrap_or(None);
            self.check_tx_and_descendant(tx.tx_hash, height, script_pubkey, &mut client)?;
        }
        Ok(have_txs)
    }

    pub fn sync<S: Read + Write>(&mut self, mut client: &mut Client<S>) -> Result<(), Error> {
        debug!("start sync");
        let max_address = 1000; //TODO make it configurable
        let path = [0, max_address].into_iter().map(|e| ChildNumber::from(*e)).collect();
        let first = self.db.get_script_pubkey_by_path(path).expect("db error").is_none();

        if first {
            let mut address_batch = Batch::default();
            let start = Instant::now();
            for i in 0..=1 {
                let path = [ChildNumber::Normal {
                    index: i,
                }];
                let first_deriv = self.xpub.derive_pub(&self.secp, &path)?;
                for j in 0..=max_address {
                    let path = [ChildNumber::Normal {
                        index: j,
                    }];
                    let second_deriv = first_deriv.derive_pub(&self.secp, &path)?;

                    let full_path: Vec<ChildNumber> =
                        [i, j].into_iter().map(|e| ChildNumber::from(*e)).collect();
                    let script_pubkey = Address::p2shwpkh(
                        &second_deriv.public_key,
                        self.network.id().get_bitcoin_network().unwrap(),
                    )
                    .script_pubkey(); //FIXME liquid
                    self.db.set_path_by_script_pubkey(
                        script_pubkey.clone(),
                        full_path.clone(),
                        &mut address_batch,
                    )?;
                    self.db.set_script_pubkey_by_path(
                        full_path,
                        script_pubkey,
                        &mut address_batch,
                    )?;
                }
            }
            info!(
                "derivation of {} addresses, took {}",
                max_address * 2,
                start.elapsed().as_millis()
            );
            self.db.apply_batch(address_batch)?;
        }

        let mut last_found = 0;
        for (i, script) in self.db.iter_script_pubkeys()?.iter().enumerate() {
            info!("checking {:?}", script);
            let found = self.check_history(script, &mut client)?;
            if found {
                last_found = i;
            }
            if i > last_found + 20 {
                break;
            }
        }

        // check utxo
        for (outpoint, output) in self.db.iter_utxos()? {
            let list_unspent = client.script_list_unspent(&output.script_pubkey)?;
            info!("outpoint {:?} is unspent for me, list unspent is {:?}", outpoint, list_unspent);

            let mut spent = true;
            for unspent in list_unspent {
                let res_outpoint = OutPoint::new(unspent.tx_hash, unspent.tx_pos as u32);
                if outpoint == res_outpoint {
                    spent = false;
                    break;
                }
            }
            if spent {
                info!("{} not anymore unspent, removing", outpoint);
                self.db.del_utxo_by_outpoint(outpoint)?;
            }
        }

        if first {
            let first_ext_new = last_found as u32 + 1;
            info!("Setting external index to {}", first_ext_new);
            self.db.set_external_index(first_ext_new)?;

            let first_int_new = self.change_max_deriv + 1;
            info!("Setting internal index to {}", first_int_new);
            self.db.set_internal_index(first_int_new)?;
        }

        Ok(())
    }

    pub fn utxos(&self) -> Result<Vec<UTXO>, Error> {
        let mut unspent = Vec::new();
        for (outpoint, txout) in self.db.iter_utxos()? {
            unspent.push(UTXO {
                outpoint,
                txout,
            });
        }
        Ok(unspent)
    }

    pub fn balance(&self) -> Result<u64, Error> {
        debug!("balance");
        Ok(self.utxos()?.iter().fold(0, |sum, i| sum + i.txout.value))
    }

    // If request.utxo is None, we do the coin selection
    pub fn create_tx(&self, request: CreateTransaction) -> Result<TransactionMeta, Error> {
        debug!("create_tx {:?}", request);
        use bitcoin::consensus::serialize;

        let mut tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![],
            output: vec![],
        };

        let fee_rate = request.fee_rate.unwrap_or(1000.0) / 1000.0;

        let mut fee_val = 0;
        let mut outgoing: u64 = 0;
        let mut is_mine = vec![];

        let calc_fee_bytes = |bytes| ((bytes as f32) * fee_rate) as u64;
        fee_val += calc_fee_bytes(tx.get_weight() / 4);

        for out in request.addressees.iter() {
            let new_out = TxOut {
                script_pubkey: out.address.script_pubkey(),
                value: out.satoshi,
            };
            fee_val += calc_fee_bytes(serialize(&new_out).len());

            tx.output.push(new_out);
            is_mine.push(false);

            outgoing += out.satoshi;
        }

        let mut utxos = self.utxos()?;
        utxos.sort_by(|a, b| a.txout.value.partial_cmp(&b.txout.value).unwrap());
        debug!("utxos len:{}", utxos.len());

        let mut selected_amount: u64 = 0;
        while selected_amount < outgoing + fee_val {
            debug!("selected_amount:{} outgoing:{} fee_val:{}", selected_amount, outgoing, fee_val);
            let utxo = utxos.pop().ok_or(Error::InsufficientFunds)?;

            let new_in = TxIn {
                previous_output: utxo.outpoint,
                script_sig: Script::default(),
                sequence: 0,
                witness: vec![],
            };
            fee_val += calc_fee_bytes(serialize(&new_in).len() + 50); // TODO: adjust 50 based on the signature size

            tx.input.push(new_in);

            selected_amount += utxo.txout.value;
        }

        let change_val = selected_amount - outgoing - fee_val;
        if change_val > 546 {
            let change_index = self.db.increment_internal_index()?;
            let change_address = self.derive_address(&self.xpub, &[1, change_index])?;
            debug!("adding change {:?}", change_address);

            // TODO: we are not accounting for this output
            tx.output.push(TxOut {
                script_pubkey: change_address.script_pubkey(),
                value: change_val,
            });

            is_mine.push(true);
        }
        let mut created_tx = TransactionMeta::new(tx, None, 0, outgoing);
        created_tx.create_transaction = Some(request);
        created_tx.fee = fee_val;
        created_tx.sent = Some(outgoing);
        created_tx.satoshi = outgoing;
        debug!("returning: {:?}", created_tx);

        self.db.flush()?;
        Ok(created_tx)
    }

    // TODO when we can serialize psbt
    //pub fn sign(&self, psbt: PartiallySignedTransaction) -> Result<PartiallySignedTransaction, Error> { Err(Error::Generic("NotImplemented".to_string())) }

    fn internal_sign(
        &self,
        tx: &Transaction,
        script: &Script,
        input_index: usize,
        path: &DerivationPath,
        xpriv: &ExtendedPrivKey,
        value: u64,
    ) -> (Vec<u8>, Vec<u8>) {
        let privkey = xpriv.derive_priv(&self.secp, &path).unwrap();
        let pubkey =
            bitcoin::secp256k1::PublicKey::from_secret_key(&self.secp, &privkey.private_key.key);

        let mut script_code = vec![0x76, 0xa9, 0x14];
        script_code.append(&mut script[2..].to_vec());
        script_code.append(&mut vec![0x88, 0xac]);

        let hash = SighashComponents::new(tx).sighash_all(
            &tx.input[input_index],
            &Script::from(script_code),
            value,
        );

        let signature = self
            .secp
            .sign(&Message::from_slice(&hash.into_inner()[..]).unwrap(), &privkey.private_key.key);

        //let mut signature = signature.serialize_der().to_vec();
        let mut signature = hex::decode(&format!("{:?}", signature)).unwrap();
        signature.push(0x01 as u8); // TODO how to properly do this?

        let pubkey = hex::decode(&pubkey.to_string()).unwrap();

        (pubkey, signature)
    }

    pub fn sign<S: Read + Write>(
        &self,
        client: &mut Client<S>,
        request: WGSignReq,
    ) -> Result<TransactionMeta, Error> {
        let mut out_tx = request.transaction.clone();

        for i in 0..request.transaction.input.len() {
            let prev_output = request.transaction.input[i].previous_output.clone();
            let tx = self.db.get_tx(&prev_output.txid.to_string())?.unwrap();

            let (pk, sig) = self.internal_sign(
                &request.transaction,
                &tx.transaction.output[prev_output.vout as usize].script_pubkey,
                i,
                &request.derivation_paths[i],
                &request.xprv,
                tx.transaction.output[prev_output.vout as usize].value,
            );
            let witness = vec![sig, pk];

            out_tx.input[i].witness = witness;
        }

        let wgtx: TransactionMeta = out_tx.into();
        self.broadcast(client, wgtx.clone())?;

        Ok(wgtx)
    }

    pub fn broadcast<S: Read + Write>(
        &self,
        client: &mut Client<S>,
        tx: TransactionMeta,
    ) -> Result<(), Error> {
        client.transaction_broadcast(&tx.transaction)?;

        Ok(())
    }

    pub fn validate_address(&self, _address: Address) -> Result<bool, Error> {
        // if we managed to get here it means that the address is already valid.
        // only other thing we can check is if it the network is right.

        // TODO implement for both Liquid and Bitcoin address
        //Ok(address.network == self.network)
        unimplemented!("validate not implemented");
    }

    pub fn poll(&self, _xpub: WGExtendedPubKey) -> Result<(), Error> {
        Ok(())
    }

    pub fn get_address(&self) -> Result<WGAddress, Error> {
        debug!("get_address");
        let index = self.db.increment_external_index()?;
        self.db.flush()?;
        let address = self.derive_address(&self.xpub, &[0, index])?.to_string();
        Ok(WGAddress {
            address,
        })
    }
    pub fn xpub_from_xprv(&self, xprv: WGExtendedPrivKey) -> Result<WGExtendedPubKey, Error> {
        Ok(WGExtendedPubKey {
            xpub: ExtendedPubKey::from_private(&self.secp, &xprv.xprv),
        })
    }

    pub fn generate_xprv(&self) -> Result<WGExtendedPrivKey, Error> {
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();

        Ok(WGExtendedPrivKey {
            xprv: ExtendedPrivKey::new_master(
                self.network.id().get_bitcoin_network().unwrap(),
                &random_bytes,
            )?, // TODO support LIQUID
        })
    }

    // TODO: only debug
    pub fn dump_db(&self) -> Result<(), Error> {
        self.db.dump()
    }
}

#[cfg(test)]
mod test {}
