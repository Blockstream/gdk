use rand::Rng;

use std::collections::{HashMap, HashSet};
use std::net::ToSocketAddrs;
use std::time::{SystemTime, UNIX_EPOCH};

use hex;

use bitcoin::blockdata::script::Script;
use bitcoin::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::{All, Message, Secp256k1};
use bitcoin::util::address::Address;
use bitcoin::util::bip143::SighashComponents;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin_hashes::hex::FromHex;
use bitcoin_hashes::sha256d;
use bitcoin_hashes::Hash;

use sled::{Batch, Db};

use crate::client::ElectrumxClient;
use crate::db::{GetTree, WalletDB};
use crate::error::WGError;
use crate::model::{
    WGAddress, WGBalance, WGCreateTxReq, WGEstimateFeeReq, WGEstimateFeeRes, WGExtendedPrivKey,
    WGExtendedPubKey, WGInit, WGSignReq, WGSyncReq, WGTransaction, WGUTXO,
};

static mut DB: Option<Db> = None;

pub unsafe fn lib_init(init: WGInit) {
    println!("opening db path: {}", init.path);
    DB = Some(Db::open(init.path).unwrap())
}

pub struct WalletCtx<A: ToSocketAddrs> {
    wallet_name: String,
    secp: Secp256k1<All>,
    network: Network,
    client: Option<ElectrumxClient<A>>,
    db: WalletDB,
}

impl<A: ToSocketAddrs + Clone> WalletCtx<A> {
    pub fn new(wallet_name: String, url: Option<A>) -> Result<Self, WGError> {
        let client = match url {
            Some(u) => Some(ElectrumxClient::new(u)?),
            None => None,
        };

        let db = unsafe { DB.as_ref().unwrap().get_tree(&wallet_name)? };

        Ok(WalletCtx {
            wallet_name,
            client,
            db,
            network: Network::Testnet, // TODO: from db
            secp: Secp256k1::gen_new(),
        })
    }

    fn derive_address(&self, xpub: &ExtendedPubKey, path: &[u32; 2]) -> Result<Address, WGError> {
        let path: Vec<ChildNumber> = path
            .iter()
            .map(|x| ChildNumber::Normal {
                index: *x,
            })
            .collect();
        let derived = xpub.derive_pub(&self.secp, &path)?;

        Ok(Address::p2wpkh(&derived.public_key, self.network))
    }

    pub fn list_tx(&self) -> Result<Vec<WGTransaction>, WGError> {
        self.db.list_tx()
    }

    pub fn sync(&mut self, request: WGSyncReq) -> Result<(), WGError> {
        use bitcoin::consensus::deserialize;

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        let mut batch = Batch::default();

        // TODO: more addrs if necessary
        let change_pool: HashMap<_, _> = (0..20)
            .map(|x| {
                let path = DerivationPath::from(vec![
                    ChildNumber::Normal {
                        index: 1,
                    },
                    ChildNumber::Normal {
                        index: x,
                    },
                ]);
                (self.derive_address(&request.xpub, &[1, x]).unwrap().script_pubkey(), path)
            })
            .collect();

        let mut last_found = 0;
        let mut i = 0;
        while i - last_found < 20 {
            let addr = self.derive_address(&request.xpub, &[0, i])?;
            let this_scriptpubkey = addr.script_pubkey();
            let history = self.client.as_mut().unwrap().get_history(addr.to_string().as_str())?;

            if history.len() == 0 {
                i += 1;
                continue;
            } else {
                last_found = i;
            }

            let unspent = self.client.as_mut().unwrap().list_unspent(addr.to_string().as_str())?;
            let mut unspent_set = HashSet::new();

            for elem in unspent {
                unspent_set.insert((elem.tx_hash.clone(), elem.tx_pos));
            }

            for tx in history {
                let tx_str =
                    self.client.as_mut().unwrap().get_transaction(tx.tx_hash.clone(), false)?;
                let unserialized: Transaction = deserialize(hex::decode(tx_str)?.as_slice())?;

                let mut incoming: u64 = 0;
                let mut outgoing: u64 = 0;

                let mut is_mine = vec![];
                let mut derivation_path = vec![];

                for (vout, out) in unserialized.output.iter().enumerate() {
                    if out.script_pubkey == this_scriptpubkey {
                        println!("{:?}", out);

                        if unspent_set.get(&(tx.tx_hash.clone(), vout)).is_none() {
                            println!("... is_spent");
                            let op = OutPoint {
                                txid: sha256d::Hash::from_hex(&tx.tx_hash).unwrap(),
                                vout: (vout as u32),
                            };
                            self.db.save_spent(&op, &mut batch)?;
                        } else {
                            println!("... unspent");
                        }

                        incoming += out.value;

                        is_mine.push(true);
                        derivation_path.push(Some(DerivationPath::from(vec![
                            ChildNumber::Normal {
                                index: 0,
                            },
                            ChildNumber::Normal {
                                index: i,
                            },
                        ])));
                    } else if let Some(path) = change_pool.get(&out.script_pubkey) {
                        println!("found change at {:?}", path);

                        let mut found = false;
                        for elem in self.client.as_mut().unwrap().list_unspent(
                            Address::from_script(&out.script_pubkey, Network::Testnet)
                                .unwrap()
                                .to_string()
                                .as_str(),
                        )? {
                            if (&elem.tx_hash, elem.tx_pos) == (&tx.tx_hash, vout) {
                                println!("... unspent");

                                found = true;
                                break;
                            }
                        }

                        if !found {
                            let op = OutPoint {
                                txid: sha256d::Hash::from_hex(&tx.tx_hash.clone()).unwrap(),
                                vout: (vout as u32),
                            };
                            self.db.save_spent(&op, &mut batch)?;
                        }

                        is_mine.push(true);
                        derivation_path.push(Some(path.clone()));
                    } else {
                        // TODO: potentially look for more outputs
                        is_mine.push(false);
                        derivation_path.push(None);
                    }
                }

                for input in &unserialized.input {
                    if let Some(spending_tx) =
                        self.db.get_tx(&input.previous_output.txid.to_string())?
                    {
                        for out in spending_tx.transaction.output {
                            if out.script_pubkey == this_scriptpubkey {
                                outgoing += out.value;
                            }
                        }
                    }
                }

                let height = match tx.height {
                    -1 | 0 => None,
                    x => Some(x as u32),
                };

                // TODO: unconfirmed tx should have None height instead of 0
                let tx = WGTransaction::new(
                    unserialized,
                    now,
                    incoming,
                    outgoing,
                    height,
                    is_mine,
                    derivation_path,
                );

                self.db.save_tx(tx, &mut batch)?;
            }

            i += 1;
        }

        self.db.apply_batch(batch)?;

        Ok(())
    }

    pub fn utxos(&self) -> Result<Vec<WGUTXO>, WGError> {
        let txs = self.db.list_tx()?;
        let spent = self.db.get_spent()?;

        let mut unspent = Vec::new();

        for tx in txs {
            for (vout, (mine, path)) in
                tx.is_mine.iter().zip(tx.derivation_paths.iter()).enumerate()
            {
                if !mine || path.is_none() {
                    continue;
                }

                let op = OutPoint {
                    txid: sha256d::Hash::from_hex(&tx.txid).unwrap(),
                    vout: (vout as u32),
                };
                if spent.get(&op).is_none() {
                    unspent.push(WGUTXO {
                        outpoint: op,
                        txout: tx.transaction.output[vout].clone(),
                        is_change: path.as_ref().unwrap().as_ref()[0]
                            == ChildNumber::Normal {
                                index: 1,
                            }, // TODO
                        height: tx.height,
                        derivation_path: path.clone().unwrap(),
                    });
                }
            }
        }

        Ok(unspent)
    }

    pub fn balance(&self) -> Result<WGBalance, WGError> {
        Ok(WGBalance {
            satoshi: self.utxos()?.iter().fold(0, |sum, i| sum + i.txout.value),
        })
    }

    // If request.utxo is None, we do the coin selection
    pub fn create_tx(&self, request: WGCreateTxReq) -> Result<WGTransaction, WGError> {
        use bitcoin::consensus::serialize;

        let mut tx = Transaction {
            version: 2,
            lock_time: 0,
            input: vec![],
            output: vec![],
        };

        let fee_rate = request.fee_perkb * 100000.0;

        let mut fee_val = 0;
        let mut outgoing: u64 = 0;
        let mut is_mine = vec![];
        let mut derivation_path = vec![]; // used for the inputs this time

        let calc_fee_bytes = |bytes| ((bytes as f32) * fee_rate) as u64;
        fee_val += calc_fee_bytes(tx.get_weight() / 4);

        for out in request.addresses_amounts {
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

        let mut selected_amount: u64 = 0;
        while selected_amount < outgoing + fee_val {
            let utxo = utxos.pop();
            if let None = utxo {
                // TODO: unsufficient funds
            }
            let utxo = utxo.unwrap();

            let new_in = TxIn {
                previous_output: utxo.outpoint,
                script_sig: Script::default(),
                sequence: 0,
                witness: vec![],
            };
            fee_val += calc_fee_bytes(serialize(&new_in).len() + 50); // TODO: adjust 50 based on the signature size

            tx.input.push(new_in);
            derivation_path.push(Some(utxo.derivation_path));

            selected_amount += utxo.txout.value;
        }

        let change_val = selected_amount - outgoing - fee_val;
        if change_val > 546 {
            let change_index = self.db.increment_internal_index()?;
            let change_address = self.derive_address(&request.xpub, &[1, change_index])?;

            // TODO: we are not accounting for this output
            tx.output.push(TxOut {
                script_pubkey: change_address.script_pubkey(),
                value: change_val,
            });

            is_mine.push(true);
        }

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        Ok(WGTransaction::new(tx, now, 0, outgoing, None, is_mine, derivation_path))
    }

    // TODO when we can serialize psbt
    //pub fn sign(&self, psbt: PartiallySignedTransaction) -> Result<PartiallySignedTransaction, WGError> { Err(WGError::Generic("NotImplemented".to_string())) }

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

    pub fn sign(&mut self, request: WGSignReq) -> Result<WGTransaction, WGError> {
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

        let wgtx = WGTransaction::new(out_tx.clone(), 0, 0, 0, None, vec![], vec![]);
        self.broadcast(wgtx)?;

        Ok(WGTransaction::new(out_tx, 0, 0, 0, None, vec![], vec![]))
    }

    pub fn broadcast(&mut self, tx: WGTransaction) -> Result<(), WGError> {
        use bitcoin::consensus::serialize;

        let txstr: String = hex::encode(serialize(&tx.transaction));
        self.client.as_mut().unwrap().broadcast_transaction(txstr)?;

        Ok(())
    }

    pub fn validate_address(&self, address: WGAddress) -> Result<bool, WGError> {
        // if we managed to get here it means that the address is already valid.
        // only other thing we can check is if it the network is right.

        Ok(address.address.network == self.network)
    }

    pub fn poll(&self, _xpub: WGExtendedPubKey) -> Result<(), WGError> {
        Ok(())
    }

    pub fn get_address(&self, xpub: WGExtendedPubKey) -> Result<WGAddress, WGError> {
        let index = self.db.increment_external_index()?;

        Ok(WGAddress {
            address: self.derive_address(&xpub.xpub, &[0, index])?,
        })
    }

    pub fn fee(&mut self, request: WGEstimateFeeReq) -> Result<WGEstimateFeeRes, WGError> {
        let estimate = WGEstimateFeeRes {
            fee_perkb: self.client.as_mut().unwrap().estimate_fee(request.nblocks as usize).unwrap()
                as f32,
        };
        Ok(estimate)
    }

    pub fn xpub_from_xprv(&self, xprv: WGExtendedPrivKey) -> Result<WGExtendedPubKey, WGError> {
        Ok(WGExtendedPubKey {
            xpub: ExtendedPubKey::from_private(&self.secp, &xprv.xprv),
        })
    }

    pub fn generate_xprv(&self) -> Result<WGExtendedPrivKey, WGError> {
        let random_bytes = rand::thread_rng().gen::<[u8; 32]>();

        Ok(WGExtendedPrivKey {
            xprv: ExtendedPrivKey::new_master(self.network, &random_bytes)?,
        })
    }

    // TODO: only debug
    pub fn dump_db(&self) -> Result<(), WGError> {
        self.db.dump()
    }
}
