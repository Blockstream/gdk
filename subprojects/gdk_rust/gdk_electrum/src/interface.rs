use bitcoin::blockdata::script::{Builder, Script};
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::hash_types::PubkeyHash;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::{self, All, Message, Secp256k1};
use bitcoin::util::address::Address;
use bitcoin::util::bip143::SighashComponents;
use bitcoin::util::bip32::{ChildNumber, DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::PublicKey;
use elements::{self, AddressParams};
use gdk_common::model::Balances;
use hex;
use log::{debug, warn};
use rand::Rng;

use gdk_common::mnemonic::Mnemonic;
use gdk_common::model::{CreateTransaction, Settings, TransactionMeta};
use gdk_common::network::{ElementsNetwork, Network, NetworkId};
use gdk_common::util::p2shwpkh_script;
use gdk_common::wally::*;

use crate::db::*;
use crate::error::*;
use crate::model::*;

use elements::confidential::{Asset, Nonce, Value};
use gdk_common::be::*;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Debug)]
pub struct WalletCtx {
    pub secp: Secp256k1<All>,
    pub network: Network,
    pub mnemonic: Mnemonic,
    pub db: Forest,
    pub xprv: ExtendedPrivKey,
    pub xpub: ExtendedPubKey,
    pub master_blinding: Option<MasterBlindingKey>,
    pub change_max_deriv: u32,
}

pub enum ElectrumUrl {
    Tls(String),
    Plaintext(String),
}

impl WalletCtx {
    pub fn new(
        db_root: &str,
        wallet_id: String,
        mnemonic: Mnemonic,
        network: Network,
        xprv: ExtendedPrivKey,
        xpub: ExtendedPubKey,
        master_blinding: Option<MasterBlindingKey>,
    ) -> Result<Self, Error> {
        let mut path: PathBuf = db_root.into();
        path.push(wallet_id);
        debug!("opening sled db root path: {:?}", path);

        let db = Forest::new(path, xpub, network.id())?;

        Ok(WalletCtx {
            mnemonic,
            db,
            network, // TODO: from db
            secp: Secp256k1::gen_new(),
            xprv,
            xpub,
            master_blinding,
            change_max_deriv: 0,
        })
    }

    pub fn get_mnemonic(&self) -> &Mnemonic {
        &self.mnemonic
    }

    fn derive_address(&self, xpub: &ExtendedPubKey, path: &[u32; 2]) -> Result<BEAddress, Error> {
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
                Ok(BEAddress::Bitcoin(Address::p2shwpkh(&derived.public_key, network)))
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
                Ok(BEAddress::Elements(addr))
            }
        }
    }

    pub fn get_settings(&self) -> Result<Settings, Error> {
        Ok(self.db.get_settings()?.unwrap_or_default())
    }

    pub fn change_settings(&self, settings: &Settings) -> Result<(), Error> {
        self.db.insert_settings(settings)
    }

    pub fn try_unblind(
        &self,
        outpoint: elements::OutPoint,
        output: elements::TxOut,
    ) -> Result<(), Error> {
        match (output.asset, output.value, output.nonce) {
            (Asset::Confidential(_, _), Value::Confidential(_, _), Nonce::Confidential(_, _)) => {
                let master_blinding = self.master_blinding.as_ref().unwrap();

                let script = output.script_pubkey.clone();
                let blinding_key = asset_blinding_key_to_ec_private_key(master_blinding, &script);
                let rangeproof = output.witness.rangeproof.clone();
                let value_commitment = elements::encode::serialize(&output.value);
                let asset_commitment = elements::encode::serialize(&output.asset);
                let nonce_commitment = elements::encode::serialize(&output.nonce);
                debug!(
                    "commitmnents len {} {} {}",
                    value_commitment.len(),
                    asset_commitment.len(),
                    nonce_commitment.len()
                );
                let sender_pk = secp256k1::PublicKey::from_slice(&nonce_commitment).unwrap();

                let (asset, abf, vbf, value) = asset_unblind(
                    sender_pk,
                    blinding_key,
                    rangeproof,
                    value_commitment,
                    script,
                    asset_commitment,
                )?;

                debug!(
                    "Unblinded outpoint:{} asset:{} value:{}",
                    outpoint,
                    hex::encode(&asset),
                    value
                );

                let unblinded = Unblinded {
                    asset,
                    value,
                    abf,
                    vbf,
                };
                self.db.insert_unblinded(&outpoint, &unblinded)?;
            }
            _ => warn!("received unconfidential or null asset/value/nonce"),
        }
        Ok(())
    }

    pub fn list_tx(&self) -> Result<Vec<TransactionMeta>, Error> {
        debug!("start list_tx");
        let (_, all_txs) = self.db.get_all_spent_and_txs()?;
        let all_scripts = self.db.get_all_scripts()?;
        let all_unblinded = self.db.get_all_unblinded()?; // empty map if not liquid

        let mut txs = vec![];

        for (tx_id, height) in self.db.get_my()? {
            let tx = all_txs.get(&tx_id).ok_or_else(fn_err("no tx"))?;
            let header = height
                .map(|h| self.db.get_header(h)?.ok_or_else(fn_err("no header")))
                .transpose()?;

            let fee = tx.fee(&all_txs);
            let satoshi = tx.my_balances(&all_txs, &all_scripts, &all_unblinded);

            let tx_meta = TransactionMeta::new(
                tx.clone(),
                height,
                header.map(|h| h.time()),
                satoshi,
                fee,
                self.network.id().get_bitcoin_network().unwrap_or(bitcoin::Network::Bitcoin),
            );

            txs.push(tx_meta);
        }
        txs.sort_by(|a, b| {
            b.height.unwrap_or(std::u32::MAX).cmp(&a.height.unwrap_or(std::u32::MAX))
        });
        Ok(txs)
    }

    fn utxos(&self) -> Result<Vec<(BEOutPoint, (String, u64))>, Error> {
        debug!("start utxos");
        let (spent, all_txs) = self.db.get_all_spent_and_txs()?;
        let all_scripts = self.db.get_all_scripts()?;
        let all_unblinded = self.db.get_all_unblinded()?; // empty map if not liquid

        let mut utxos = vec![];
        for tx_id in self.db.get_only_txids()? {
            let tx = all_txs.get(&tx_id).ok_or_else(fn_err("no tx"))?;
            let tx_utxos: Vec<(BEOutPoint, (String, u64))> = match tx {
                BETransaction::Bitcoin(tx) => tx
                    .output
                    .clone()
                    .into_iter()
                    .enumerate()
                    .map(|(vout, output)| (BEOutPoint::new_bitcoin(tx.txid(), vout as u32), output))
                    .filter(|(_, output)| all_scripts.contains(&output.script_pubkey))
                    .filter(|(outpoint, _)| !spent.contains(&outpoint))
                    .map(|(outpoint, output)| (outpoint, ("btc".to_string(), output.value)))
                    .collect(),
                BETransaction::Elements(tx) => tx
                    .output
                    .clone()
                    .into_iter()
                    .enumerate()
                    .map(|(vout, output)| {
                        (BEOutPoint::new_elements(tx.txid(), vout as u32), output)
                    })
                    .filter(|(_, output)| all_scripts.contains(&output.script_pubkey))
                    .filter(|(outpoint, _)| !spent.contains(&outpoint))
                    .filter_map(|(outpoint, _)| {
                        if let BEOutPoint::Elements(el_outpoint) = outpoint {
                            if let Some(unblinded) = all_unblinded.get(&el_outpoint) {
                                return Some((
                                    outpoint,
                                    (
                                        unblinded.asset_hex(self.network.policy_asset.as_ref()),
                                        unblinded.value,
                                    ),
                                ));
                            }
                        }
                        None
                    })
                    .collect(),
            };
            utxos.extend(tx_utxos);
        }
        utxos.sort_by(|a, b| (b.1).1.cmp(&(a.1).1));

        Ok(utxos)
    }

    pub fn balance(&self) -> Result<Balances, Error> {
        debug!("start balance");
        let mut result = HashMap::new();
        result.entry("btc".to_string()).or_insert(0);
        for (_, (asset, value)) in self.utxos()?.iter() {
            let asset_btc = if Some(asset) == self.network.policy_asset.as_ref() {
                "btc".to_string()
            } else {
                asset.to_string()
            };
            *result.entry(asset_btc).or_default() += *value as i64;
        }
        Ok(result)
    }

    // If request.utxo is None, we do the coin selection
    pub fn create_tx(&self, request: &CreateTransaction) -> Result<TransactionMeta, Error> {
        debug!("create_tx {:?}", request);

        let mut tx = BETransaction::new(self.network.id());
        let policy_asset = self.network.policy_asset().ok();

        let fee_rate = (request.fee_rate.unwrap_or(1000) as f64) / 1000.0 * 1.3; //TODO 30% increase hack because we compute fee badly

        let mut fee_val = 0;
        let mut outgoing: u64 = 0;

        let calc_fee_bytes = |bytes| ((bytes as f64) * fee_rate) as u64;
        fee_val += calc_fee_bytes(tx.get_weight() / 4);

        for out in request.addressees.iter() {
            let len = tx
                .add_output(&out.address, out.satoshi, self.network.policy_asset().ok())
                .map_err(|_| Error::InvalidAddress)?;
            fee_val += calc_fee_bytes(len);

            outgoing += out.satoshi;
        }

        let mut utxos = self.utxos()?;
        debug!("utxos len:{}", utxos.len());

        let mut selected_amount: u64 = 0;
        while selected_amount < outgoing + fee_val {
            debug!("selected_amount:{} outgoing:{} fee_val:{}", selected_amount, outgoing, fee_val);
            let (outpoint, (_, value)) = utxos.pop().ok_or(Error::InsufficientFunds)?;

            let len = tx.add_input(outpoint);
            fee_val += calc_fee_bytes(len + 70); // TODO: adjust 70 based on the signature size

            selected_amount += value;
        }

        let change_val = selected_amount - outgoing - fee_val;
        if change_val > 546 {
            let change_index = self.db.increment_index(Index::Internal)?;
            let change_address = self.derive_address(&self.xpub, &[1, change_index])?.to_string();
            debug!("adding change {:?}", change_address);

            tx.add_output(&change_address, change_val, policy_asset)?;
        }
        tx.add_fee_if_elements(fee_val, policy_asset);

        let mut created_tx = TransactionMeta::new(
            tx, //TODO
            None,
            None,
            HashMap::new(), //TODO
            fee_val,
            self.network.id().get_bitcoin_network().unwrap_or(bitcoin::Network::Bitcoin),
        );
        created_tx.create_transaction = Some(request.clone());
        debug!("returning: {:?}", created_tx);

        Ok(created_tx)
    }

    // TODO when we can serialize psbt
    //pub fn sign(&self, psbt: PartiallySignedTransaction) -> Result<PartiallySignedTransaction, Error> { Err(Error::Generic("NotImplemented".to_string())) }

    fn internal_sign(
        &self,
        tx: &Transaction,
        input_index: usize,
        path: &DerivationPath,
        value: u64,
    ) -> (PublicKey, Vec<u8>) {
        let privkey = self.xprv.derive_priv(&self.secp, &path).unwrap();
        let pubkey = ExtendedPubKey::from_private(&self.secp, &privkey);

        let witness_script = Address::p2pkh(&pubkey.public_key, pubkey.network).script_pubkey();

        let hash =
            SighashComponents::new(tx).sighash_all(&tx.input[input_index], &witness_script, value);

        let signature = self
            .secp
            .sign(&Message::from_slice(&hash.into_inner()[..]).unwrap(), &privkey.private_key.key);

        //let mut signature = signature.serialize_der().to_vec();
        let mut signature = hex::decode(&format!("{:?}", signature)).unwrap();
        signature.push(0x01 as u8); // TODO how to properly do this?

        (pubkey.public_key, signature)
    }

    pub fn sign(&self, request: &TransactionMeta) -> Result<TransactionMeta, Error> {
        debug!("sign");

        match &request.transaction {
            BETransaction::Bitcoin(tx) => {
                let mut out_tx = tx.clone();

                for i in 0..tx.input.len() {
                    let prev_output = tx.input[i].previous_output.clone();
                    debug!("input#{} prev_output:{:?}", i, prev_output);
                    let prev_tx = self
                        .db
                        .get_bitcoin_tx(&prev_output.txid)?
                        .ok_or_else(|| Error::Generic("cannot find tx in db".into()))?;
                    let out = prev_tx.output[prev_output.vout as usize].clone();
                    let derivation_path = self
                        .db
                        .get_path(&out.script_pubkey)?
                        .ok_or_else(|| Error::Generic("can't find derivation path".into()))?
                        .to_derivation_path()?;
                    debug!(
                        "input#{} prev_output:{:?} derivation_path:{:?}",
                        i, prev_output, derivation_path
                    );

                    let (pk, sig) = self.internal_sign(&tx, i, &derivation_path, out.value);
                    let script_sig = script_sig(&pk);
                    let witness = vec![sig, pk.to_bytes()];

                    out_tx.input[i].script_sig = script_sig;
                    out_tx.input[i].witness = witness;
                }

                let wgtx: TransactionMeta = BETransaction::Bitcoin(out_tx).into();

                Ok(wgtx)
            }
            BETransaction::Elements(tx) => {
                let mut out_tx = tx.clone();
                self.blind_tx(&mut out_tx)?;
                let wgtx: TransactionMeta = BETransaction::Elements(out_tx).into();

                Ok(wgtx)
            }
        }
    }

    fn blind_tx(&self, tx: &mut elements::Transaction) -> Result<(), Error> {
        debug!("blind_tx {}", tx.txid());
        let mut input_assets = vec![];
        let mut input_abfs = vec![];
        let mut input_vbfs = vec![];
        let mut input_ags = vec![];
        let mut input_values = vec![];
        for input in tx.input.iter() {
            debug!("input {:?}", input);

            let unblinded = self
                .db
                .get_unblinded(&input.previous_output)?
                .ok_or_else(|| Error::Generic("cannot find unblinded values".into()))?;
            debug!("unblinded value: {} asset:{}", unblinded.value, hex::encode(&unblinded.asset[..]));

            input_values.push(unblinded.value);
            input_assets.extend(unblinded.asset.to_vec());
            input_abfs.extend(unblinded.abf.to_vec());
            input_vbfs.extend(unblinded.vbf.to_vec());
            let input_asset = asset_generator_from_bytes(&unblinded.asset, &unblinded.abf);
            input_ags.extend(elements::encode::serialize(&input_asset));
        }

        //let random_bytes = rand::thread_rng().gen::<[u8; 32]>().clone();
        let random_bytes = [11u8; 32];
        let min_value = 1;
        let ct_exp = 0;
        let ct_bits = 52;

        let mut output_blinded_values = vec![];
        for output in tx.output.iter() {
            if !output.is_fee() {
                output_blinded_values.push(output.minimum_value());
            }
        }
        debug!("output_blinded_values {:?}", output_blinded_values);
        let mut all_values = vec![];
        all_values.extend(input_values);
        all_values.extend(output_blinded_values);
        let in_num = tx.input.len();
        let out_num = tx.output.len();

        let output_abfs: Vec<Vec<u8>> = (0..out_num - 1).map(|_| random_bytes.to_vec()).collect();
        let mut output_vbfs: Vec<Vec<u8>> =
            (0..out_num - 2).map(|_| random_bytes.to_vec()).collect();

        let mut all_abfs = vec![];
        all_abfs.extend(input_abfs.to_vec());
        all_abfs.extend(output_abfs.iter().cloned().flatten().collect::<Vec<u8>>());

        let mut all_vbfs = vec![];
        all_vbfs.extend(input_vbfs.to_vec());
        all_vbfs.extend(output_vbfs.iter().cloned().flatten().collect::<Vec<u8>>());

        let last_vbf = asset_final_vbf(all_values, in_num as u32, all_abfs, all_vbfs);
        output_vbfs.push(last_vbf.to_vec());

        for (i, mut output) in tx.output.iter_mut().enumerate() {
            debug!("output {:?}", output);
            if !output.is_fee() {
                match (output.value, output.asset, output.nonce) {
                    (Value::Explicit(value), Asset::Explicit(asset), Nonce::Confidential(_, _)) => {
                        let nonce = elements::encode::serialize(&output.nonce);
                        let blinding_pubkey = PublicKey::from_slice(&nonce).unwrap();
                        let blinding_key = asset_blinding_key_to_ec_private_key(
                            self.master_blinding.as_ref().unwrap(),
                            &output.script_pubkey,
                        );
                        let mut output_abf = [0u8; 32];
                        output_abf.copy_from_slice(&(&output_abfs[i])[..]);
                        let mut output_vbf = [0u8; 32];
                        output_vbf.copy_from_slice(&(&output_vbfs[i])[..]);
                        let asset = asset.clone().into_inner();

                        let output_generator = asset_generator_from_bytes(&asset, &output_abf);
                        let output_value_commitment =
                            asset_value_commitment(value, output_vbf, output_generator);

                        let rangeproof = asset_rangeproof(
                            value,
                            blinding_pubkey.key,
                            blinding_key,
                            asset,
                            output_abf,
                            output_vbf,
                            output_value_commitment,
                            &output.script_pubkey,
                            output_generator,
                            min_value,
                            ct_exp,
                            ct_bits,
                        );
                        debug!("asset: {}", hex::encode(&asset));
                        debug!("output_abf: {}", hex::encode(&output_abf));
                        debug!(
                            "output_generator: {}",
                            hex::encode(&elements::encode::serialize(&output_generator))
                        );
                        debug!("random_bytes: {}", hex::encode(&random_bytes));
                        debug!("input_assets: {}", hex::encode(&input_assets));
                        debug!("input_abfs: {}", hex::encode(&input_abfs));
                        debug!("input_ags: {}", hex::encode(&input_ags));
                        debug!("in_num: {}", in_num);

                        let surjectionproof = asset_surjectionproof(
                            asset,
                            output_abf,
                            output_generator,
                            random_bytes,
                            &input_assets,
                            &input_abfs,
                            &input_ags,
                            in_num,
                        );
                        debug!("surjectionproof: {}", hex::encode(&surjectionproof));

                        output.asset = output_generator;
                        output.value = output_value_commitment;
                        output.witness.surjection_proof = surjectionproof;
                        output.witness.rangeproof = rangeproof;
                    }
                    _ => panic!("create_tx created things not right"),
                }
            }
        }
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
        let index = self.db.increment_index(Index::External)?;
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
}

fn script_sig(public_key: &PublicKey) -> Script {
    let internal = Builder::new()
        .push_int(0)
        .push_slice(&PubkeyHash::hash(&public_key.to_bytes())[..])
        .into_script();
    Builder::new().push_slice(internal.as_bytes()).into_script()
}

#[cfg(test)]
mod test {
    use crate::interface::script_sig;
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::hash160;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{All, Message, Secp256k1, SecretKey};
    use bitcoin::util::bip143::SighashComponents;
    use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
    use bitcoin::util::key::PrivateKey;
    use bitcoin::util::key::PublicKey;
    use bitcoin::Script;
    use bitcoin::{Address, Network, Transaction};
    use std::str::FromStr;

    fn p2pkh_hex(pk: &str) -> (PublicKey, Script) {
        let pk = hex::decode(pk).unwrap();
        let pk = PublicKey::from_slice(pk.as_slice()).unwrap();
        let witness_script = Address::p2pkh(&pk, Network::Bitcoin).script_pubkey();
        (pk, witness_script)
    }

    #[test]
    fn test_bip() {
        let secp: Secp256k1<All> = Secp256k1::gen_new();

        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
        let tx_bytes = hex::decode("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000").unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let private_key_bytes =
            hex::decode("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")
                .unwrap();

        let key = SecretKey::from_slice(&private_key_bytes).unwrap();
        let private_key = PrivateKey {
            compressed: true,
            network: Network::Testnet,
            key,
        };

        let (public_key, witness_script) =
            p2pkh_hex("03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");
        assert_eq!(
            hex::encode(witness_script.to_bytes()),
            "76a91479091972186c449eb1ded22b78e40d009bdf008988ac"
        );
        let value = 1_000_000_000;
        let comp = SighashComponents::new(&tx);
        let hash = comp.sighash_all(&tx.input[0], &witness_script, value).into_inner();

        assert_eq!(
            &hash[..],
            &hex::decode("64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6")
                .unwrap()[..],
        );

        let signature = secp.sign(&Message::from_slice(&hash[..]).unwrap(), &private_key.key);

        //let mut signature = signature.serialize_der().to_vec();
        let signature_hex = format!("{:?}01", signature); // add sighash type at the end
        assert_eq!(signature_hex, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01");

        let script_sig = script_sig(&public_key);

        assert_eq!(
            format!("{}", hex::encode(script_sig.as_bytes())),
            "16001479091972186c449eb1ded22b78e40d009bdf0089"
        );
    }

    #[test]
    fn test_my_tx() {
        let secp: Secp256k1<All> = Secp256k1::gen_new();
        let xprv = ExtendedPrivKey::from_str("tprv8jdzkeuCYeH5hi8k2JuZXJWV8sPNK62ashYyUVD9Euv5CPVr2xUbRFEM4yJBB1yBHZuRKWLeWuzH4ptmvSgjLj81AvPc9JhV4i8wEfZYfPb").unwrap();
        let xpub = ExtendedPubKey::from_private(&secp, &xprv);
        let private_key = xprv.private_key;
        let public_key = xpub.public_key;
        let public_key_bytes = public_key.to_bytes();
        let public_key_str = format!("{}", hex::encode(&public_key_bytes));

        let address = Address::p2shwpkh(&public_key, Network::Testnet);
        assert_eq!(format!("{}", address), "2NCEMwNagVAbbQWNfu7M7DNGxkknVTzhooC");

        assert_eq!(
            public_key_str,
            "0386fe0922d694cef4fa197f9040da7e264b0a0ff38aa2e647545e5a6d6eab5bfc"
        );
        let tx_hex = "020000000001010e73b361dd0f0320a33fd4c820b0c7ac0cae3b593f9da0f0509cc35de62932eb01000000171600141790ee5e7710a06ce4a9250c8677c1ec2843844f0000000002881300000000000017a914cc07bc6d554c684ea2b4af200d6d988cefed316e87a61300000000000017a914fda7018c5ee5148b71a767524a22ae5d1afad9a9870247304402206675ed5fb86d7665eb1f7950e69828d0aa9b41d866541cedcedf8348563ba69f022077aeabac4bd059148ff41a36d5740d83163f908eb629784841e52e9c79a3dbdb01210386fe0922d694cef4fa197f9040da7e264b0a0ff38aa2e647545e5a6d6eab5bfc00000000";

        let tx_bytes = hex::decode(tx_hex).unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let (_, witness_script) = p2pkh_hex(&public_key_str);
        assert_eq!(
            hex::encode(witness_script.to_bytes()),
            "76a9141790ee5e7710a06ce4a9250c8677c1ec2843844f88ac"
        );
        let value = 10_202;
        let comp = SighashComponents::new(&tx);
        let hash = comp.sighash_all(&tx.input[0], &witness_script, value);

        assert_eq!(
            &hash.into_inner()[..],
            &hex::decode("58b15613fc1701b2562430f861cdc5803531d08908df531082cf1828cd0b8995")
                .unwrap()[..],
        );

        let signature = secp.sign(&Message::from_slice(&hash[..]).unwrap(), &private_key.key);

        //let mut signature = signature.serialize_der().to_vec();
        let signature_hex = format!("{:?}01", signature); // add sighash type at the end
        let signature = hex::decode(&signature_hex).unwrap();

        assert_eq!(signature_hex, "304402206675ed5fb86d7665eb1f7950e69828d0aa9b41d866541cedcedf8348563ba69f022077aeabac4bd059148ff41a36d5740d83163f908eb629784841e52e9c79a3dbdb01");
        assert_eq!(tx.input[0].witness[0], signature);
        assert_eq!(tx.input[0].witness[1], public_key_bytes);

        let script_sig = script_sig(&public_key);
        assert_eq!(tx.input[0].script_sig, script_sig);
    }
}
