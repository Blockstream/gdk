use gdk_common::bitcoin::blockdata::script::Builder as ScriptBuilder;
use gdk_common::bitcoin::hashes::hex::{FromHex, ToHex};
use gdk_common::bitcoin::hashes::Hash;
use gdk_common::bitcoin::network::constants::Network as Bip32Network;
use gdk_common::bitcoin::secp256k1::{All, Message, Secp256k1};
use gdk_common::bitcoin::util::address::Address;
use gdk_common::bitcoin::util::bip32::{DerivationPath, ExtendedPrivKey, ExtendedPubKey};
use gdk_common::bitcoin::util::sighash::SighashCache;
use gdk_common::bitcoin::{self, EcdsaSighashType, Witness};
use gdk_common::EC;

use gdk_common::be::BETransaction;
use gdk_common::model::*;
use gdk_common::wally::{self, asset_blinding_key_from_seed, MasterBlindingKey};

/// Struct that holds the secret, so that we can replicate the resolver behavior
pub struct TestSigner {
    pub credentials: Credentials,
    pub network: Bip32Network,
    is_liquid: bool,
    secp: Secp256k1<All>,
}

impl TestSigner {
    pub fn new(credentials: &Credentials, network: Bip32Network, is_liquid: bool) -> Self {
        TestSigner {
            credentials: credentials.clone(),
            network,
            is_liquid,
            secp: EC.clone(),
        }
    }
    fn seed(&self) -> [u8; 64] {
        wally::bip39_mnemonic_to_seed(&self.credentials.mnemonic, "").unwrap()
    }

    fn master_xprv(&self) -> ExtendedPrivKey {
        ExtendedPrivKey::new_master(self.network, &self.seed()).unwrap()
    }

    pub(crate) fn master_xpub(&self) -> ExtendedPubKey {
        ExtendedPubKey::from_priv(&self.secp, &self.master_xprv())
    }

    pub fn master_blinding(&self) -> MasterBlindingKey {
        asset_blinding_key_from_seed(&self.seed())
    }

    pub fn account_xpub(&self, path: &DerivationPath) -> ExtendedPubKey {
        let xprv = self.master_xprv().derive_priv(&self.secp, path).unwrap();
        ExtendedPubKey::from_priv(&self.secp, &xprv)
    }

    pub fn sign_tx(&self, details: &TransactionMeta) -> TransactionMeta {
        let be_tx: BETransaction = if self.is_liquid {
            // FIXME: sort out what we need to do with blinding and implement this
            unimplemented!();
        } else {
            let tx: bitcoin::Transaction =
                bitcoin::consensus::deserialize(&Vec::<u8>::from_hex(&details.hex).unwrap())
                    .unwrap();
            let mut out_tx = tx.clone();

            let num_inputs = tx.input.len();
            assert_eq!(details.used_utxos.len(), num_inputs);

            for i in 0..num_inputs {
                if details.used_utxos[i].skip_signing {
                    continue;
                }
                let utxo = &details.used_utxos[i];

                let path: DerivationPath = utxo.user_path.clone().into();
                let private_key =
                    self.master_xprv().derive_priv(&self.secp, &path).unwrap().to_priv();
                let sighash = utxo.sighash.unwrap_or(EcdsaSighashType::All as u32);
                let sighash = EcdsaSighashType::from_standard(sighash).unwrap();

                // Optional sanity checks
                let public_key = private_key.public_key(&self.secp);
                assert_eq!(utxo.public_key, public_key.to_string());
                let script_code =
                    Address::p2pkh(&public_key, Bip32Network::Regtest).script_pubkey();
                assert_eq!(utxo.script_code, script_code.to_hex());

                let signature_hash = if utxo.address_type != "p2pkh" {
                    SighashCache::new(&tx)
                        .segwit_signature_hash(i, &script_code, utxo.satoshi, sighash)
                        .unwrap()
                } else {
                    tx.signature_hash(i, &script_code, sighash.to_u32())
                };

                let message = Message::from_slice(&signature_hash.into_inner()[..]).unwrap();
                let signature = self.secp.sign_ecdsa(&message, &private_key.inner);

                let mut der = signature.serialize_der().to_vec();
                der.push(sighash as u8);

                let pk = public_key.to_bytes();
                let (script_sig, witness) = match utxo.address_type.as_str() {
                    "p2pkh" => (
                        ScriptBuilder::new()
                            .push_slice(der.as_slice())
                            .push_slice(pk.as_slice())
                            .into_script(),
                        vec![],
                    ),
                    "p2sh-p2wpkh" => (
                        Address::p2shwpkh(&public_key, Bip32Network::Regtest)
                            .unwrap()
                            .script_pubkey(),
                        vec![der, pk],
                    ),
                    "p2wpkh" => (bitcoin::Script::new(), vec![der, pk]),
                    _ => unimplemented!(),
                };

                out_tx.input[i].script_sig = script_sig;
                out_tx.input[i].witness = Witness::from_vec(witness);
            }
            BETransaction::Bitcoin(out_tx)
        };

        let mut details_out: TransactionMeta = be_tx.into();
        // FIXME: set more fields
        details_out.fee = details.fee;
        details_out.create_transaction = details.create_transaction.clone();
        details_out.used_utxos = details.used_utxos.clone();
        details_out
    }
}
