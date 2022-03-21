use serde::{Deserialize, Serialize};

use crate::error::*;

use electrum_client::{Client, ConfigBuilder};
use std::str::FromStr;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ElectrumUrl {
    Tls(String, bool), // the bool value indicates if the domain name should be validated
    Plaintext(String),
}

impl ElectrumUrl {
    /// returns error if both proxy and timeout are set
    pub fn build_client(&self, proxy: Option<&str>, timeout: Option<u8>) -> Result<Client, Error> {
        let mut config = ConfigBuilder::new();

        // TODO: add support for socks5 credentials?
        config = config.socks5(
            proxy.filter(|p| !p.trim().is_empty()).map(|p| electrum_client::Socks5Config::new(p)),
        )?;
        config = config.timeout(timeout)?;

        let (url, config) = match self {
            ElectrumUrl::Tls(url, validate) => {
                (format!("ssl://{}", url), config.validate_domain(*validate))
            }
            ElectrumUrl::Plaintext(url) => (format!("tcp://{}", url), config),
        };
        Ok(Client::from_config(&url, config.build())?)
    }

    pub fn url(&self) -> &str {
        match self {
            ElectrumUrl::Tls(url, _) => url,
            ElectrumUrl::Plaintext(url) => url,
        }
    }

    pub fn is_onion(&self) -> bool {
        match self {
            ElectrumUrl::Tls(_, _) => false,
            ElectrumUrl::Plaintext(url) => url.ends_with(".onion"),
        }
    }
}

// Parse the standard <host>:<port>:<t|s> string format,
// with an optional non-standard `:noverify` suffix to skip tls validation
impl FromStr for ElectrumUrl {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Error> {
        let mk_err = || Error::InvalidElectrumUrl(s.into());
        let mut parts = s.split(":");
        let hostname = parts.next().ok_or_else(mk_err)?;
        let port: u16 = parts.next().ok_or_else(mk_err)?.parse().map_err(|_| mk_err())?;
        let proto = parts.next().unwrap_or("t");
        let validate_tls = parts.next() != Some("noverify");

        let url = format!("{}:{}", hostname, port);
        Ok(match proto {
            "s" => ElectrumUrl::Tls(url, validate_tls),
            "t" => ElectrumUrl::Plaintext(url),
            _ => return Err(mk_err()),
        })
    }
}

#[cfg(test)]
mod test {
    use bitcoin::consensus::deserialize;
    use bitcoin::hashes::hex::{FromHex, ToHex};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::{Message, SecretKey};
    use bitcoin::util::bip143::SigHashCache;
    use bitcoin::util::bip32::{ExtendedPrivKey, ExtendedPubKey};
    use bitcoin::util::key::PrivateKey;
    use bitcoin::util::key::PublicKey;
    use bitcoin::Script;
    use bitcoin::{Address, Network, SigHashType, Transaction};
    use gdk_common::scripts::p2shwpkh_script_sig;
    use std::str::FromStr;

    fn p2pkh_hex(pk: &str) -> (PublicKey, Script) {
        let pk = Vec::<u8>::from_hex(pk).unwrap();
        let pk = PublicKey::from_slice(pk.as_slice()).unwrap();
        let witness_script = Address::p2pkh(&pk, Network::Bitcoin).script_pubkey();
        (pk, witness_script)
    }

    #[test]
    fn test_bip() {
        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
        let tx_bytes = Vec::<u8>::from_hex("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000").unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let private_key_bytes =
            Vec::<u8>::from_hex("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")
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
            witness_script.to_bytes().to_hex(),
            "76a91479091972186c449eb1ded22b78e40d009bdf008988ac"
        );
        let value = 1_000_000_000;
        let hash =
            SigHashCache::new(&tx).signature_hash(0, &witness_script, value, SigHashType::All);

        assert_eq!(
            &hash.into_inner().to_hex(),
            "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
        );

        let signature = crate::EC.sign(&Message::from_slice(&hash[..]).unwrap(), &private_key.key);

        //let mut signature = signature.serialize_der().to_vec();
        let signature_hex = format!("{:?}01", signature); // add sighash type at the end
        assert_eq!(signature_hex, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01");

        let script_sig = p2shwpkh_script_sig(&public_key);

        assert_eq!(
            script_sig.as_bytes().to_hex(),
            "16001479091972186c449eb1ded22b78e40d009bdf0089"
        );
    }

    #[test]
    fn test_my_tx() {
        let xprv = ExtendedPrivKey::from_str("tprv8jdzkeuCYeH5hi8k2JuZXJWV8sPNK62ashYyUVD9Euv5CPVr2xUbRFEM4yJBB1yBHZuRKWLeWuzH4ptmvSgjLj81AvPc9JhV4i8wEfZYfPb").unwrap();
        let xpub = ExtendedPubKey::from_private(&crate::EC, &xprv);
        let private_key = xprv.private_key;
        let public_key = xpub.public_key;
        let public_key_bytes = public_key.to_bytes();
        let public_key_str = public_key_bytes.to_hex();

        let address = Address::p2shwpkh(&public_key, Network::Testnet).unwrap();
        assert_eq!(format!("{}", address), "2NCEMwNagVAbbQWNfu7M7DNGxkknVTzhooC");

        assert_eq!(
            public_key_str,
            "0386fe0922d694cef4fa197f9040da7e264b0a0ff38aa2e647545e5a6d6eab5bfc"
        );
        let tx_hex = "020000000001010e73b361dd0f0320a33fd4c820b0c7ac0cae3b593f9da0f0509cc35de62932eb01000000171600141790ee5e7710a06ce4a9250c8677c1ec2843844f0000000002881300000000000017a914cc07bc6d554c684ea2b4af200d6d988cefed316e87a61300000000000017a914fda7018c5ee5148b71a767524a22ae5d1afad9a9870247304402206675ed5fb86d7665eb1f7950e69828d0aa9b41d866541cedcedf8348563ba69f022077aeabac4bd059148ff41a36d5740d83163f908eb629784841e52e9c79a3dbdb01210386fe0922d694cef4fa197f9040da7e264b0a0ff38aa2e647545e5a6d6eab5bfc00000000";

        let tx_bytes = Vec::<u8>::from_hex(tx_hex).unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let (_, witness_script) = p2pkh_hex(&public_key_str);
        assert_eq!(
            witness_script.to_bytes().to_hex(),
            "76a9141790ee5e7710a06ce4a9250c8677c1ec2843844f88ac"
        );
        let value = 10_202;
        let hash =
            SigHashCache::new(&tx).signature_hash(0, &witness_script, value, SigHashType::All);

        assert_eq!(
            hash.into_inner().to_hex(),
            "58b15613fc1701b2562430f861cdc5803531d08908df531082cf1828cd0b8995",
        );

        let signature = crate::EC.sign(&Message::from_slice(&hash[..]).unwrap(), &private_key.key);

        //let mut signature = signature.serialize_der().to_vec();
        let signature_hex = format!("{:?}01", signature); // add sighash type at the end
        let signature = Vec::<u8>::from_hex(&signature_hex).unwrap();

        assert_eq!(signature_hex, "304402206675ed5fb86d7665eb1f7950e69828d0aa9b41d866541cedcedf8348563ba69f022077aeabac4bd059148ff41a36d5740d83163f908eb629784841e52e9c79a3dbdb01");
        assert_eq!(tx.input[0].witness[0], signature);
        assert_eq!(tx.input[0].witness[1], public_key_bytes);

        let script_sig = p2shwpkh_script_sig(&public_key);
        assert_eq!(tx.input[0].script_sig, script_sig);
    }
}
