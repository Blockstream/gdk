use serde::{Deserialize, Serialize};

use crate::error::*;

use electrum_client::{Client, ConfigBuilder, Socks5Config};
use gdk_common::electrum_client;
use gdk_common::network::NETWORK_REQUEST_TIMEOUT;
use std::net::ToSocketAddrs;
use std::str::FromStr;

#[derive(Clone, Serialize, Deserialize, Debug)]
pub enum ElectrumUrl {
    Tls(String, bool), // the bool value indicates if the domain name should be validated
    Plaintext(String),
}

impl ElectrumUrl {
    pub fn build_client(&self, proxy: Option<&str>, timeout: Option<u8>) -> Result<Client, Error> {
        let mut config = ConfigBuilder::new();

        // TODO: add support for socks5 credentials?
        if let Some(proxy) = proxy {
            if !proxy.trim().is_empty() {
                let mut proxy = proxy.replacen("socks5://", "", 1).to_string();
                if proxy.starts_with("localhost:") {
                    // Try to prevent issues with "localhost" resolving incorrectly
                    proxy = proxy.replacen("localhost:", "127.0.0.1:", 1);
                }
                if proxy.to_socket_addrs().is_err() {
                    return Err(Error::InvalidProxySocket(proxy.to_string()));
                }
                config = config.socks5(Some(Socks5Config::new(proxy)));
            }
        }

        let timeout = timeout.unwrap_or(NETWORK_REQUEST_TIMEOUT.as_secs() as u8);

        config = config.timeout(Some(timeout));

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
    use gdk_common::bitcoin::bip32::{Xpriv, Xpub};
    use gdk_common::bitcoin::consensus::deserialize;
    use gdk_common::bitcoin::hashes::hex::FromHex;
    use gdk_common::bitcoin::hashes::Hash;
    use gdk_common::bitcoin::key::CompressedPublicKey;
    use gdk_common::bitcoin::key::PrivateKey;
    use gdk_common::bitcoin::secp256k1::{Message, SecretKey};
    use gdk_common::bitcoin::sighash::{EcdsaSighashType, SighashCache};
    use gdk_common::bitcoin::Amount;
    use gdk_common::bitcoin::{Address, Network, NetworkKind, Transaction};
    use gdk_common::scripts::p2shwpkh_script_sig;
    use std::str::FromStr;

    use super::*;

    #[test]
    fn test_bip() {
        // https://github.com/bitcoin/bips/blob/master/bip-0143.mediawiki#p2sh-p2wpkh
        let tx_bytes = Vec::<u8>::from_hex("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000").unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let private_key_bytes =
            Vec::<u8>::from_hex("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf")
                .unwrap();

        let inner = SecretKey::from_slice(&private_key_bytes).unwrap();
        let private_key = PrivateKey {
            compressed: true,
            network: NetworkKind::Test,
            inner,
        };

        let public_key = Vec::<u8>::from_hex(
            "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873",
        )
        .unwrap();
        let public_key = CompressedPublicKey::from_slice(public_key.as_slice()).unwrap();
        let script_pubkey = Address::p2wpkh(&public_key, Network::Bitcoin).script_pubkey();
        assert_eq!(script_pubkey.to_hex_string(), "001479091972186c449eb1ded22b78e40d009bdf0089");
        let value = Amount::from_sat(1_000_000_000);
        let hash = SighashCache::new(&tx)
            .p2wpkh_signature_hash(0, &script_pubkey, value, EcdsaSighashType::All)
            .unwrap();

        assert_eq!(
            &hash.to_string(),
            "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6"
        );

        let signature = crate::EC.sign_ecdsa(
            &Message::from_digest(hash.to_raw_hash().to_byte_array()),
            &private_key.inner,
        );

        //let mut signature = signature.serialize_der().to_vec();
        let signature_hex = format!("{:?}01", signature); // add sighash type at the end
        assert_eq!(signature_hex, "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01");

        let script_sig = p2shwpkh_script_sig(&public_key);

        assert_eq!(script_sig.to_hex_string(), "16001479091972186c449eb1ded22b78e40d009bdf0089");
    }

    #[test]
    fn test_my_tx() {
        let xprv = Xpriv::from_str("tprv8jdzkeuCYeH5hi8k2JuZXJWV8sPNK62ashYyUVD9Euv5CPVr2xUbRFEM4yJBB1yBHZuRKWLeWuzH4ptmvSgjLj81AvPc9JhV4i8wEfZYfPb").unwrap();
        let xpub = Xpub::from_priv(&crate::EC, &xprv);
        let private_key = xprv.to_priv();
        let public_key = xpub.to_pub();
        let public_key_bytes = public_key.to_bytes();
        let public_key_str = format!("{}", public_key);

        let address = Address::p2shwpkh(&public_key, Network::Testnet);
        assert_eq!(format!("{}", address), "2NCEMwNagVAbbQWNfu7M7DNGxkknVTzhooC");

        assert_eq!(
            public_key_str,
            "0386fe0922d694cef4fa197f9040da7e264b0a0ff38aa2e647545e5a6d6eab5bfc"
        );
        let tx_hex = "020000000001010e73b361dd0f0320a33fd4c820b0c7ac0cae3b593f9da0f0509cc35de62932eb01000000171600141790ee5e7710a06ce4a9250c8677c1ec2843844f0000000002881300000000000017a914cc07bc6d554c684ea2b4af200d6d988cefed316e87a61300000000000017a914fda7018c5ee5148b71a767524a22ae5d1afad9a9870247304402206675ed5fb86d7665eb1f7950e69828d0aa9b41d866541cedcedf8348563ba69f022077aeabac4bd059148ff41a36d5740d83163f908eb629784841e52e9c79a3dbdb01210386fe0922d694cef4fa197f9040da7e264b0a0ff38aa2e647545e5a6d6eab5bfc00000000";

        let tx_bytes = Vec::<u8>::from_hex(tx_hex).unwrap();
        let tx: Transaction = deserialize(&tx_bytes).unwrap();

        let script_pubkey = Address::p2wpkh(&public_key, Network::Bitcoin).script_pubkey();
        let value = Amount::from_sat(10_202);
        let hash = SighashCache::new(&tx)
            .p2wpkh_signature_hash(0, &script_pubkey, value, EcdsaSighashType::All)
            .unwrap();

        assert_eq!(
            hash.to_string(),
            "58b15613fc1701b2562430f861cdc5803531d08908df531082cf1828cd0b8995",
        );

        let signature = crate::EC.sign_ecdsa(
            &Message::from_digest(hash.to_raw_hash().to_byte_array()),
            &private_key.inner,
        );

        //let mut signature = signature.serialize_der().to_vec();
        let signature_hex = format!("{:?}01", signature); // add sighash type at the end
        let signature = Vec::<u8>::from_hex(&signature_hex).unwrap();

        assert_eq!(signature_hex, "304402206675ed5fb86d7665eb1f7950e69828d0aa9b41d866541cedcedf8348563ba69f022077aeabac4bd059148ff41a36d5740d83163f908eb629784841e52e9c79a3dbdb01");
        let witness = tx.input[0].witness.to_vec();
        assert_eq!(witness[0], signature);
        assert_eq!(witness[1], public_key_bytes);

        let script_sig = p2shwpkh_script_sig(&public_key);
        assert_eq!(tx.input[0].script_sig, script_sig);
    }

    /// Tests that passing an invalid proxy to `ElectrumUrl::build_client()`
    /// immediately results in an error.
    #[test]
    fn invalid_proxy() {
        let url = ElectrumUrl::Plaintext(String::new());
        let invalid_proxy = "invalid_proxy";

        assert!(matches!(
            url.build_client(Some(&invalid_proxy), None),
            Err(Error::InvalidProxySocket(p)) if p == invalid_proxy
        ));
    }

    #[test]
    fn valid_proxy() {
        let url = ElectrumUrl::Plaintext(String::new());

        // `build_client()` can still return an error, here we're just checking
        // that the error it returns (if any) is not caused by an incorrectly
        // formatted proxy.

        for valid_proxy in ["127.0.0.1:9050", "socks5://127.0.0.1:9050", "localhost:9050"] {
            assert!(!matches!(
                url.build_client(Some(valid_proxy), None),
                Err(Error::InvalidProxySocket(_))
            ));
        }
    }
}
