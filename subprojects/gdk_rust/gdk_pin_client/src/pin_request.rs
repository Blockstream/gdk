use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{
    ecdh::SharedSecret, ecdsa::Signature, Message, PublicKey, Secp256k1, SecretKey,
};
use bitcoin_private::hex::exts::DisplayHex;
use block_modes::BlockMode;
use once_cell::sync::Lazy;

use crate::crypto::{Aes256Cbc, ClientKey, Salt};
use crate::{Pin, Result};

static EC: Lazy<Secp256k1<bitcoin::secp256k1::All>> = Lazy::new(|| {
    let mut ctx = Secp256k1::new();
    let mut rng = rand::thread_rng();
    ctx.randomize(&mut rng);
    ctx
});

#[derive(Debug, serde::Serialize)]
pub(crate) struct PinServerRequest {
    cke: String,
    encrypted_data: String,
    hmac_encrypted_data: String,
    ske: String,
}

impl PinServerRequest {
    pub(crate) fn new(
        pin: &Pin,
        client_key: &ClientKey,
        encryption_key: &RequestEncryptionKey,
    ) -> Result<Self> {
        let hashed_pin = sha256::Hash::hash(pin.as_bytes());

        let salt = Salt::<32>::new();

        let serialized_cke = encryption_key.cke.serialize();

        let data = {
            let mut v = Vec::<u8>::with_capacity(97);
            v.extend(&serialized_cke);
            v.extend(&hashed_pin[..]);
            v.extend(salt.as_bytes());
            assert_eq!(97, v.len());
            v
        };

        let payload = {
            let hashed_data = sha256::Hash::hash(&data);

            let message = Message::from_slice(&hashed_data.as_ref())?;

            let (recovery_id, signature) =
                EC.sign_ecdsa_recoverable(&message, client_key.secret_key()).serialize_compact();

            let mut v = Vec::<u8>::with_capacity(129);
            v.extend(&hashed_pin[..]);
            v.extend(salt.as_bytes());
            v.push((31 + recovery_id.to_i32()) as u8);
            v.extend(&signature[..]);
            assert_eq!(129, v.len());
            v
        };

        let encrypted_data = {
            let salt = Salt::<16>::new();

            let cipher =
                Aes256Cbc::new_from_slices(&encryption_key.encryption_key[..], salt.as_bytes())
                    .expect("Both the encryption key and the salt have the right length");

            let mut v = Vec::<u8>::new();
            v.extend(salt.as_bytes());
            v.extend(&cipher.encrypt_vec(&payload));
            v
        };

        let auth_payload = {
            let mut v = Vec::<u8>::new();
            v.extend(&serialized_cke);
            v.extend(&encrypted_data);
            v
        };

        let hmac_encrypted_data = {
            let mut engine = HmacEngine::<sha256::Hash>::new(&encryption_key.hmac_key[..]);
            engine.input(&auth_payload);
            Hmac::from_engine(engine)
        };

        Ok(Self {
            ske: encryption_key.ske.serialize().to_lower_hex_string(),
            cke: serialized_cke.to_lower_hex_string(),
            encrypted_data: encrypted_data.to_lower_hex_string(),
            hmac_encrypted_data: hmac_encrypted_data.as_byte_array().to_lower_hex_string(),
        })
    }
}

#[derive(Debug, serde::Deserialize)]
pub(crate) struct HandShake {
    #[serde(rename = "sig", deserialize_with = "deserialize_ecdsa_signature_from_hex")]
    signature: Signature,

    #[serde(deserialize_with = "deserialize_secp_pubkey_from_hex")]
    ske: (PublicKey, sha256::Hash),
}

impl HandShake {
    /// Verifies this [`HandShake`] against the public key of the PIN server,
    /// which should match the one passed to [`PinClient::new`].
    pub(crate) fn verify(&self, pin_server_public_key: &bitcoin::PublicKey) -> Result<()> {
        let ske_hash = &self.ske.1;
        let message = Message::from_slice(ske_hash.as_ref())?;
        Ok(EC.verify_ecdsa(&message, &self.signature, &pin_server_public_key.inner)?)
    }

    /// Generates a `(encryption_key, decryption_key)` keypair used to encrypt
    /// the request sent to the PIN server and to decrypt the response obtained
    /// by the PIN server, respectively.
    ///
    /// This function consumes `Self` because a [`HandShake`] is only valid for
    /// a single request-response cycle. The following request should generate
    /// a new handshake.
    pub(crate) fn generate_keys(self) -> (RequestEncryptionKey, ResponseDecryptionKey) {
        let secret_key = SecretKey::new(&mut rand::thread_rng());

        let shared_secret = { SharedSecret::new(&self.ske.0, &secret_key) };

        let encryption_key = RequestEncryptionKey {
            ske: self.ske.0,
            cke: PublicKey::from_secret_key(&EC, &secret_key),
            encryption_key: derive(0, &shared_secret),
            hmac_key: derive(1, &shared_secret),
        };

        let decryption_key = ResponseDecryptionKey {
            decryption_key: derive(2, &shared_secret),
            hmac_key: derive(3, &shared_secret),
        };

        (encryption_key, decryption_key)
    }
}

fn derive(value: u8, key: &SharedSecret) -> Hmac<sha256::Hash> {
    let mut engine = HmacEngine::<sha256::Hash>::new(&key.secret_bytes()[..]);
    engine.input(&[value]);
    Hmac::from_engine(engine)
}

/// The 1st half of [`HandShake::generate_key`]'s output.
///
/// Can be passed to [`PinServerRequest::new`] to generate a new request for
/// the PIN server.
pub(crate) struct RequestEncryptionKey {
    ske: PublicKey,
    cke: PublicKey,
    encryption_key: Hmac<sha256::Hash>,
    hmac_key: Hmac<sha256::Hash>,
}

/// The 2nd half of [`HandShake::generate_key`]'s output.
///
/// Can be passed to [`PinServerResponse::decrypt_server_key`] to decrypt the
/// server key contained in the PIN server response.
pub(crate) struct ResponseDecryptionKey {
    decryption_key: Hmac<sha256::Hash>,
    hmac_key: Hmac<sha256::Hash>,
}

impl ResponseDecryptionKey {
    /// Allows to create a [`ResponseDecryptionKey`] from other modules when
    /// testing while still keeping its fields private.
    #[cfg(test)]
    pub(crate) fn new(decryption_key: Hmac<sha256::Hash>, hmac_key: Hmac<sha256::Hash>) -> Self {
        Self {
            decryption_key,
            hmac_key,
        }
    }

    pub(crate) fn decryption_key(&self) -> &Hmac<sha256::Hash> {
        &self.decryption_key
    }

    pub(crate) fn hmac_key(&self) -> &Hmac<sha256::Hash> {
        &self.hmac_key
    }
}

/// Deserializes an ECDSA [`Signature`] from a hex string.
fn deserialize_ecdsa_signature_from_hex<'de, D>(
    deserializer: D,
) -> std::result::Result<Signature, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    use serde::de::Error;

    let bytes = deserialize_bytes_from_hex(deserializer)?;
    Signature::from_compact(&bytes).map_err(D::Error::custom)
}

/// Deserializes a Secp256k1 [`PublicKey`] from a hex string, returning the
/// `PublicKey` and its sha256 hash.
fn deserialize_secp_pubkey_from_hex<'de, D>(
    deserializer: D,
) -> std::result::Result<(PublicKey, sha256::Hash), D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    use serde::de::Error;

    let bytes = deserialize_bytes_from_hex(deserializer)?;

    let pub_key = bitcoin::PublicKey::from_slice(&bytes).map_err(D::Error::custom)?.inner;
    let hash = sha256::Hash::hash(&bytes);

    Ok((pub_key, hash))
}

/// Deserializes a Vec of bytes from a hex string.
pub(super) fn deserialize_bytes_from_hex<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    use bitcoin::hashes::hex::FromHex;
    use serde::de::{Deserialize, Error};
    let hex = String::deserialize(deserializer)?;
    Vec::<u8>::from_hex(&hex).map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde_json::json;

    use super::*;

    const PIN_SERVER_PROD_PUBLIC_KEY: &str =
        "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547";

    /// Tests that a handshake deserializes correctly from a JSON string and
    /// that it verifies against its PIN server public key.
    #[test]
    fn deserialize_handshake() {
        // Handshake taken from a random response from the production PIN
        // server.
        let json = json!({
            "sig": "004a58b09b6b4b6585536c5fbd662fb729a277426875a644fa56f5d05d6724281576f9d7844fc131102cd9d4fd56ca0b7f3cf9872379510407b3075f5c862c70",
            "ske": "032541c31f808a28750daf386e52ad70f16db153fa9e8375a6178021a0c7a74c09",
        });

        let handshake = serde_json::from_value::<HandShake>(json).unwrap();
        let pubkey = bitcoin::PublicKey::from_str(PIN_SERVER_PROD_PUBLIC_KEY).unwrap();

        assert!(handshake.verify(&pubkey).is_ok());
    }
}
