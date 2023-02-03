use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use serde::{Deserialize, Serialize};

use crate::crypto::{ClientKey, Salt, ServerKey};

/// Contains the encrypted data passed to `PinClient::encrypt` together with
/// some metadata used to decrypt with `PinClient::decrypt`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PinData {
    /// The plaintext data encrypted using the key obtained from the PIN server
    /// and the `salt`.
    #[serde(
        rename = "encrypted_data",
        serialize_with = "serialize_bytes_to_hex",
        deserialize_with = "crate::pin_request::deserialize_bytes_from_hex"
    )]
    encrypted_bytes: Vec<u8>,

    /// A client-generated key sent to the PIN server.
    #[serde(rename = "pin_identifier")]
    client_key: ClientKey,

    /// 16 random bytes added to `encrypted_bytes` during encryption.
    salt: Salt<16>,

    /// An Hmac constructed using the server key, the salt and the encrypted
    /// data. Used to validate the `ServerKey` returned by
    /// `PinClient::decrypt()`.
    ///
    /// It's wrapped in an `Option` to be backwards compatible with
    /// old `PinData`s that were serialized without this field.
    #[serde(default)]
    hmac: Option<Hmac<sha256::Hash>>,
}

impl PinData {
    pub(crate) fn new(
        encrypted_bytes: Vec<u8>,
        client_key: ClientKey,
        salt: Salt<16>,
        server_key: &ServerKey,
    ) -> Self {
        let hmac = Self::get_hmac(server_key, &salt, &encrypted_bytes);

        Self {
            encrypted_bytes,
            client_key,
            salt,
            hmac: Some(hmac),
        }
    }

    pub(crate) fn get_hmac(
        server_key: &ServerKey,
        salt: &Salt<16>,
        encrypted: &[u8],
    ) -> Hmac<sha256::Hash> {
        let mut engine = HmacEngine::<sha256::Hash>::new(server_key.as_bytes());
        engine.input(salt.as_bytes());
        engine.input(&*encrypted);
        Hmac::from_engine(engine)
    }

    /// Allows testing against the old `PinData`s that didn't have an Hmac.
    #[cfg(test)]
    pub(crate) fn remove_hmac(&mut self) {
        self.hmac = None;
    }

    pub(crate) fn encrypted_bytes(&self) -> &[u8] {
        &*self.encrypted_bytes
    }

    pub(crate) fn client_key(&self) -> &ClientKey {
        &self.client_key
    }

    pub(crate) fn salt(&self) -> Salt<16> {
        self.salt
    }

    pub(crate) fn hmac(&self) -> Option<&Hmac<sha256::Hash>> {
        self.hmac.as_ref()
    }
}

/// Serializes a Vec of bytes to a hex string.
pub(super) fn serialize_bytes_to_hex<S>(
    bytes: &Vec<u8>,
    serializer: S,
) -> std::result::Result<S::Ok, S::Error>
where
    S: serde::ser::Serializer,
{
    use bitcoin::hashes::hex::ToHex;
    serializer.serialize_str(&bytes.to_hex())
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde_json::json;

    use super::*;
    use crate::tests::*;
    use crate::{Pin, PinClient};

    /// Checks that the old `PinData` returned by calling `GA_encrypt_with_pin`
    /// using the previous implementation of the PIN client correctly
    /// deserializes to the new `PinData`.
    ///
    /// Can be removed once we switch over.
    #[test]
    fn deserialize_old() -> TestResult {
        let old_pin_data_json = json!({
            "encrypted_data": "e029597ef1d721256e0fc1cc9a40e3b8",
            "pin_identifier": "c49c8656f834a8b672080c6f86e004b5c3127316a91ed279f6d9a6917b07fe68",
            "salt": "5af7eedda779127d1b87c5e4c80e53e3"
        });

        let pin_data = serde_json::from_value::<PinData>(old_pin_data_json)?;

        let client = PinClient::new(
            ureq::Agent::new(),
            url::Url::from_str(PIN_SERVER_PROD_URL).unwrap(),
            bitcoin::PublicKey::from_str(PIN_SERVER_PROD_PUBLIC_KEY).unwrap(),
        );

        // This is the plaintext that was passed to `encrypt_with_pin`.
        let expected = "\"Hello there\"";

        // This is the PIN that was passed to `encrypt_with_pin`.
        let pin = Pin::from("123456");

        let decrypted = client.decrypt(&pin_data, &pin)?;

        assert_eq!(expected, std::str::from_utf8(&decrypted)?);

        Ok(())
    }
}
