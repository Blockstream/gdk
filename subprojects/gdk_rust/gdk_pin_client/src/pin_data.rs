use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::hex::DisplayHex;
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
    serializer.serialize_str(&bytes.to_lower_hex_string())
}
