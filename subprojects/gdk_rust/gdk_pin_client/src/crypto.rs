use rand::Rng;

use bitcoin::{self, secp256k1::SecretKey};
use block_modes::BlockMode;

pub(crate) type Aes256Cbc = block_modes::Cbc<aes::Aes256, block_modes::block_padding::Pkcs7>;

/// A client-generated key.
#[derive(Debug, Clone)]
pub(crate) struct ClientKey {
    key: SecretKey,
}

impl ClientKey {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            key: SecretKey::new(&mut rand::thread_rng()),
        }
    }

    #[inline]
    pub(crate) fn secret_key(&self) -> &SecretKey {
        &self.key
    }
}

/// A key stored on the PIN server. Used to decrypt the data stored in the
/// [`PinData`].
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct ServerKey {
    bytes: Vec<u8>,
}

impl ServerKey {
    #[inline]
    pub(crate) fn from_bytes(bytes: Vec<u8>) -> Self {
        Self {
            bytes,
        }
    }

    #[inline]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Random data added to the plaintext bytes when encrypting using
/// [`encrypt`](self::encrypt).
#[derive(Debug, Copy, Clone)]
pub(crate) struct Salt<const BYTES: usize> {
    bytes: [u8; BYTES],
}

impl<const BYTES: usize> Salt<BYTES> {
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            bytes: rand::thread_rng().gen::<[u8; BYTES]>(),
        }
    }

    #[inline]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Takes a `plaintext` and the `ServerKey` to be used for the encryption, and
/// it returns the encrypted bytes together with a random salt generated during
/// the encryption process.
pub(crate) fn encrypt(plaintext: &[u8], server_key: &ServerKey) -> (Vec<u8>, Salt<16>) {
    let salt = Salt::<16>::new();

    let cipher = Aes256Cbc::new_from_slices(server_key.as_bytes(), salt.as_bytes())
        .expect("Both the ServerKey and the Salt have the right length");

    (cipher.encrypt_vec(plaintext), salt)
}

/// The encrypted bytes and the salt should be obtained by calling
/// [`encrypt`](self::encrypt) with the same `ServerKey`, otherwise decryption
/// will fail
pub(crate) fn decrypt(
    encrypted: &[u8],
    server_key: &ServerKey,
    salt: Salt<16>,
) -> crate::Result<Vec<u8>> {
    let decipher = Aes256Cbc::new_from_slices(server_key.as_bytes(), salt.as_bytes())
        .expect("Both the ServerKey and the Salt have the right length");

    decipher.decrypt_vec(encrypted).map_err(Into::into)
}

mod serde_impls {
    //! `Serialize` and `Deserialize` impls for `ClientKey` and `Salt`.

    use super::*;
    use bitcoin::hex::DisplayHex;
    use serde::{de, ser};

    impl<'de> de::Deserialize<'de> for ClientKey {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            struct ClientKeyVisitor;

            impl<'de> de::Visitor<'de> for ClientKeyVisitor {
                type Value = ClientKey;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a hex-encoded string")
                }

                fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    use bitcoin::hashes::hex::FromHex;

                    let bytes = <Vec<u8>>::from_hex(s).map_err(E::custom)?;

                    let key = SecretKey::from_slice(&bytes).map_err(E::custom)?;

                    Ok(ClientKey {
                        key,
                    })
                }
            }

            deserializer.deserialize_str(ClientKeyVisitor)
        }
    }

    impl ser::Serialize for ClientKey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: ser::Serializer,
        {
            serializer.serialize_str(&self.key.secret_bytes().to_lower_hex_string())
        }
    }

    impl<'de, const BYTES: usize> de::Deserialize<'de> for Salt<BYTES> {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: de::Deserializer<'de>,
        {
            struct SaltVisitor<const BYTES: usize>;

            impl<'de, const BYTES: usize> de::Visitor<'de> for SaltVisitor<BYTES> {
                type Value = Salt<BYTES>;

                fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    f.write_str("a hex-encoded string")
                }

                fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    use bitcoin::hashes::hex::FromHex;

                    let bytes = <Vec<u8>>::from_hex(s).map_err(E::custom)?;

                    match <[u8; BYTES]>::try_from(bytes) {
                        Ok(bytes) => Ok({
                            Salt {
                                bytes,
                            }
                        }),

                        Err(bytes) => Err(E::invalid_length(
                            bytes.len(),
                            &(&*format!("{BYTES} bytes where expected")),
                        )),
                    }
                }
            }

            deserializer.deserialize_str(SaltVisitor)
        }
    }

    impl<const BYTES: usize> ser::Serialize for Salt<BYTES> {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: ser::Serializer,
        {
            serializer.serialize_str(&self.bytes.to_lower_hex_string())
        }
    }
}
