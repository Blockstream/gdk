use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::PublicKey;
use url::Url;

use crate::crypto;
use crate::crypto::{Aes256Cbc, ClientKey, ServerKey};
use crate::pin_request::{HandShake, PinServerRequest, ResponseDecryptionKey};
use crate::{Pin, PinData, Result};

/// The PIN client used to manage all interactions with the PIN server.
pub struct PinClient {
    agent: ureq::Agent,
    pin_server_public_key: PublicKey,
    pin_server_url: Url,
}

impl PinClient {
    /*
     `PinClient::new`, `PinClient::encrypt` and `PinClient::decrypt` are the
      only methods exposed publicly.
    */

    #[inline]
    pub fn new(agent: ureq::Agent, pin_server_url: Url, pin_server_public_key: PublicKey) -> Self {
        Self {
            agent,
            pin_server_url,
            pin_server_public_key,
        }
    }

    /// Encrypts `plaintext` using the `pin`, storing the pin on the PIN
    /// server.
    ///
    /// The returned [`PinData`] can be passed to [`PinClient::decrypt`]
    /// together with the same [`Pin`] to retrieve the encrypted data.
    pub fn encrypt(&self, plaintext: &[u8], pin: &Pin) -> Result<PinData> {
        let client_key = ClientKey::new();
        let server_key = self.set_pin(pin, &client_key)?;
        let (encrypted, salt) = crypto::encrypt(plaintext, &server_key);
        Ok(PinData::new(encrypted, client_key, salt, &server_key))
    }

    /// Decrypts the [`PinData`] obtained by calling [`PinClient::encrypt`],
    /// returning the original plaintext.
    pub fn decrypt(&self, data: &PinData, pin: &Pin) -> Result<Vec<u8>> {
        let server_key = self.get_pin(pin, data.client_key())?;

        if let Some(hmac) = data.hmac() {
            if hmac != &PinData::get_hmac(&server_key, &data.salt(), data.encrypted_bytes()) {
                return Err(crate::Error::InvalidPin);
            }
        }

        let decrypted = crypto::decrypt(data.encrypted_bytes(), &server_key, data.salt())?;
        Ok(decrypted)
    }

    /*
      Private methods.
    */

    #[inline]
    fn set_pin(&self, pin: &Pin, client_key: &ClientKey) -> Result<ServerKey> {
        self.server_op(pin, client_key, ServerOp::SetPin)
    }

    #[inline]
    fn get_pin(&self, pin: &Pin, client_key: &ClientKey) -> Result<ServerKey> {
        self.server_op(pin, client_key, ServerOp::GetPin)
    }

    fn server_op(&self, pin: &Pin, client_key: &ClientKey, op: ServerOp) -> Result<ServerKey> {
        let handshake = self.handshake_server()?;
        handshake.verify(&self.pin_server_public_key)?;

        let (request_key, response_key) = handshake.generate_keys();

        let request = PinServerRequest::new(pin, client_key, &request_key)?;

        let response = self.call_server(&request, op)?;
        response.verify(&response_key)?;
        response.decrypt_server_key(&response_key)
    }

    fn handshake_server(&self) -> Result<HandShake> {
        let response = self
            .agent
            .post(&format!("{}/start_handshake", self.pin_server_url))
            .set("content-length", "0")
            .call()
            .map_err(|_| crate::Error::HandshakeFailed)?;

        serde_json::from_reader(response.into_reader()).map_err(Into::into)
    }

    fn call_server(&self, request: &PinServerRequest, op: ServerOp) -> Result<PinServerResponse> {
        let endpoint = match op {
            ServerOp::GetPin => "get_pin",
            ServerOp::SetPin => "set_pin",
        };

        let response = self
            .agent
            .post(&format!("{}/{endpoint}", self.pin_server_url))
            .send_json(request)
            .map_err(|_| crate::Error::ServerCallFailed)?;

        serde_json::from_reader(response.into_reader()).map_err(Into::into)
    }
}

#[derive(Debug, serde::Deserialize)]
struct PinServerResponse {
    encrypted_key: String,
    hmac: String,
}

impl PinServerResponse {
    fn decrypt_server_key(&self, decryption_key: &ResponseDecryptionKey) -> Result<ServerKey> {
        use bitcoin::hashes::hex::FromHex;
        use block_modes::BlockMode;

        let (salt, encrypted) = {
            let salt_bytes = 32;

            if self.encrypted_key.len() < salt_bytes {
                return Err(crate::Error::InvalidResponse);
            }

            let s = Vec::<u8>::from_hex(&self.encrypted_key[..salt_bytes])?;
            let e = Vec::<u8>::from_hex(&self.encrypted_key[salt_bytes..])?;
            (s, e)
        };

        let decipher = {
            let key = decryption_key.decryption_key();
            Aes256Cbc::new_from_slices(&key[..], &salt)
                .expect("Both the decryption key and the salt have the right length")
        };

        let decrypted = decipher.decrypt_vec(&encrypted)?;

        Ok(ServerKey::from_bytes(decrypted))
    }

    fn verify(&self, decryption_key: &ResponseDecryptionKey) -> Result<()> {
        use bitcoin::hashes::hex::FromHex;

        let hmac = {
            let encrypted_key = Vec::<u8>::from_hex(&self.encrypted_key)?;
            let mut engine = HmacEngine::<sha256::Hash>::new(&decryption_key.hmac_key()[..]);
            engine.input(&encrypted_key);
            Hmac::from_engine(engine)
        };

        if hmac == Hmac::from_str(&self.hmac)? {
            Ok(())
        } else {
            Err(crate::Error::InvalidResponse)
        }
    }
}

enum ServerOp {
    GetPin,
    SetPin,
}

#[cfg(test)]
mod tests {

    use bitcoin::hashes::hex::FromHex;
    use serde_json::json;

    use super::*;

    /// Tests that a PIN server response deserializes correctly from a JSON,
    /// that it verifies against its Hmac key and that its server key can be
    /// correctly decrypted.
    #[test]
    fn deserialize_response() {
        let json = json!({
            "encrypted_key": "5ed80945d894225d9add79796896efb0515665a1ff00e9678c0e312b386c3287d2160662c3069c4bcdfde1219e3873261714498a5f3cb09c8102a5481759738d",
            "hmac": "a40f098419b542a5ac8be1871a30c6c958d05fe0c57df2791ea87dac83786943",
        });

        let response = serde_json::from_value::<PinServerResponse>(json).unwrap();

        let decryption_key = {
            let decr_key =
                Hmac::from_str("795d9b98328cf9606eabbf3ef4c42faabffb86e98949f68c6bf7a45b89e9461b")
                    .unwrap();

            let hmac_key =
                Hmac::from_str("2a19879506bc560a2120187ca4871c79845d19019874435cde4be9115ca31ec0")
                    .unwrap();

            ResponseDecryptionKey::new(decr_key, hmac_key)
        };

        assert!(response.verify(&decryption_key).is_ok());

        let expected = ServerKey::from_bytes(
            Vec::<u8>::from_hex("b5035db9ffeb913bbe8090abe800e1d5a93e653328b4a628f8f511e82d554704")
                .unwrap(),
        );

        assert_eq!(expected, response.decrypt_server_key(&decryption_key).unwrap());
    }
}
