use crate::Error;
use aes::Aes256;
use bitcoin::hashes::hex::FromHex;
use bitcoin::hashes::{sha256, Hash, HashEngine, Hmac, HmacEngine};
use bitcoin::secp256k1::{self, ecdh, All, Message, Secp256k1, SecretKey, Signature};
use bitcoin::PublicKey;
use block_modes::block_padding::Pkcs7;
use block_modes::{BlockMode, Cbc};
use log::info;
use rand::prelude::ThreadRng;
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::fmt::Display;
use std::str::FromStr;

const PINSERVER_URL: &'static str = "https://jadepin.blockstream.com";
const PINSERVER_PUBKEY: &'static str =
    "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547";

type Aes256Cbc = Cbc<Aes256, Pkcs7>;
type ShaHmac = Hmac<sha256::Hash>;

#[derive(Debug, Deserialize)]
struct Handshake {
    sig: String,
    ske: String,
}

#[derive(Debug, Serialize)]
struct RequestData {
    cke: String,
    ske: String,
    encrypted_data: String,
    hmac_encrypted_data: String,
}

#[derive(Debug, Deserialize)]
struct ResponseData {
    encrypted_key: String,
    hmac: String,
}

pub struct PinManager {
    secp: Secp256k1<All>,
    ske: secp256k1::PublicKey,
    cke: secp256k1::PublicKey,
    request_encryption_key: ShaHmac,
    request_hmac_key: ShaHmac,
    response_encryption_key: ShaHmac,
    response_hmac_key: ShaHmac,
    rng: ThreadRng,
    agent: ureq::Agent,
}

enum PinOp {
    Set,
    Get,
}

impl PinManager {
    pub fn new(agent: ureq::Agent) -> Result<Self, Error> {
        info!("PinManager new()");
        let data = Self::handshake_request(&agent)?;
        Self::with_handshake(data, agent)
    }

    /// `set_pin` consume self, because handshake must be done for every request
    pub fn set_pin(self, pin_secret: &[u8], private_key: &SecretKey) -> Result<Vec<u8>, Error> {
        self.server_call(pin_secret, private_key, PinOp::Set).map_err(|_| Error::PinError)
    }

    /// `get_pin` consume self, because handshake must be done for every request
    pub fn get_pin(self, pin_secret: &[u8], private_key: &SecretKey) -> Result<Vec<u8>, Error> {
        self.server_call(pin_secret, private_key, PinOp::Get).map_err(|_| Error::PinError)
    }

    fn handshake_request(agent: &ureq::Agent) -> Result<Handshake, Error> {
        let response = agent
            .post(&format!("{}/start_handshake", PINSERVER_URL))
            .set("content-length", "0")
            .call();
        if !response.ok() {
            return Err(Error::PinError);
        }
        let data: Handshake = serde_json::from_reader(response.into_reader())?;
        Ok(data)
    }

    fn with_handshake(data: Handshake, agent: ureq::Agent) -> Result<Self, Error> {
        let mut rng = rand::thread_rng();
        let pinserver_pubkey = PublicKey::from_str(PINSERVER_PUBKEY).unwrap();

        let sig = data.sig()?;
        let (ske, msg) = data.ske()?;

        let mut secp = Secp256k1::new();
        secp.randomize(&mut rng);
        secp.verify(&msg, &sig, &pinserver_pubkey.key)?;

        let secret_key = SecretKey::new(&mut rng);
        let shared_secret = secp256k1::ecdh::SharedSecret::new(&ske, &secret_key);
        let cke = secp256k1::PublicKey::from_secret_key(&secp, &secret_key);

        Ok(PinManager {
            secp,
            ske,
            cke,
            rng,
            request_encryption_key: Self::derive(0, &shared_secret),
            request_hmac_key: Self::derive(1, &shared_secret),
            response_encryption_key: Self::derive(2, &shared_secret),
            response_hmac_key: Self::derive(3, &shared_secret),
            agent,
        })
    }

    fn derive(value: u8, key: &ecdh::SharedSecret) -> ShaHmac {
        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(key);
        hmac_engine.input(&[value]);
        Hmac::from_engine(hmac_engine)
    }

    fn server_call(
        mut self,
        pin_secret: &[u8],
        private_key: &SecretKey,
        op: PinOp,
    ) -> Result<Vec<u8>, Error> {
        let pin_secret = sha256::Hash::hash(pin_secret);
        let entropy = self.rng.gen::<[u8; 32]>();
        let mut data = vec![];
        let serialized_cke = &self.cke.serialize()[..];
        let serialized_ske = &self.ske.serialize()[..];
        data.extend(serialized_cke);
        data.extend(&pin_secret[..]);
        data.extend(&entropy);
        assert_eq!(data.len(), 97);

        let hash = sha256::Hash::hash(&data);
        let msg = Message::from_slice(&hash.into_inner())?;
        let (rec_id, sig) = self.secp.sign_recoverable(&msg, &private_key).serialize_compact();
        let mut payload = vec![];
        payload.extend(&pin_secret[..]);
        payload.extend(&entropy);
        payload.push((31 + rec_id.to_i32()) as u8);
        payload.extend(&sig[..]);
        assert_eq!(payload.len(), 129);

        let iv = self.rng.gen::<[u8; 16]>();
        let cipher = Aes256Cbc::new_from_slices(&self.request_encryption_key[..], &iv).unwrap();
        let encrypted = cipher.encrypt_vec(&payload);
        let mut iv_encrypted: Vec<u8> = vec![];
        iv_encrypted.extend(&iv[..]);
        iv_encrypted.extend(&encrypted[..]);

        let mut auth_payload = vec![];
        auth_payload.extend(serialized_cke);
        auth_payload.extend(&iv_encrypted);
        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(&self.request_hmac_key[..]);
        hmac_engine.input(&auth_payload);
        let hmac = Hmac::from_engine(hmac_engine);

        let req = RequestData {
            ske: hex::encode(&serialized_ske),
            cke: hex::encode(&serialized_cke),
            encrypted_data: hex::encode(&iv_encrypted),
            hmac_encrypted_data: hex::encode(&hmac[..]),
        };

        let response = self
            .agent
            .post(&format!("{}/{}", PINSERVER_URL, op))
            .send_json(serde_json::to_value(&req).unwrap());

        if !response.ok() {
            return Err(Error::PinError);
        }

        let response: ResponseData = serde_json::from_reader(response.into_reader())?;

        response.verify_and_decrypt(&self.response_hmac_key, &self.response_encryption_key)
    }
}

impl ResponseData {
    fn verify_and_decrypt(&self, hmac_key: &ShaHmac, enc_key: &ShaHmac) -> Result<Vec<u8>, Error> {
        let mut hmac_engine: HmacEngine<sha256::Hash> = HmacEngine::new(&hmac_key[..]);
        hmac_engine.input(&hex::decode(&self.encrypted_key)?);
        let hmac = Hmac::from_engine(hmac_engine);

        if hmac != Hmac::from_hex(&self.hmac)? {
            return Err(Error::PinError);
        }

        let iv = hex::decode(&self.encrypted_key[..32])?;
        let decipher = Aes256Cbc::new_from_slices(&enc_key[..], &iv).unwrap();
        let decrypted = decipher.decrypt_vec(&hex::decode(&self.encrypted_key[32..])?)?;

        Ok(decrypted)
    }
}

impl Handshake {
    /// returns the parsed signature of the payload
    fn sig(&self) -> Result<Signature, Error> {
        let sig_bytes = hex::decode(&self.sig)?;
        Ok(Signature::from_compact(&sig_bytes)?)
    }

    /// returns the ske Public key and its sha256 hash as a `Message`
    fn ske(&self) -> Result<(secp256k1::PublicKey, Message), Error> {
        let ske_bytes = hex::decode(&self.ske)?;
        let ske = PublicKey::from_slice(&ske_bytes)?.key;
        let hash = sha256::Hash::hash(&ske_bytes);
        let msg = Message::from_slice(&hash.into_inner())?;
        Ok((ske, msg))
    }
}

impl Display for PinOp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self {
            PinOp::Get => write!(f, "get_pin"),
            PinOp::Set => write!(f, "set_pin"),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::pin::{Handshake, PinManager, ResponseData};
    use bitcoin::hashes::hex::FromHex;
    use bitcoin::hashes::Hmac;
    use bitcoin::secp256k1::SecretKey;

    #[test]
    fn test_with_pin_server() {
        // requires internet connection and pin server working
        let mut rng = rand::thread_rng();
        let secret_key = SecretKey::new(&mut rng);

        let manager = PinManager::new(ureq::Agent::new()).unwrap();
        let pin_key_set = manager.set_pin(&[0u8; 4], &secret_key).unwrap();

        let manager = PinManager::new(ureq::Agent::new()).unwrap();
        let pin_key_get = manager.get_pin(&[0u8; 4], &secret_key).unwrap();
        assert_eq!(pin_key_get, pin_key_set);
    }

    #[test]
    fn test_handshake() {
        // test vector taken from a random response from the production pin server
        let data = Handshake { sig: "004a58b09b6b4b6585536c5fbd662fb729a277426875a644fa56f5d05d6724281576f9d7844fc131102cd9d4fd56ca0b7f3cf9872379510407b3075f5c862c70".to_string(), ske: "032541c31f808a28750daf386e52ad70f16db153fa9e8375a6178021a0c7a74c09".to_string() };
        assert!(PinManager::with_handshake(data, ureq::Agent::new()).is_ok());
    }

    #[test]
    fn test_response() {
        // test vector taken from a random response from the production pin server
        let data = ResponseData { encrypted_key: "5ed80945d894225d9add79796896efb0515665a1ff00e9678c0e312b386c3287d2160662c3069c4bcdfde1219e3873261714498a5f3cb09c8102a5481759738d".to_string(), hmac: "a40f098419b542a5ac8be1871a30c6c958d05fe0c57df2791ea87dac83786943".to_string() };
        let hmac_key =
            Hmac::from_hex("2a19879506bc560a2120187ca4871c79845d19019874435cde4be9115ca31ec0")
                .unwrap();
        let decr_key =
            Hmac::from_hex("795d9b98328cf9606eabbf3ef4c42faabffb86e98949f68c6bf7a45b89e9461b")
                .unwrap();

        let result = data.verify_and_decrypt(&hmac_key, &decr_key).unwrap();
        let expected = "b5035db9ffeb913bbe8090abe800e1d5a93e653328b4a628f8f511e82d554704";
        assert_eq!(expected, &hex::encode(&result));
    }
}
