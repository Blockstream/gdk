use std::borrow::Borrow;
use std::time::Instant;

use bitcoin::hashes::{sha256, Hash, HashEngine, HmacEngine};
use gdk_common::log::debug;
use gdk_common::once_cell::sync::Lazy;
use gdk_common::{bitcoin, log, ureq, url};
use log::info;
use serde::Deserialize;

use super::Error;

const EMPTY_HMAC: Lazy<Hmac> = Lazy::new(|| Hmac::from_slice(&[0u8; 32]).unwrap());

type Hmac = bitcoin::hashes::Hmac<bitcoin::hashes::sha256::Hash>;

/// A client used to manage all interactions with the blob server.
pub struct BlobClient {
    agent: ureq::Agent,

    blob_server_url: url::Url,

    client_id: String,

    last_hmac: Option<Hmac>,
}

impl BlobClient {
    /// Creates a new [`BlobClient`] from its ID.
    pub(super) fn new(agent: ureq::Agent, blob_server_url: url::Url, client_id: String) -> Self {
        let mut client = Self {
            agent,
            blob_server_url,
            client_id,
            last_hmac: None,
        };

        let _ = client.init_hmac();

        client
    }

    fn init_hmac(&mut self) -> Result<(), Error> {
        self.last_hmac =
            Some(self.get_blob()?.map(|(_blob, hmac)| hmac).unwrap_or_else(|| EMPTY_HMAC.clone()));

        Ok(())
    }

    /// Fetches the current `(Blob, Hmac)` pair from the blob server. It can
    /// return `None` if this client has never stored a blob on the server
    /// before.
    pub fn get_blob(&self) -> Result<Option<(Vec<u8>, Hmac)>, Error> {
        let response = self
            .agent
            .get(&format!("{}/get_client_blob", self.blob_server_url))
            .query("client_id", self.client_id.as_str())
            .query("sequence", "0")
            .call()?;

        let GetBlobResponse {
            blob,
            hmac,
            ..
        } = response.into_json()?;

        let hmac = Hmac::from_slice(&base64::decode(hmac)?)?;

        if hmac == *EMPTY_HMAC {
            return Ok(None);
        }

        Ok(Some((blob.bytes, hmac)))
    }

    /// Saves a new blob to the server. This can fail if another client (which
    /// could be on another device) is updating the blob at the same time.
    ///
    /// Returns early without calling the server if the hmac of the new blob
    /// is the same as the last seen by this client.
    ///
    /// `bytes` are sent to the server `as is`.
    /// Encryption to preserve privacy must be done by the caller
    pub fn set_blob(&mut self, bytes: impl AsRef<[u8]>) -> Result<(), Error> {
        if self.last_hmac.is_none() {
            self.init_hmac()?;
        }

        let blob = base64::encode(&bytes);

        let blob_hmac = self.to_hmac(blob.as_bytes());

        let previous_hmac = self.last_hmac.as_ref().unwrap();

        if &blob_hmac == previous_hmac {
            return Ok(());
        }

        let b64_blob_hmac = base64::encode(Borrow::<[u8]>::borrow(&blob_hmac));
        let b64_previous_hmac = base64::encode(Borrow::<[u8]>::borrow(previous_hmac));

        info!("set_client_blob client_id:{} hmac:{:?}", self.client_id, b64_blob_hmac);

        let now = Instant::now();
        let response = self
            .agent
            .get(&format!("{}/set_client_blob", self.blob_server_url))
            .query("client_id", self.client_id.as_str())
            .query("sequence", "0")
            .query("blob", &blob)
            .query("hmac", &b64_blob_hmac)
            .query("previous_hmac", &b64_previous_hmac)
            .call()?;

        let resp = response.into_json::<SetBlobResponse>()?;
        debug!(
            "set_client_blob client_id:{:?} hmac:{} previous_mac:{}, took {:?} return {:?}",
            self.client_id,
            b64_blob_hmac,
            b64_previous_hmac,
            now.elapsed(),
            resp
        );

        if let SetBlobResponse::Err(SetBlobError {
            error,
        }) = resp
        {
            return Err(Error::BlobClientError(error));
        }

        self.last_hmac = Some(blob_hmac);

        Ok(())
    }

    /// Hmacs the given data using this client's ID as key.
    fn to_hmac(&self, bytes: &[u8]) -> Hmac {
        let mut engine = HmacEngine::<sha256::Hash>::new(self.client_id.as_bytes());
        engine.input(bytes);
        Hmac::from_engine(engine)
    }
}

#[derive(Deserialize, Debug)]
struct GetBlobResponse {
    blob: Blob,
    hmac: String,

    #[serde(rename = "sequence")]
    _sequence: u8,
}

#[derive(Deserialize, Debug)]
#[serde(untagged)]
enum SetBlobResponse {
    /// The server returns a [`GetBlobResponse`] when it successfully updates
    /// the blob.
    Ok(GetBlobResponse),

    Err(SetBlobError),
}

#[derive(Deserialize, Debug)]
struct SetBlobError {
    error: String,
}

/// An encrypted blob sent to the server. The first 12 bytes contain the random
/// nonce used during the encryption process.
#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct Blob {
    #[serde(deserialize_with = "deserialize_bytes_from_b64")]
    pub bytes: Vec<u8>,
}

/// Deserializes a Vec of bytes from its Base64 representation.
pub(super) fn deserialize_bytes_from_b64<'de, D>(
    deserializer: D,
) -> std::result::Result<Vec<u8>, D::Error>
where
    D: serde::de::Deserializer<'de>,
{
    use serde::de::Error;
    base64::decode(String::deserialize(deserializer)?).map_err(D::Error::custom)
}

#[cfg(test)]
mod tests {
    use gdk_common::model::{LoadStoreOpt, Pricing, Settings};
    use gdk_common::session::Session;
    use gdk_common::NetworkParameters;
    use std::str::FromStr;

    use super::*;
    use crate::ElectrumSession;
    use gdk_common::ureq;
    use ureq::Agent;

    const BLOBSERVER_STAGING: &'static str = "https://green-blobserver.staging.blockstream.com";

    #[allow(dead_code)]
    const BLOBSERVER_STAGING_ONION: &'static str =
        "bloba2m6sogq7qxnxhxexxnphn2xh6h62kvywpekx4crrrg3sl3ttbqd.onion";

    #[test]
    fn blob_server_roundtrip() {
        let id = "Client123".to_string();

        let mut client =
            BlobClient::new(Agent::new(), url::Url::from_str(&BLOBSERVER_STAGING).unwrap(), id);

        let data = "Hello, world!";

        client.set_blob(data).unwrap();

        let (returned, _) = client.get_blob().unwrap().unwrap();

        assert_eq!(data, std::str::from_utf8(&returned).unwrap());
    }

    #[test]
    fn restore_settings() -> Result<(), Box<dyn std::error::Error>> {
        let _ = env_logger::try_init();
        let state_dir = tempfile::TempDir::new()?;

        let network_parameters = {
            let mut p = NetworkParameters::default();
            p.electrum_url = Some("blockstream.info:700".to_owned());
            p.blob_server_url = BLOBSERVER_STAGING.to_owned();
            p.state_dir = state_dir.path().display().to_string();
            p
        };

        let load_opts = serde_json::from_value::<LoadStoreOpt>(json! {{
            "master_xpub": "tpubD8G8MPH9RK9uk4EV97RxhzaY8SJPUWXnViHUwji92i8B7vYdht797PPDrJveeathnKxonJe8SbaScAC1YJ8xAzZbH9UvywrzpQTQh5pekkk",
        }})?;

        let settings = Settings {
            unit: "foo".to_owned(),
            required_num_blocks: 13,
            altimeout: 42,
            pricing: Pricing::default(),
            sound: true,
        };

        let mut session = ElectrumSession::new(network_parameters.clone())?;
        session.load_store(&load_opts)?;
        session.connect(&json! {{}})?;

        // Modify the store.
        {
            let store = session.store()?;
            let mut store = store.write().unwrap();
            store.insert_settings(settings.clone())?;
        }

        // Disconnect.
        session.disconnect()?;
        drop(session);
        drop(state_dir);

        // Using another session with the same mnemonic to check if settings are updated correctly
        let state_dir_2 = tempfile::TempDir::new()?;
        let mut network_parameters_2 = network_parameters;
        network_parameters_2.state_dir = state_dir_2.path().display().to_string();

        // Create a new session.
        let mut session_2 = ElectrumSession::new(network_parameters_2)?;
        session_2.load_store(&load_opts)?;
        session_2.connect(&json! {{}})?;

        // Get the settings.
        let restored_settings = {
            let store = session_2.store()?;
            let store = store.read().unwrap();
            store.get_settings().unwrap()
        };

        assert_eq!(restored_settings, settings);

        Ok(())
    }
}
