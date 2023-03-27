use std::borrow::Borrow;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use bitcoin::hashes::{sha256, Hash, HashEngine, HmacEngine};
use gdk_common::once_cell::sync::Lazy;
use gdk_common::store::{Decryptable, Encryptable, ToCipher};
use gdk_common::{aes, bitcoin, log, ureq, url};
use log::{info, warn};
use serde::Deserialize;

use super::{Error, LoginData, RawStore, Store};

#[cfg(not(test))]
const BLOBSERVER_SYNCING_INTERVAL: Duration = Duration::from_secs(60);

#[cfg(test)]
const BLOBSERVER_SYNCING_INTERVAL: Duration = Duration::from_secs(5);

/// Once we polled the server we'll have some time to wait before we poll
/// again. This controls how often we check if the user wants to close the
/// thread within that time period.
const CHECK_THREAD_STOP: Duration = Duration::from_secs(3);

const EMPTY_HMAC: Lazy<Hmac> = Lazy::new(|| Hmac::from_slice(&[0u8; 32]).unwrap());

type Hmac = bitcoin::hashes::Hmac<bitcoin::hashes::sha256::Hash>;

/// Periodically syncs the contents of the wallet's [`RawStore`] with the
/// remote blob server.
pub(super) fn sync_blob(
    mut client: BlobClient,
    store: Store,
    user_wants_to_sync: &AtomicBool,
    store_update_recv: mpsc::Receiver<()>,
) -> Result<(), Error> {
    info!("starting client blob thread");

    let mut sync_blob = || match client.get_blob()? {
        // The server doesn't have a blob for this client id => upload the
        // current store.
        None => update_blob_from_store(&mut client, &store),

        Some((store_blob, hmac)) => {
            match &client.last_hmac {
                // The blob on the server has not changed since the previous
                // iteration => upload the current store.
                Some(last) if &hmac == last => update_blob_from_store(&mut client, &store),

                // The blob on the server has changed since the previous
                // iteration or the client has never synced with the server =>
                // update the local store.
                _ => update_store_from_blob(&mut client, &store, &store_blob),
            }
        }
    };

    loop {
        let start = Instant::now();

        if let Err(err) = sync_blob() {
            warn!("error syncing blob: {}", err);
        }

        while start.elapsed() < BLOBSERVER_SYNCING_INTERVAL {
            if !user_wants_to_sync.load(Ordering::Relaxed) {
                info!("closing client blob thread");
                return Ok(());
            }

            // If we receive a message on the channel it means that the
            // store has been updated and we should stop waiting and sync it
            // with the blob server.
            if let Ok(()) = store_update_recv.recv_timeout(CHECK_THREAD_STOP) {
                break;
            }
        }
    }
}

/// Updates the local contents of the store with the new value returned by the
/// blob server. If the blob server has an older version of the store, it will
/// be updated with the local contents.
fn update_store_from_blob(
    client: &mut BlobClient,
    store: &Store,
    store_blob: &[u8],
) -> Result<(), Error> {
    let raw_store = serde_cbor::from_slice::<RawStore>(store_blob)?;

    info!("received new store from blob server: {raw_store:?}");

    if let Err(Error::StoreTimestamp(_, _)) = store.write()?.update_store(raw_store) {
        info!("store on blob server is out of date, updating it");
        update_blob_from_store(client, store)
    } else {
        Ok(())
    }
}

/// Saves the local contents of the store to the remote blob server.
fn update_blob_from_store(client: &mut BlobClient, store: &Store) -> Result<(), Error> {
    let raw_store = serde_cbor::to_vec(&store.read()?.store)?;

    client.set_blob(raw_store).map_err(|err| {
        warn!("Couldn't save store on blob server: {err:?}");
        err
    })
}

/// A client used to manage all interactions with the blob server.
pub(super) struct BlobClient {
    agent: ureq::Agent,

    blob_server_url: url::Url,

    client_id: ClientBlobId,

    last_hmac: Option<Hmac>,

    /// A cipher derived from the [`client_id`](Self::client_id) uses to
    /// encrypt the contents of the blob before sending them to the serve.r
    encryption_key: aes::Aes256GcmSiv,
}

impl BlobClient {
    /// Creates a new [`BlobClient`] from its ID.
    pub(super) fn new(
        agent: ureq::Agent,
        blob_server_url: url::Url,
        client_id: ClientBlobId,
    ) -> Self {
        let encryption_key = client_id.to_cipher().unwrap();

        let mut client = Self {
            agent,
            blob_server_url,
            client_id,
            last_hmac: None,
            encryption_key,
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
    fn get_blob(&self) -> Result<Option<(Vec<u8>, Hmac)>, Error> {
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

        Ok(Some((blob.decrypt(&self.encryption_key)?, hmac)))
    }

    /// Saves a new blob to the server. This can fail if another client (which
    /// could be on another device) is updating the blob at the same time.
    ///
    /// Returns early without calling the server if the hmac of the new blob
    /// is the same as the last seen by this client.
    fn set_blob(&mut self, blob: impl AsRef<[u8]>) -> Result<(), Error> {
        if self.last_hmac.is_none() {
            self.init_hmac()?;
        }

        let blob = {
            let (nonce, mut bytes) = blob.as_ref().to_owned().encrypt(&self.encryption_key)?;
            bytes.splice(0..0, nonce);
            base64::encode(&bytes)
        };

        let blob_hmac = self.to_hmac(blob.as_bytes());

        let previous_hmac = self.last_hmac.as_ref().unwrap();

        if &blob_hmac == previous_hmac {
            return Ok(());
        }

        let b64_blob_hmac = base64::encode(Borrow::<[u8]>::borrow(&blob_hmac));
        let b64_previous_hmac = base64::encode(Borrow::<[u8]>::borrow(previous_hmac));

        info!("storing new blob on the server with hmac {b64_blob_hmac:?}");

        let response = self
            .agent
            .get(&format!("{}/set_client_blob", self.blob_server_url))
            .query("client_id", self.client_id.as_str())
            .query("sequence", "0")
            .query("blob", &blob)
            .query("hmac", &b64_blob_hmac)
            .query("previous_hmac", &b64_previous_hmac)
            .call()?;

        if let SetBlobResponse::Err(SetBlobError {
            error,
        }) = response.into_json::<SetBlobResponse>()?
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

/// An identifier used to access a wallet's blob stored on the the blob server.
pub(super) struct ClientBlobId {
    wallet_hash_id: String,
}

impl From<LoginData> for ClientBlobId {
    fn from(login_data: LoginData) -> Self {
        Self {
            wallet_hash_id: login_data.wallet_hash_id,
        }
    }
}

impl ToCipher for &ClientBlobId {
    fn to_cipher(self) -> gdk_common::Result<aes::Aes256GcmSiv> {
        use aes::aead::NewAead;
        let key_bytes = sha256::Hash::hash(&self.as_bytes()).into_inner();
        let key = aes::Key::from_slice(&key_bytes);
        Ok(aes::Aes256GcmSiv::new(&key))
    }
}

impl ClientBlobId {
    fn as_str(&self) -> &str {
        &self.wallet_hash_id
    }

    fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

#[derive(Deserialize)]
struct GetBlobResponse {
    blob: Blob,
    hmac: String,

    #[serde(rename = "sequence")]
    _sequence: u8,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum SetBlobResponse {
    /// The server returns a [`GetBlobResponse`] when it successfully updates
    /// the blob.
    Ok(GetBlobResponse),

    Err(SetBlobError),
}

#[derive(Deserialize)]
struct SetBlobError {
    error: String,
}

/// An encrypted blob sent to the server. The first 12 bytes contain the random
/// nonce used during the encryption process.
#[derive(Debug, Deserialize)]
#[serde(transparent)]
struct Blob {
    #[serde(deserialize_with = "deserialize_bytes_from_b64")]
    bytes: Vec<u8>,
}

impl Decryptable for Blob {
    fn decrypt(self, cipher: &aes::Aes256GcmSiv) -> gdk_common::Result<Vec<u8>> {
        self.bytes.decrypt(cipher)
    }
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
    use crate::store::Kind;
    use crate::ElectrumSession;
    use gdk_common::ureq;
    use ureq::Agent;

    const BLOBSERVER_STAGING: &'static str = "https://green-blobserver.staging.blockstream.com";

    #[allow(dead_code)]
    const BLOBSERVER_STAGING_ONION: &'static str =
        "bloba2m6sogq7qxnxhxexxnphn2xh6h62kvywpekx4crrrg3sl3ttbqd.onion";

    #[test]
    fn blob_server_roundtrip() {
        let id = ClientBlobId {
            wallet_hash_id: "Client123".to_owned(),
        };

        let mut client =
            BlobClient::new(Agent::new(), url::Url::from_str(BLOBSERVER_STAGING).unwrap(), id);

        let data = "Hello, world!";

        client.set_blob(data).unwrap();

        let (returned, _) = client.get_blob().unwrap().unwrap();

        assert_eq!(data, std::str::from_utf8(&returned).unwrap());
    }

    #[test]
    fn restore_settings() -> Result<(), Box<dyn std::error::Error>> {
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

        // Wait for the blob to be sent to the server.
        std::thread::sleep(BLOBSERVER_SYNCING_INTERVAL + Duration::from_secs(5));

        // Disconnect.
        session.disconnect()?;

        // Remove the store.
        {
            let store = session.store()?;
            let mut store = store.write().unwrap();
            store.remove_file(Kind::Store);
        }

        // The store is kept in memory, so we need to drop the session to
        // verify that the store is reloaded from the blob.
        drop(session);

        // Create a new session.
        let mut session = ElectrumSession::new(network_parameters)?;
        session.load_store(&load_opts)?;
        session.connect(&json! {{}})?;

        // Wait for the settings to be restored from the blob server.
        std::thread::sleep(BLOBSERVER_SYNCING_INTERVAL + Duration::from_secs(5));

        // Get the settings.
        let restored_settings = {
            let store = session.store()?;
            let store = store.read().unwrap();
            store.get_settings().unwrap()
        };

        assert_eq!(restored_settings, settings);

        Ok(())
    }
}
