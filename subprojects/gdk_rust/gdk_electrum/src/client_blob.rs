use std::borrow::Borrow;
use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use bitcoin::hashes::{sha256, Hash, HashEngine, HmacEngine};
use gdk_common::once_cell::sync::Lazy;
use gdk_common::store::{Decryptable, Encryptable, ToCipher};
use gdk_common::{aes, bitcoin, log, ureq, url};
use log::{info, warn};
use serde::Deserialize;

use super::{Error, LoginData, RawStore, Store};

const BLOBSERVER_SYNCING_INTERVAL: Duration = Duration::from_secs(60);

const EMPTY_HMAC: Lazy<Hmac> = Lazy::new(|| Hmac::from_slice(&[0u8; 32]).unwrap());

type Hmac = bitcoin::hashes::Hmac<bitcoin::hashes::sha256::Hash>;

/// TODO: docs
pub(super) fn sync_blob(
    mut client: BlobClient,
    store: Store,
    user_wants_to_sync: &AtomicBool,
) -> Result<(), Error> {
    info!("starting client blob thread");

    // Get the blob from the server, or save the current one on the server if
    // it doesn't have one for this client id.
    if let Some((raw_store_blob, _)) = client.get_blob()? {
        update_store_from_blob(&store, raw_store_blob)?;
    } else {
        let store = store.read()?;
        let raw_store = serde_cbor::to_vec(&store.store)?;

        if let Err(err) = client.set_blob(raw_store) {
            warn!("Couldn't save store on blob server: {err:?}");
        }
    }

    while !wait_or_close(user_wants_to_sync, interval) {
        let start = Instant::now();

        match (client.get_blob()?, &client.last_hmac) {
            (Some((new_store_blob, hmac)), Some(last_hmac)) if &hmac != last_hmac => {
                update_store_from_blob(&store, new_store_blob)?;
                continue;
            }
            _ => (),
        }

        if let Some(remaining) = BLOBSERVER_SYNCING_INTERVAL.checked_sub(start.elapsed()) {
            std::thread::sleep(remaining);
        }

        // TODO: we should have a channel that sends us a message every time
        // the `RawStore` gets flushed. When that happens we send the new store
        // to the blob server.
    }

    Ok(())
}

/// Updates the local contents of the store with the new value returned by the
/// blob server.
fn update_store_from_blob(store: &Store, new_store: Vec<u8>) -> Result<(), Error> {
    let raw_store = serde_cbor::from_slice::<RawStore>(&new_store)?;
    info!("received new store from blob server: {raw_store:?}");
    let mut store = store.write()?;
    store.store = raw_store;
    store.flush_store()?;
    Ok(())
}

/// A client used to manage all interactions with the blob server.
pub(super) struct BlobClient {
    agent: ureq::Agent,

    blob_server_url: url::Url,

    client_id: ClientBlobId,
    last_hmac: Option<Hmac>,
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
    Ok(GetBlobResponse),
    Err(SetBlobError),
}

#[derive(Deserialize)]
struct SetBlobError {
    error: String,
}

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
    use std::str::FromStr;

    use super::*;
    use gdk_common::ureq;
    use ureq::Agent;

    const BLOBSERVER_STAGING: &'static str = "https://green-blobserver.staging.blockstream.com";
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
}
