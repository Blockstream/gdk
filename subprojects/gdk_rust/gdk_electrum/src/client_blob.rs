use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use bitcoin::hashes::{sha256, Hash, HashEngine, HmacEngine};
use gdk_common::{bitcoin, log, ureq, url};
use log::{info, warn};
use serde::Deserialize;

use super::{Error, LoginData, RawStore, Store};


const EMPTY_HMAC_B64: &'static str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

const BLOBSERVER_SYNCING_INTERVAL: Duration = Duration::from_secs(60);

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
        let raw_store = serde_cbor::from_slice::<RawStore>(raw_store_blob.as_bytes())?;

        let mut store = store.write()?;
        store.store = raw_store;
        store.flush_store()?;
    } else {
        let store = store.read()?;
        let raw_store = serde_cbor::to_vec(&store.store)?;

        if let Err(err) = client.set_blob(raw_store) {
            warn!("Couldn't save store on blob server: {err:?}");
        }
    }

    while !wait_or_close(user_wants_to_sync, interval) {
        let start = Instant::now();

        if let Some((new_store_blob, _)) = client.get_blob()? {
            let raw_store = serde_cbor::from_slice::<RawStore>(new_store_blob.as_bytes())?;

            let mut store = store.write()?;
            store.store = raw_store;
            store.flush_store()?;
        }

        if let Some(remaining) = BLOBSERVER_SYNCING_INTERVAL.checked_sub(start.elapsed()) {
            std::thread::sleep(remaining);
        }

        // TODO: we should have a channel that sends us a message every time
        // the `RawStore` gets flushed. When that happens we send the new store
        // to the blob server.
    }

    todo!();
}

/// A client used to manage all interactions with the blob server.
pub(super) struct BlobClient {
    agent: ureq::Agent,

    blob_server_url: url::Url,

    client_id: ClientBlobId,
    last_hmac: Option<Hmac>,
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
        }
    }

    /// Fetches the current `(Blob, Hmac)` pair from the blob server. It can
    /// return `None` if this client has never stored a blob on the server
    /// before or if the blob hasn't changed since the last time it was
    /// fetched.
    fn get_blob(&self) -> Result<Option<(Blob, Hmac)>, Error> {
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
        } = serde_cbor::from_reader(response.into_reader())?;

        if hmac == EMPTY_HMAC_B64 {
            return Ok(None);
        }

        let hmac = self.to_hmac(&base64::decode(hmac)?);

        if let Some(last) = self.last_hmac {
            if hmac == last {
                return Ok(None);
            }
        }

        Ok(Some((blob, hmac)))
    }

    /// Saves a new blob to the server. This can fail if another client (which
    /// could be on another device) is updating the blob at the same time.
    fn set_blob(&mut self, blob: impl AsRef<[u8]>) -> Result<(), Error> {
        let blob_base64 = base64::encode(blob.as_ref());

        let blob_hmac = self.to_hmac(blob_base64.as_bytes());

        let previous_hmac = self
            .last_hmac
            .map(|hmac| format!("{hmac:x}"))
            .unwrap_or_else(|| EMPTY_HMAC_B64.to_owned());

        let response = self
            .agent
            .get(&format!("{}/set_client_blob", self.blob_server_url))
            .query("client_id", self.client_id.as_str())
            .query("sequence", "0")
            .query("blob", &blob_base64)
            .query("hmac", &format!("{blob_hmac:x}"))
            .query("previous_hmac", &previous_hmac)
            .call()?;

        // TODO: check response.

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

impl ClientBlobId {
    fn as_str(&self) -> &str {
        &self.wallet_hash_id
    }

    fn as_bytes(&self) -> &[u8] {
        self.as_str().as_bytes()
    }
}

// TODO: deserialize from hex string
#[derive(Deserialize)]
struct Blob(Vec<u8>);

impl Blob {
    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Deserialize)]
struct GetBlobResponse {
    blob: Blob,
    hmac: String,
    sequence: u8,
}

#[cfg(test)]
mod tests {
    use super::*;
    use gdk_common::ureq;
    use ureq::Agent;

    const BLOBSERVER_STAGING: &'static str = "https://green-blobserver.staging.blockstream.com";
    const BLOBSERVER_STAGING_ONION: &'static str =
        "bloba2m6sogq7qxnxhxexxnphn2xh6h62kvywpekx4crrrg3sl3ttbqd.onion";

    #[test]
    fn blob_server_roundtrip() {}
}
