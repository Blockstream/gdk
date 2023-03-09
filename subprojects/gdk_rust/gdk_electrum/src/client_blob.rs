use std::sync::atomic::{AtomicBool, Ordering};

use bitcoin::hashes::{sha256, Hash, HashEngine, HmacEngine};
use gdk_common::{bitcoin, log, ureq, url};
use log::info;
use serde::Deserialize;

use super::{Error, LoginData, Store};

const BLOBSERVER_SYNCING_INTERVAL: Duration = Duration::from_secs(60);

const EMPTY_HMAC: Lazy<Hmac> = Lazy::new(|| Hmac::from_slice(&[0u8; 32]).unwrap());

const EMPTY_HMAC_B64: &'static str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

type Hmac = bitcoin::hashes::Hmac<bitcoin::hashes::sha256::Hash>;

/// TODO: docs
pub(super) fn sync_blob(
    client: BlobClient,
    store: Store,
    user_wants_to_sync: &AtomicBool,
) -> Result<(), Error> {
    info!("starting client blob thread");

    // Get the blob from the server, or save the current one on the server if
    // it doesn't have one for this client id.

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
    /// before.
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

        let mut engine = HmacEngine::<sha256::Hash>::new(self.client_id.as_bytes());
        engine.input(&base64::decode(hmac)?);

        let hmac = Hmac::from_engine(engine);

        Ok(Some((blob, hmac)))
    }

    /// Updates the last hmac received by the server.
    fn set_last_hmac(&mut self, hmac: Hmac) {
        self.last_hmac = Some(hmac);
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

    #[test]
    fn blob_server_roundtrip() {}
}
