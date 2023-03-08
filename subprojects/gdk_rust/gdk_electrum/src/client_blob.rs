use super::{Error, LoginData, Store};
use crate::wait_or_close;
use gdk_common::log;
use log::info;
use std::sync::atomic::{AtomicBool, Ordering};

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

/// TODO: docs
pub(super) fn sync_blob(
    store: Store,
    client_id: ClientBlobId,
    user_wants_to_sync: &AtomicBool,
    interval: u32,
) -> Result<(), Error> {
    info!("starting client blob thread");

    todo!();
}
