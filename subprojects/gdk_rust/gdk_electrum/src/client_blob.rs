use super::{Error, Store};
use crate::wait_or_close;
use gdk_common::log;
use log::info;
use std::sync::atomic::{AtomicBool, Ordering};

/// TODO: docs
pub(super) fn sync_blob(
    store: Store,
    user_wants_to_sync: &AtomicBool,
    interval: u32,
) -> Result<(), Error> {
    info!("starting client blob thread");

    todo!();
}
