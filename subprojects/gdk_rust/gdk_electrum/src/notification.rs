use gdk_common::model::Settings;
use gdk_common::wally::make_str;
use log::{info, warn};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

#[derive(Clone)]
pub struct NativeNotif(
    pub Option<(extern "C" fn(*const libc::c_void, *const libc::c_char), *const libc::c_void)>,
);
unsafe impl Send for NativeNotif {}

fn notify(notif: NativeNotif, data: Value, terminated: Arc<AtomicBool>) {
    info!("push notification: {:?}", data);
    if terminated.load(Ordering::Relaxed) {
        warn!("terminated signal already received, skipping notification");
        return;
    }
    if let Some((handler, self_context)) = notif.0 {
        handler(self_context, make_str(data.to_string()));
    } else {
        warn!("no registered handler to receive notification");
    }
}

pub fn notify_block(notif: NativeNotif, height: u32, terminated: Arc<AtomicBool>) {
    let data = json!({"block":{"block_height":height},"event":"block"});
    notify(notif, data, terminated);
}

pub fn notify_settings(notif: NativeNotif, settings: &Settings, terminated: Arc<AtomicBool>) {
    let data = json!({"settings":settings,"event":"settings"});
    notify(notif, data, terminated);
}

pub fn notify_updated_txs(notif: NativeNotif, account_num: u32, terminated: Arc<AtomicBool>) {
    // This is used as a signal to trigger syncing via get_transactions, the transaction
    // list contained here is ignored and can be just a mock.
    let mockup_json = json!({"event":"transaction","transaction":{"subaccounts":[account_num]}});
    notify(notif, mockup_json, terminated);
}
