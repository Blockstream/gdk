use std::thread;
use std::time::Duration;

use serde_json::Value;

use gdk_common::model::*;
use gdk_common::{NetworkId, NetworkParameters, State};
use gdk_electrum::headers;
use gdk_electrum::{Notification, TransactionNotification};

/// Json of network notification
pub fn ntf_network(current: State, desired: State) -> Value {
    serde_json::to_value(&Notification::new_network(current, desired)).unwrap()
}

/// Json of transaction notification
pub fn ntf_transaction(ntf: &TransactionNotification) -> Value {
    serde_json::to_value(&Notification::new_transaction(ntf)).unwrap()
}
