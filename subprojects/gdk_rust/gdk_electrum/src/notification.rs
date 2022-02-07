use gdk_common::model::Settings;
use gdk_common::wally::make_str;
use log::{info, warn};
use serde_json::Value;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

type NativeType = (extern "C" fn(*const libc::c_void, *const libc::c_char), *const libc::c_void);
#[derive(Clone)]
pub struct NativeNotif {
    pub native: Option<NativeType>,

    /// With testing feature notifications are simply pushed in the following vec so assertions
    /// could check over it, it's a mutex so that methods signatures doesn't need to be mut
    #[cfg(feature = "testing")]
    pub testing: Arc<std::sync::Mutex<Vec<Value>>>,
}
unsafe impl Send for NativeNotif {}

impl NativeNotif {
    #[cfg(not(feature = "testing"))]
    pub fn new() -> Self {
        NativeNotif {
            native: None,
        }
    }

    fn notify(&self, data: Value, terminated: Arc<AtomicBool>) {
        info!("push notification: {:?}", data);
        if terminated.load(Ordering::Relaxed) {
            warn!("terminated signal already received, skipping notification");
            return;
        }
        if let Some((handler, self_context)) = self.native.as_ref() {
            handler(*self_context, make_str(data.to_string()));
        } else {
            warn!("no registered handler to receive notification");
            self.push(data);
        }
    }

    pub fn set_native(&mut self, native_type: NativeType) {
        self.native = Some(native_type);
    }

    pub fn block(&self, height: u32, terminated: Arc<AtomicBool>) {
        let data = json!({"block":{"block_height":height},"event":"block"});
        self.notify(data, terminated);
    }

    pub fn settings(&self, settings: &Settings, terminated: Arc<AtomicBool>) {
        let data = json!({"settings":settings,"event":"settings"});
        self.notify(data, terminated);
    }

    pub fn updated_txs(&self, account_num: u32, terminated: Arc<AtomicBool>) {
        // This is used as a signal to trigger syncing via get_transactions, the transaction
        // list contained here is ignored and can be just a mock.
        let mockup_json =
            json!({"event":"transaction","transaction":{"subaccounts":[account_num]}});
        self.notify(mockup_json, terminated);
    }

    #[cfg(not(feature = "testing"))]
    pub fn push(&self, _value: Value) {
        //does nothing in non testing mode
    }
}

#[cfg(feature = "testing")]
impl NativeNotif {
    pub fn new() -> Self {
        NativeNotif {
            native: None,
            testing: Arc::new(std::sync::Mutex::new(vec![])),
        }
    }

    pub fn notifications(&self) -> Vec<Value> {
        self.testing.lock().unwrap().clone()
    }

    pub fn find_last_event(&self, event: &str) -> Option<Value> {
        self.testing
            .lock()
            .unwrap()
            .iter()
            .rev()
            .find(|e| e.get("event").unwrap().as_str().unwrap() == event)
            .cloned()
    }

    pub fn push(&self, value: Value) {
        self.testing.lock().unwrap().push(value);
    }
}
