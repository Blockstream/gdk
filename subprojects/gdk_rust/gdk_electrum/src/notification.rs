use crate::State;
use gdk_common::model::Settings;
use gdk_common::wally::make_str;
use log::{info, warn};
use serde::{Deserialize, Serialize};
use serde_json::Value;

type NativeType = (extern "C" fn(*const libc::c_void, *const libc::c_char), *const libc::c_void);
#[derive(Clone)]
pub struct NativeNotif {
    pub native: Option<NativeType>,

    /// With testing feature notifications are simply pushed in the following vec so assertions
    /// could check over it, it's a mutex so that methods signatures doesn't need to be mut
    #[cfg(feature = "testing")]
    pub testing: std::sync::Arc<std::sync::Mutex<Vec<Value>>>,
}
unsafe impl Send for NativeNotif {}

#[derive(Serialize, Deserialize)]
pub struct Notification {
    network: Option<NetworkNotification>,
    event: Kind,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Network,
}

#[derive(Serialize, Deserialize)]
struct NetworkNotification {
    current_state: State,
    next_state: State,
    wait_ms: u32,
}

impl Notification {
    fn new_network(current: State, next: State) -> Self {
        Notification {
            network: Some(NetworkNotification {
                current_state: current,
                next_state: next,
                wait_ms: 0,
            }),
            event: Kind::Network,
        }
    }

    pub fn new_network_value(current: State, next: State) -> Value {
        serde_json::to_value(&Notification::new_network(current, next)).unwrap()
    }
}

impl NativeNotif {
    #[cfg(not(feature = "testing"))]
    pub fn new() -> Self {
        NativeNotif {
            native: None,
        }
    }

    fn notify(&self, data: Value) {
        info!("push notification: {:?}", data);
        if let Some((handler, self_context)) = self.native.as_ref() {
            handler(*self_context, make_str(data.to_string()));
        } else {
            if !cfg!(feature = "testing") {
                warn!("no registered handler to receive notification");
            }
            self.push(data);
        }
    }

    pub fn set_native(&mut self, native_type: NativeType) {
        self.native = Some(native_type);
    }

    pub fn block(&self, height: u32) {
        let data = json!({"block":{"block_height":height},"event":"block"});
        self.notify(data);
    }

    pub fn settings(&self, settings: &Settings) {
        let data = json!({"settings":settings,"event":"settings"});
        self.notify(data);
    }

    pub fn updated_txs(&self, account_num: u32) {
        // This is used as a signal to trigger syncing via get_transactions, the transaction
        // list contained here is ignored and can be just a mock.
        let data = json!({"event":"transaction","transaction":{"subaccounts":[account_num]}});
        self.notify(data);
    }

    pub fn network(&self, current: State, desired: State) {
        self.notify(Notification::new_network_value(current, desired));
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
            testing: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
        }
    }

    pub fn filter_events(&self, event: &str) -> Vec<Value> {
        self.testing
            .lock()
            .unwrap()
            .iter()
            .filter(|e| e.get("event").unwrap().as_str().unwrap() == event)
            .cloned()
            .collect()
    }

    pub fn push(&self, value: Value) {
        self.testing.lock().unwrap().push(value);
    }
}

#[cfg(test)]
mod test {
    use crate::notification::Notification;
    use crate::State;

    #[test]
    fn test_network_json() {
        let expected = json!({"network":{"wait_ms": 0, "current_state": "connected", "next_state": "connected"},"event":"network"});
        let obj = Notification::new_network_value(State::Connected, State::Connected);
        assert_eq!(expected, obj);
    }
}
