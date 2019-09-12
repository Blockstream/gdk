use std::mem::transmute;

use serde_json::Value;

use crate::errors::Error;
use crate::network::Network;
use crate::settings::Settings;
use crate::wallet::Wallet;
use crate::GDKRPC_json;

#[derive(Debug)]
#[repr(C)]
pub struct GDKRPC_session {
    pub settings: Settings,
    pub network: Option<Network>,
    pub wallet: Option<Wallet>,
    pub notify:
        Option<(extern "C" fn(*const libc::c_void, *const GDKRPC_json), *const libc::c_void)>,
}

impl GDKRPC_session {
    pub fn new() -> *mut GDKRPC_session {
        let sess = GDKRPC_session {
            settings: Settings::default(),
            network: None,
            wallet: None,
            notify: None,
        };
        unsafe { transmute(Box::new(sess)) }
    }

    pub fn wallet(&self) -> Option<&Wallet> {
        self.wallet.as_ref()
    }

    pub fn wallet_mut(&mut self) -> Option<&mut Wallet> {
        self.wallet.as_mut()
    }

    pub fn tick(&mut self) -> Result<(), Error> {
        if let Some(ref mut wallet) = self.wallet {
            for msg in wallet.updates()? {
                self.notify(msg)
            }
        }
        Ok(())
    }

    // called when the wallet is initialized and logged in
    pub fn hello(&mut self) -> Result<(), Error> {
        self.notify(json!({ "event": "settings", "settings": self.settings }));
        self.tick()
    }

    pub fn notify(&self, data: Value) {
        debug!("push notification: {:?}", data);
        if let Some((handler, context)) = self.notify {
            handler(context, GDKRPC_json::new(data));
        } else {
            warn!("no registered handler to receive notification");
        }
    }
}
