
use serde_json::Value;

use crate::errors::Error;
use crate::network::{RpcConfig, RpcNetwork};
use crate::settings::Settings;
use crate::wallet::Wallet;
use bitcoincore_rpc::RpcApi;
use gdk_common::constants::*;
use gdk_common::network::Network;
use gdk_common::util::OptionExt;
use gdk_common::model::GDKRUST_json;
use gdk_common::session::Session;
use serde_json::from_value;

#[derive(Debug)]
#[repr(C)]
pub struct RpcSession {
    pub settings: Settings,
    pub rpc_cfg: Option<RpcConfig>,
    pub network: Network,
    pub wallet: Option<Wallet>,
    pub notify:
        Option<(extern "C" fn(*const libc::c_void, *const GDKRUST_json), *const libc::c_void)>,
}

impl RpcSession {
    fn new(network: Network) -> Result<Self, Error> {
        let sess = RpcSession {
            settings: Settings::default(),
            rpc_cfg: None,
            network,
            wallet: None,
            notify: None,
        };
        Ok(sess)
    }
}

impl Session<Error> for RpcSession {

    fn destroy_session(mut self) -> Result<(), Error> {
        if let Some(wallet) = self.wallet.take() {
            wallet.logout()?;
        }
        Ok(())
    }

    fn poll_session(&self) -> Result<(), Error> {
        //TODO
        Ok(())
    }

    fn connect(&mut self, net_params: Value, log_level: u32) -> Result<(), Error> {
        let mwallet = obj_str(&net_params, "wallet");

        let mrpc = json_to_rpc_config(&net_params);

        if mrpc.is_none() {
            println!("Couldn't parse rpc json in GDKRUST_connect: {:#?}", net_params);
            return Err(Error::Other(format!("{}", GA_ERROR)));
        }
        let rpc = mrpc.unwrap();

        println!("Connecting to {} socks5({:#?})", rpc.url, rpc.socks5);
        let mclient = RpcNetwork::connect(&rpc, mwallet);

        if let Err(msg) = mclient {
            println!("Error connecting to rpc: {}", msg);
            return Err(Error::Other(format!("{}", GA_RECONNECT)));
        }

        let client = mclient.unwrap();
        let mcount = client.get_block_count();

        if let Err(msg) = mcount {
            println!("Error establishing connection to rpc: {}", msg);
            return Err(Error::Other(format!("{}", GA_RECONNECT)));
        }

        self.rpc_cfg = Some(rpc);

        println!("Client: {:#?}", client);
        println!("RpcConfig: {:#?}", self.rpc_cfg);

        debug!("GA_connect() {:?}", self);
        Ok(())
    }

    fn disconnect(&mut self) -> Result<(), Error> {
        self.rpc_cfg = None;
        if let Some(wallet) = self.wallet.take() {
            wallet.logout()?;
        }
        debug!("GA_disconnect() {:?}", self);
        Ok(())
    }

    fn register_user(&mut self, mnemonic: String) -> Result<(), Error> {
        debug!("GA_register_user({:?}) {:?}", mnemonic, self);
        self.rpc_cfg.as_ref().or_err("session not connected")?;
        Ok(())
    }

    fn login(&mut self, mnemonic: String, password: Option<String>) -> Result<(), Error> {
        if let Some(ref wallet) = self.wallet {
            if wallet.mnemonic() != mnemonic {
                println!("user called login but was already logged-in");
                return Err(Error::Other(format!("{}", GA_ERROR)));
            } else {
                return Err(Error::Other(format!("{}", GA_OK)));
            }
        }

        if self.rpc_cfg.is_none() {
            println!("Could not login. Not connected.");
            return Err(Error::Other(format!("{}", GA_RECONNECT)));
        }

        let rpc_cfg = self.rpc_cfg.as_ref().unwrap();

        let mwallet = Wallet::login(&self.network, &rpc_cfg, &mnemonic, None);
        if let Err(msg) = mwallet {
            println!("Could not login: {}", msg);
            return Err(Error::Other(format!("{}", GA_NOT_AUTHORIZED)));
        }

        self.wallet = Some(mwallet.unwrap());
        // let wallet = self.wallet.as_ref().or_err("session not connected")?;

        self.hello()?;

        Ok(())
    }

    fn get_subaccounts(&self) -> Result<Vec<Value>, Error> {
        let wallet = self.wallet().or_err("no loaded wallet")?;
        let account = wallet.get_account()?;
        Ok(vec![account])
    }

    fn get_subaccount(&self, index: u32) -> Result<Value, Error> {
        let wallet = self.wallet().or_err("no loaded wallet")?;
        let account = wallet.get_account()?;
        Ok(account)
    }

    fn get_transactions(&self, details: Value) -> Result<Value, Error> {
        let wallet = self.wallet().or_err("no loaded wallet")?;
        let txs = wallet.get_transactions(&details)?;
        Ok(txs)
    }

    fn get_transaction_details(&self, txid: String) -> Result<Value, Error> {
        let wallet = self.wallet().or_err("no loaded wallet")?;
        let tx = wallet.get_transaction(&txid)?;
        Ok(tx)
    }

    fn get_balance(&self, details: Value) -> Result<i64, Error> {
        let wallet = self.wallet().or_err("no loaded wallet")?;
        let balance = wallet.get_balance(&details)?;

        debug!("get_balance: {:?}", balance);
        Ok(balance)
    }

    fn set_transaction_memo(
        &self,
        txid: String,
        memo: String,
        memo_type: u32,
    ) -> Result<(), Error> {
        let wallet = self.wallet().or_err("no loaded wallet")?;
        wallet.set_tx_memo(&txid, &memo[..])?;
        Ok(())
    }

    fn create_transaction(&self, details: Value) -> Result<String, Error> {
        debug!("GA_create_transaction() {:?}", details);

        let wallet = self.wallet().or_err("no loaded wallet")?;

        let tx_unsigned = wallet.create_transaction(&details)?;

        debug!("GA_create_transaction() tx_unsigned {}", tx_unsigned);
        Ok(tx_unsigned)
    }

    fn sign_transaction(&mut self, mut tx_detail_unsigned: Value) -> Result<Value, Error> {
        debug!("GA_sign_transaction() {:?}", tx_detail_unsigned);

        let wallet = self.wallet_mut().or_err("no loaded wallet")?;
        let tx_signed = wallet.sign_transaction(&tx_detail_unsigned)?;

        debug!("GA_sign_transaction() {:?}", tx_signed);

        const NO_CHANGE_INDEX: u32 = 0xffffffff;

        tx_detail_unsigned["hex"] = json!(tx_signed);
        tx_detail_unsigned["change_index"] = json!({ "btc": NO_CHANGE_INDEX });
        Ok(tx_detail_unsigned)
    }

    fn send_transaction(&self, tx_detail_signed: Value) -> Result<String, Error> {
        debug!("GDKRUST_send_transaction detail_signed: {:?}", tx_detail_signed);

        let wallet = self.wallet().or_err("no loaded wallet")?;
        let txid = wallet.send_transaction(&tx_detail_signed)?;
        Ok(txid)
    }

    fn broadcast_transaction(&self, tx_hex: String) -> Result<String, Error> {
        let wallet = self.wallet().or_err("no loaded wallet")?;
        let txid = wallet.send_raw_transaction(&tx_hex)?;
        Ok(txid)
    }

    fn get_receive_address(&self, addr_details: Value) -> Result<Value, Error> {
        let wallet = self.wallet().or_err("no loaded wallet")?;
        let address = wallet.get_receive_address(&addr_details)?;

        Ok(address)
    }

    fn get_mnemonic_passphrase(&self, _password: String) -> Result<String, Error> {
        let wallet = self.wallet().or_err("no loaded wallet")?;
        Ok(wallet.mnemonic())
    }

    fn get_available_currencies(&self) -> Result<Value, Error> {
        let wallet = self.wallet().or_err("no loaded wallet")?;
        let currencies = wallet.get_available_currencies();
        Ok(currencies)
    }

    fn get_fee_estimates(&self) -> Result<Value, Error> {
        let wallet = self.wallet().or_err("no loaded wallet")?;
        let estimates = wallet.get_fee_estimates().or_err("fee estimates unavailable")?;
        Ok(estimates.clone())
    }

    fn get_settings(&self) -> Result<Value, Error> {
        Ok(json!(&self.settings))
    }

    fn change_settings(&mut self, settings: Value) -> Result<(), Error> {
        // XXX should we allow patching just some setting fields instead of replacing it?
        self.settings = from_value(settings.clone())?;
        Ok(())
    }
}

impl RpcSession {


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
        if let Some((handler, self_context)) = self.notify {
            handler(self_context, GDKRUST_json::new(data));
        } else {
            warn!("no registered handler to receive notification");
        }
    }
}

fn json_to_rpc_config(val: &Value) -> Option<RpcConfig> {
    let url = obj_string(val, "rpc_url")?;
    let user = obj_string(val, "username")?;
    let pass = obj_string(val, "password")?;
    let network = obj_string(val, "name")?;
    let msocks5 = obj_string(val, "socks5");
    Some(RpcConfig {
        url,
        network,
        cred: Some((user, pass)),
        socks5: msocks5,
        cookie: None,
    })
}

fn obj_string(val: &Value, key: &str) -> Option<String> {
    obj_str(val, key).map(|s| s.to_string())
}

fn obj_str<'a>(val: &'a Value, key: &str) -> Option<&'a str> {
    val.get(key).and_then(|v| v.as_str())
}
