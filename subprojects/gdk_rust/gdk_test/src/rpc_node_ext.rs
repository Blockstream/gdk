use electrsd::bitcoind::bitcoincore_rpc::{Client, RpcApi};
use gdk_common::bitcoin::amount::Denomination;
use gdk_common::bitcoin::Amount;
use gdk_common::log;
use serde_json::{Map, Value};

use crate::Result;

/// Extension trait for [`bitcoin_rpc::client::Client`] providing a more
/// ergonomic API.
pub trait RpcNodeExt {
    /// Mine blocks immediately to a specified address (before the RPC call returns)
    ///
    /// # Arguments
    ///
    /// * `nblocks` - How many blocks are generated immediately
    /// * `address` - The address to send the newly generated bitcoin to (default = `RpcNodeExt::getnewaddress`)
    // /// * `maxtries` - How many iterations to try (default = `1000000`)
    fn generate(&self, nblocks: u32, address: Option<&str>) -> Result<Vec<String>>;

    /// Returns a new Bitcoin address for receiving payments.
    ///
    /// # Arguments
    ///
    /// * `label` - The label name for the address to be linked to (default = `""`)
    /// * `kind` - The address type to use (default = `"p2sh-segwit"`)
    fn getnewaddress(&self, label: Option<&str>, address_type: Option<&str>) -> Result<String>;

    /// Creates a new asset and returns the asset's hex identifier.
    fn issueasset(&self, satoshi: u64) -> Result<String>;

    /// Send an amount to a given address.
    ///
    /// # Arguments
    ///
    /// * `address` - The bitcoin address to send to
    /// * `satoshi` - The amount in satoshi to send
    /// * `asset` - todo
    fn sendtoaddress(&self, address: &str, satoshi: u64, asset: Option<&str>) -> Result<String>;
}

/// Takes a tuple of values that implement [`ToJson`] and returns an array of
/// [`Value`]s by converting each item in the tuple.
macro_rules! values {
    ($($value:expr),* $(,)?) => {
        [$($value.to_json(),)*]
    }
}

impl RpcNodeExt for Client {
    fn generate(&self, nblocks: u32, address: Option<&str>) -> Result<Vec<String>> {
        let address = address.unwrap_or(&*self.getnewaddress(None, None)?).to_owned();
        let params = values!(nblocks, address);
        let block_hashes = self.call("generatetoaddress", &params)?;
        if nblocks < 10 {
            log::info!("generate result {:?}", block_hashes);
        } else {
            log::info!("generated {} blocks", nblocks);
        }
        Ok(block_hashes)
    }

    fn getnewaddress(&self, label: Option<&str>, address_type: Option<&str>) -> Result<String> {
        let label = label.unwrap_or("");
        let address_type = address_type.unwrap_or("p2sh-segwit");
        let params = values!(label, address_type);
        Ok(self.call("getnewaddress", &params)?)
    }

    fn issueasset(&self, satoshi: u64) -> Result<String> {
        let btc = Amount::from_sat(satoshi).to_string_in(Denomination::Bitcoin);
        let params = values!(btc, 0);
        let res = self.call::<Map<_, _>>("issueasset", &params)?;
        Ok(res["asset"].as_str().unwrap().to_owned())
    }

    fn sendtoaddress(&self, address: &str, satoshi: u64, asset: Option<&str>) -> Result<String> {
        let btc = Amount::from_sat(satoshi).to_string_in(Denomination::Bitcoin);

        log::info!("`sendtoaddress` called w/ address {} and btc {}", address, btc);
        let params = match asset {
            Some(asset) => {
                values!(address, btc, "", "", false, false, 1, "UNSET", false, asset).to_vec()
            }

            None => values!(address, btc).to_vec(),
        };

        let txid = self.call("sendtoaddress", &params)?;

        log::info!("`sendtoaddress` received txid {}", txid);

        Ok(txid)
    }
}

trait ToJson {
    fn to_json(self) -> serde_json::Value;
}

/// Implements `ToJson` for types that already implement
/// `Into<serde_json::Value>`.
macro_rules! into_json {
    ($type:ty) => {
        impl ToJson for $type {
            fn to_json(self) -> Value {
                self.into()
            }
        }
    };
}

into_json!(u32);
into_json!(bool);
into_json!(&str);
into_json!(Value);
into_json!(Map<String, Value>);

impl ToJson for Option<u32> {
    fn to_json(self) -> Value {
        match self {
            Some(num) => num.into(),
            None => Value::Null,
        }
    }
}

impl ToJson for Option<&str> {
    fn to_json(self) -> Value {
        match self {
            Some(s) => s.into(),
            None => Value::Null,
        }
    }
}
