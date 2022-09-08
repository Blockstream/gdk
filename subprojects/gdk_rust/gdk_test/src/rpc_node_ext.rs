use bitcoin::secp256k1::SecretKey;
use electrsd::bitcoind::bitcoincore_rpc::{Client, RpcApi};
use serde_json::Value;

use crate::Result;

/// Extension trait for [`bitcoin_rpc::client::Client`] providing a more
/// ergonomic API.
pub trait RpcNodeExt {
    /// Returns the raw, hex-encoded transaction data.
    ///
    /// # Arguments
    ///
    /// * `txid` - The transaction id
    /// * `verbose` - If `false` return a string, otherwise return a json object (default = `false`)
    /// * `blockhash` - The block in which to look for the transaction (default
    /// = `null`)
    fn getrawtransaction(
        &self,
        txid: &str,
        verbose: bool,
        blockhash: Option<&str>,
    ) -> Result<Value>;

    /// Adds an address or script (in hex) that can be watched as if it were in
    /// your wallet but cannot be used to spend.
    ///
    /// # Arguments
    ///
    /// * `address` - The Bitcoin address or hex-encoded script
    /// * `label`   - An optional label (default = `""`)
    /// * `rescan`  - Rescan the wallet for transactions (default = `true`)
    /// * `p2sh`    - Add the P2SH version of the script as well (default = `false`)
    fn importaddress(
        &self,
        address: &str,
        label: Option<&str>,
        rescan: bool,
        p2sh: bool,
    ) -> Result<()>;

    /// Imports a private blinding key in hex for a Confidential Transaction
    /// (CT) address.
    ///
    /// # Arguments
    ///
    /// * `address` - The address to which the private blinding key belongs
    /// * `priv_key` - The private key
    fn importblindingkey(&self, address: &str, priv_key: &SecretKey) -> Result<()>;
}

/// Takes a tuple of values that implement [`ToJson`] and returns an array of
/// [`Value`]s by converting each item in the tuple.
macro_rules! values {
    ($($value:ident),* $(,)?) => {
        [$($value.to_json(),)*]
    }
}

impl RpcNodeExt for Client {
    fn getrawtransaction(
        &self,
        txid: &str,
        verbose: bool,
        blockhash: Option<&str>,
    ) -> Result<Value> {
        let params = values!(txid, verbose, blockhash);
        Ok(self.call("getrawtransaction", &params)?)
    }

    fn importaddress(
        &self,
        address: &str,
        label: Option<&str>,
        rescan: bool,
        p2sh: bool,
    ) -> Result<()> {
        let label = label.unwrap_or_default();
        let params = values!(address, label, rescan, p2sh);
        Ok(self.call("importaddress", &params)?)
    }

    fn importblindingkey(&self, address: &str, priv_key: &SecretKey) -> Result<()> {
        let priv_key = priv_key.display_secret().to_string();
        let params = values!(address, priv_key);
        Ok(self.call("importblindingkey", &params)?)
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

into_json!(bool);
into_json!(&str);

impl ToJson for Option<&str> {
    fn to_json(self) -> Value {
        match self {
            Some(s) => s.into(),
            None => Value::Null,
        }
    }
}
