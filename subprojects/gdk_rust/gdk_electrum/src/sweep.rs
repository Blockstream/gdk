use crate::error::Error;
use crate::session::determine_electrum_url;
use gdk_common::be::{BEScript, BEScriptConvert};
use gdk_common::bitcoin::{Address, Network, PublicKey};
use gdk_common::electrum_client::{Client, ElectrumApi};
use gdk_common::error::Error::InvalidAddressType;
use gdk_common::model::UnspentOutput;
use gdk_common::network::NetworkParameters;
use gdk_common::scripts::p2pkh_script;
use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone, Default)]
pub struct SweepOpt {
    /// The network parameters
    pub network: NetworkParameters,

    /// Maximum timeout for network calls,
    /// the final timeout in seconds is roughly equivalent to 2 + `timeout` * 2
    ///
    /// Cannot be specified if `network.proxy` is non empty.
    pub timeout: Option<u8>,

    /// The public key to sweep
    pub public_key: String,

    /// The address type to sweep
    pub address_type: String,

    /// The private blinding key to unblind with
    ///
    /// None if not Liquid
    pub blinding_private_key: Option<String>,
}

impl SweepOpt {
    /// Build the Electrum client
    pub fn build_client(&self) -> Result<Client, Error> {
        let url = determine_electrum_url(&self.network)?;
        url.build_client(self.network.proxy.as_deref(), self.timeout)
    }

    /// Compute the script_pubkey and script_code
    pub fn scripts(&self) -> Result<(BEScript, BEScript), Error> {
        let public_key = PublicKey::from_str(&self.public_key)?;
        let script_code = p2pkh_script(&public_key).into_be();
        let script_pubkey = match self.address_type.as_str() {
            "p2pkh" => script_code.clone(),
            "p2wpkh" => Address::p2wpkh(&public_key, Network::Regtest)?.script_pubkey().into_be(),
            "p2sh-p2wpkh" => {
                Address::p2shwpkh(&public_key, Network::Regtest)?.script_pubkey().into_be()
            }
            _ => return Err(Error::Common(InvalidAddressType)),
        };
        Ok((script_pubkey, script_code))
    }
}

pub fn get_unspent_outputs_for_private_key(opt: &SweepOpt) -> Result<Vec<UnspentOutput>, Error> {
    let client = opt.build_client()?;
    let (script_pubkey, script_code) = opt.scripts()?;
    let listunspent = client.script_list_unspent(&script_pubkey.clone().into_bitcoin())?;
    // FIXME: (leo) listunpent does not work with Liquid
    // TODO: (leo) if Liquid unblind here
    let utxos: Vec<UnspentOutput> = listunspent
        .iter()
        .map(|unspent| UnspentOutput {
            address_type: opt.address_type.clone(),
            block_height: unspent.height as u32,
            pointer: 0,
            pt_idx: unspent.tx_pos as u32,
            satoshi: unspent.value,
            subaccount: 0,
            txhash: unspent.tx_hash.to_string(),
            is_internal: false,
            user_path: vec![],
            scriptpubkey: script_pubkey.clone(),
            sequence: None,
            script_code: script_code.to_hex(),
            public_key: opt.public_key.clone(),
            skip_signing: false,
            is_blinded: None,
            is_confidential: None,
            asset_id: None,
            asset_blinder: None,
            amount_blinder: None,
            asset_commitment: None,
            value_commitment: None,
            nonce_commitment: None,
        })
        .collect();
    Ok(utxos)
}
