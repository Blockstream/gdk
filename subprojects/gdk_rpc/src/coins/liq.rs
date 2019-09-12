use std::collections::HashMap;

use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::util::bip32;
use bitcoincore_rpc::{Client as RpcClient, RpcApi};
use elements::{Address, Transaction};
use liquid_rpc::{bitcoin_hashes::hex::FromHex, json as rpcjson, json::AssetId, LiquidRpcApi};
use secp256k1::SecretKey;
use serde_json::Value;

use crate::errors::{Error, OptionExt};
use crate::network::ElementsNetwork;
use crate::throw;
use crate::util::{self, SECP};
use crate::wallet::AddressMeta;
use crate::wally;

pub const LBTC_HEX: &str = "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d";
pub const EBTC_HEX: &str = "b2e15d0d7a0c94e4e2ce0fe6e8691b9e451377f6e46e8045a86f7c4b5d4f0f23";

lazy_static! {
    pub static ref LBTC: rpcjson::AssetId = rpcjson::AssetId::from_hex(LBTC_HEX).unwrap();
    pub static ref EBTC: rpcjson::AssetId = rpcjson::AssetId::from_hex(EBTC_HEX).unwrap();
}

pub fn address_params(net: ElementsNetwork) -> &'static elements::AddressParams {
    match net {
        ElementsNetwork::Liquid => &elements::AddressParams::LIQUID,
        ElementsNetwork::ElementsRegtest => &elements::AddressParams::ELEMENTS,
    }
}

pub fn asset_hex(net: ElementsNetwork) -> &'static str {
    match net {
        ElementsNetwork::Liquid => LBTC_HEX,
        ElementsNetwork::ElementsRegtest => EBTC_HEX,
    }
}

pub fn asset(net: ElementsNetwork) -> &'static rpcjson::AssetId {
    match net {
        ElementsNetwork::Liquid => &LBTC,
        ElementsNetwork::ElementsRegtest => &EBTC,
    }
}

/// Quick wrapper type for our RPC client that implements the Liquid API.
pub struct LiquidClient<'a>(pub &'a RpcClient);

impl<'c> bitcoincore_rpc::RpcApi for LiquidClient<'c> {
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T, bitcoincore_rpc::Error> {
        bitcoincore_rpc::RpcApi::call(self.0, cmd, args)
    }
}

impl<'c> LiquidRpcApi for LiquidClient<'c> {
    fn call<T: for<'a> serde::de::Deserialize<'a>>(
        &self,
        cmd: &str,
        args: &[serde_json::Value],
    ) -> Result<T, bitcoincore_rpc::Error> {
        bitcoincore_rpc::RpcApi::call(self.0, cmd, args)
    }
}

pub fn tx_props(raw_tx: &[u8]) -> Result<Value, Error> {
    let tx: Transaction = deserialize(&raw_tx)?;
    let weight = tx.get_weight();
    let vsize = (weight as f32 / 4.0) as u32;

    Ok(json!({
        "transaction_version": tx.version,
        "transaction_locktime": tx.lock_time,
        "transaction_size": raw_tx.len(),
        "transaction_vsize": vsize,
        "transaction_weight": weight,
    }))
}

/// Store the blinding key in the liquidd node.
pub fn store_blinding_key(rpc: &RpcClient, addr: &str, key: &SecretKey) -> Result<(), Error> {
    let rpc = LiquidClient(rpc);
    rpc.import_blinding_key(addr, key)?;
    Ok(())
}

pub fn create_transaction(rpc: &RpcClient, details: &Value) -> Result<Vec<u8>, Error> {
    let outs = util::parse_outs(&details)?;
    if outs.is_empty() {
        return Err(Error::NoRecipients);
    }

    let hex_tx = rpc.create_raw_transaction_hex(&[], &outs, None, None)?;
    Ok(hex::decode(&hex_tx)?)
}

pub fn sign_transaction<G>(
    rpc: &RpcClient,
    network: ElementsNetwork,
    details: &Value,
    change_address: &str,
    get_private_key: G,
) -> Result<Vec<u8>, Error>
where
    G: Fn(&bip32::Fingerprint, &bip32::ChildNumber) -> Result<secp256k1::SecretKey, Error>,
{
    let rpc = LiquidClient(rpc);

    let mut change_map = HashMap::new();
    change_map.insert(*asset(network), change_address.to_string());
    let fund_opts = rpcjson::FundRawTransactionOptions {
        change_address_map: Some(change_map),
        include_watching: Some(true),
        ..Default::default()
    };
    debug!("hex: {}", details["hex"].as_str().unwrap());

    let funded_result = LiquidRpcApi::fund_raw_transaction(
        &rpc,
        details["hex"].as_str().unwrap(),
        Some(&fund_opts),
        None,
    )?;
    debug!("unsigned tx raw: {:?}", hex::encode(&funded_result.hex));
    let unsigned_tx: Transaction = deserialize(&funded_result.hex)?;

    // Get the private keys needed to sign the tx.
    let mut privkeys = Vec::with_capacity(unsigned_tx.input.len());
    let mut amounts = Vec::with_capacity(unsigned_tx.input.len());
    let mut amountcommitments = Vec::with_capacity(unsigned_tx.input.len());
    let mut addresses = Vec::with_capacity(unsigned_tx.input.len());
    let mut script_pubkeys = Vec::with_capacity(unsigned_tx.input.len());
    let mut assets = Vec::with_capacity(unsigned_tx.input.len());
    let mut amount_blinders = Vec::with_capacity(unsigned_tx.input.len());
    let mut asset_blinders = Vec::with_capacity(unsigned_tx.input.len());
    for input in &unsigned_tx.input {
        let prevout = input.previous_output;
        let prevtx = RpcApi::call::<Value>(
            &rpc,
            "gettransaction",
            &[prevout.txid.to_string().into(), true.into()],
        )?;

        let mut details = prevtx.as_object().req()?["details"].as_array().req()?.iter();
        let detail = match details.find(|d| d["vout"].as_u64() == Some(u64::from(prevout.vout))) {
            None => throw!("transaction has unknown input: {}", prevout),
            Some(det) => det,
        };
        let address = detail["address"].as_str().req()?;
        let amount = detail["amount"].as_f64().or_err("own input with unknown amount")?;
        let asset_hex = detail["asset"].as_str().req()?;
        let label = detail["label"].as_str();
        let amount_blinder_hex = detail["amountblinder"].as_str().req()?;
        let asset_blinder_hex = detail["assetblinder"].as_str().req()?;

        // Parse address and label.
        let address: Address = address.parse()?;
        let label = AddressMeta::from_label(label)?;

        let prevtx_hex = hex::decode(prevtx["hex"].as_str().req()?)?;
        let prevtx_tx: Transaction = deserialize(&prevtx_hex)?;
        if !prevtx_tx.output[prevout.vout as usize].script_pubkey.is_p2sh()
            || label.fingerprint.is_none()
            || label.child.is_none()
        {
            throw!("An address that is not ours is used for coin selection: {}", address);
        }

        let sk = get_private_key(&label.fingerprint.unwrap(), &label.child.unwrap())?;
        privkeys.push(bitcoin::PrivateKey {
            key: sk,
            compressed: true,
            network: match network {
                ElementsNetwork::Liquid => bitcoin::Network::Bitcoin,
                ElementsNetwork::ElementsRegtest => bitcoin::Network::Regtest,
            },
        });
        amounts.push(rpcjson::Amount::from_btc(amount));
        let prevtx_hex = hex::decode(prevtx["hex"].as_str().req()?)?;
        let prevtx_tx: Transaction = deserialize(&prevtx_hex)?;
        amountcommitments.push(prevtx_tx.output[prevout.vout as usize].value);
        addresses.push(address);
        script_pubkeys.push(prevtx_tx.output[prevout.vout as usize].script_pubkey.clone());
        assets.push(
            AssetId::from_hex(&asset_hex).map_err(|_| Error::Other("invalid asset id".into()))?,
        );
        amount_blinders.push(hex::decode(&amount_blinder_hex)?);
        asset_blinders.push(hex::decode(&asset_blinder_hex)?);
    }

    // Blind the tx.
    let blinded_tx = LiquidRpcApi::raw_blind_raw_transaction(
        &rpc,
        &serialize(&unsigned_tx),
        &amount_blinders,
        &amounts,
        &assets,
        &asset_blinders,
        Some(true), //TODO(stevenroose) set to false and catch error?
    )?;
    debug!("blinded tx raw: {}", hex::encode(&serialize(&blinded_tx)));

    // Sign the tx.
    let mut signed_tx = blinded_tx.clone(); // keep a totally unsigned copy
    for idx in 0..blinded_tx.input.len() {
        let privkey = privkeys[idx];
        let pubkey = privkey.public_key(&SECP);

        let script_code =
            elements::Address::p2pkh(&pubkey, None, address_params(network)).script_pubkey();
        let sighash = wally::tx_get_elements_signature_hash(
            &blinded_tx,
            idx,
            &script_code,
            &amountcommitments[idx],
            bitcoin::SigHashType::All.as_u32(),
            true, // segwit
        );
        let msg = secp256k1::Message::from_slice(&sighash[..])?;
        let mut signature = SECP.sign(&msg, &privkey.key).serialize_der();
        signature.push(0x01);
        let redeem_script =
            elements::Address::p2wpkh(&pubkey, None, address_params(network)).script_pubkey();
        signed_tx.input[idx].script_sig = bitcoin::blockdata::script::Builder::new()
            .push_slice(redeem_script.as_bytes())
            .into_script();
        signed_tx.input[idx].witness.script_witness = vec![signature, pubkey.to_bytes()];
    }
    let raw = serialize(&signed_tx);
    debug!("signed tx raw: {}", hex::encode(&raw));

    Ok(raw)
}
