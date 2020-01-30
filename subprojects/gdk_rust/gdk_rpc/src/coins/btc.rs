use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::secp256k1;
use bitcoin::util::{bip143, bip32};
use bitcoin::{Network as BNetwork, PrivateKey, Transaction};
use bitcoincore_rpc::{Client as RpcClient, RpcApi};
use serde_json::Value;

use crate::errors::Error;
use crate::throw;
use crate::wallet::AddressMeta;
use gdk_common::util::{self, SECP};

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

pub fn create_transaction(rpc: &RpcClient, details: &Value) -> Result<Vec<u8>, Error> {
    //TODO(stevenroose) don't use RPC for this once Amounts lands
    let outs = util::parse_outs(&details)?;
    if outs.is_empty() {
        return Err(Error::NoRecipients);
    }

    let hex_tx = rpc.create_raw_transaction_hex(&[], &outs, None, None)?;
    Ok(hex::decode(&hex_tx)?)
}

pub fn sign_transaction<G>(
    rpc: &RpcClient,
    details: &Value,
    change_address: &str,
    get_private_key: G,
) -> Result<Vec<u8>, Error>
where
    G: Fn(&bip32::Fingerprint, &bip32::ChildNumber) -> Result<secp256k1::SecretKey, Error>,
{
    let fund_opts = bitcoincore_rpc::json::FundRawTransactionOptions {
        change_address: Some(change_address.parse().unwrap()),
        include_watching: Some(true),
        ..Default::default()
    };
    debug!("hex: {}", details["hex"].as_str().unwrap());

    // We start a loop because we need to retry when we find unusable inputs.
    'outer: loop {
        let funded_result =
            rpc.fund_raw_transaction(details["hex"].as_str().unwrap(), Some(&fund_opts), None)?;
        debug!("funded_tx raw: {:?}", hex::encode(&funded_result.hex));
        let mut unsigned_tx: Transaction = deserialize(&funded_result.hex)?;

        // Gather the details for the inputs.
        let mut input_details = Vec::with_capacity(unsigned_tx.input.len());
        for input in &unsigned_tx.input {
            let prevout = input.previous_output;
            let prevtx = rpc.get_transaction(&prevout.txid, Some(true))?;
            let details = match prevtx.details.into_iter().find(|d| d.vout == prevout.vout) {
                None => throw!("transaction has unknown input: {}", prevout),
                //None => panic!("transaction has unknown input: {}", prevout),
                Some(det) => det,
            };

            // If the output is not p2wpkh, we can't spend it for now.
            //TODO(stevenroose) implement non-p2wpkh spending
            //TODO(stevenroose) make this check better after https://github.com/rust-bitcoin/rust-bitcoin/pull/255
            let is_p2wpkh = match details.address.payload {
                bitcoin::util::address::Payload::WitnessProgram {
                    version: ref _version,
                    ref program,
                } => program.len() == 20,
                _ => false,
            };
            if !is_p2wpkh {
                warn!(
                    "Wallet received a tx on a non-p2wpkh address {}: {}",
                    details.address, prevout
                );
                // We lock the unspent so it doesn't get selected anymore.
                rpc.lock_unspent(&[prevout])?;
                continue 'outer;
            }

            input_details.push(details);
        }
        debug!("unsigned_tx: {:?}", unsigned_tx);

        // Sign the tx.
        let sighash_components = bip143::SighashComponents::new(&unsigned_tx);
        for (idx, details) in input_details.into_iter().enumerate() {
            let label = AddressMeta::from_label(details.label.as_ref())?;
            if label.fingerprint.is_none() || label.child.is_none() {
                error!(
                    "An address that is not ours is used for coin selection: {}",
                    details.address
                );
            }
            let sk = get_private_key(&label.fingerprint.unwrap(), &label.child.unwrap())?;
            let privkey = PrivateKey {
                key: sk,
                network: BNetwork::Bitcoin, // field is not used
                compressed: true,
            };
            let pubkey = privkey.public_key(&SECP);

            let script_code = bitcoin::Address::p2pkh(&pubkey, privkey.network).script_pubkey();
            let sighash = sighash_components.sighash_all(
                &unsigned_tx.input[idx],
                &script_code,
                details.amount.as_sat(),
            );
            let msg = secp256k1::Message::from_slice(&sighash[..])?;
            let mut signature = SECP.sign(&msg, &privkey.key).serialize_der().as_ref().to_vec();
            signature.push(0x01);
            unsigned_tx.input[idx].witness = vec![signature, pubkey.to_bytes()];
        }

        return Ok(serialize(&unsigned_tx));
    }
}
