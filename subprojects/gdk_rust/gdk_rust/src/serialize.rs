use crate::error::Error;

use gdk_common::model::*;
use gdk_electrum::ElectrumSession;
use serde_json::Value;

pub fn txs_result_value(txs: &TxsResult) -> Value {
    json!(txs.0.clone())
}

pub fn login(session: &mut ElectrumSession, input: &Value) -> Result<Value, Error> {
    let mnemonic_str = input["mnemonic"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Error::Other("login: missing mnemonic argument".into()))?;

    let pass_str = input["password"].as_str().map(|x| x.to_string());

    session
        .login(&mnemonic_str.into(), pass_str.map(Into::into))
        .map(|x| serde_json::to_value(&x).unwrap())
        .map_err(Into::into)
}

pub fn mnemonic_from_pin_data(
    session: &mut ElectrumSession,
    input: &Value,
) -> Result<Value, Error> {
    let pin = input["pin"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Error::Other("login_with_pin: missing pin argument".into()))?;
    let pin_data: PinGetDetails = serde_json::from_value(input["pin_data"].clone())?;
    session
        .mnemonic_from_pin_data(pin, pin_data)
        .map(|x| serde_json::to_value(&x).unwrap())
        .map_err(Into::into)
}

pub fn get_subaccount(session: &mut ElectrumSession, input: &Value) -> Result<Value, Error> {
    let index = input["subaccount"]
        .as_u64()
        .ok_or_else(|| Error::Other("get_subaccount: index argument not found".into()))?;

    session.get_subaccount(index as u32).map(|v| json!(v)).map_err(Into::into)
}

pub fn get_transaction_hex(session: &ElectrumSession, input: &Value) -> Result<String, Error> {
    // TODO: parse txid?
    let txid = input
        .as_str()
        .ok_or_else(|| Error::Other("get_transaction_hex: input is not a string".into()))?;

    session.get_transaction_hex(txid).map_err(Into::into)
}

pub fn create_transaction(session: &mut ElectrumSession, input: &Value) -> Result<Value, Error> {
    let mut create_tx: CreateTransaction = serde_json::from_value(input.clone())?;

    let res = session
        .create_transaction(&mut create_tx)
        .map(|v| serde_json::to_value(v).unwrap())
        .map_err(crate::error::Error::Electrum);

    Ok(match res {
        Err(ref err) => {
            warn!("err {:?}", err);
            let mut input_cloned = input.clone();
            input_cloned["error"] = err.to_gdk_code().into();
            input_cloned
        }

        Ok(v) => v,
    })
}

pub fn set_transaction_memo(session: &ElectrumSession, input: &Value) -> Result<Value, Error> {
    // TODO: parse txid?.
    let txid = input["txid"]
        .as_str()
        .ok_or_else(|| Error::Other("set_transaction_memo: missing txid".into()))?;

    let memo = input["memo"]
        .as_str()
        .ok_or_else(|| Error::Other("set_transaction_memo: missing memo".into()))?;

    session.set_transaction_memo(txid, memo).map(|v| json!(v)).map_err(Into::into)
}

pub fn fee_estimate_values(estimates: &[FeeEstimate]) -> Result<Value, Error> {
    if estimates.is_empty() {
        // Current apps depend on this length
        return Err(Error::Other("Expected at least one feerate".into()));
    }

    Ok(json!({ "fees": estimates }))
}
