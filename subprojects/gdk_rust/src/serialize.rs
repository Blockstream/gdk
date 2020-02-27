use crate::error::Error;

use bitcoin::util::address::AddressType;
use gdk_common::*;
use gdk_common::model::{ExchangeRate, ExchangeRateError, ExchangeRateErrorType, ExchangeRateOk};
use serde_json::Value;

pub fn address_result_value(addr: &AddressResult) -> Value {
    json!({"address": addr.0})
}

pub fn balance_result_value(bal: &BalanceResult) -> Value {
    json!(bal.0)
}

pub fn address_type_str(addr_type: &AddressType) -> &'static str {
    match addr_type {
        AddressType::P2pkh => "p2pkh",
        AddressType::P2sh => "p2sh",
        AddressType::P2wpkh => "p2wpkh",
        AddressType::P2wsh => "p2wsh",
    }
}

pub fn address_io_value(addr: &AddressIO) -> Value {
    json!({
        "address": addr.address,
        "address_type": address_type_str(&addr.address_type),
        "addressee": addr.addressee,
        "is_output": addr.is_output,
        "is_relevant": addr.is_relevant,
        "is_spent": addr.is_spent,
        "pointer": addr.pointer,
        "pt_idx": addr.pt_idx,
        "satoshi": addr.satoshi,
        "script_type": addr.script_type,
        "subaccount": addr.subaccount,
        "subtype": addr.subtype,
    })
}

pub fn txitem_value(tx: &TxListItem) -> Value {
    let inputs = Value::Array(tx.inputs.iter().map(address_io_value).collect());
    let outputs = Value::Array(tx.inputs.iter().map(address_io_value).collect());

    json!({
        "block_height": 1,
        "created_at": tx.created_at, // TODO: is this a unix timestmap?

        "type": tx.type_,
        "memo": tx.memo,

        "txhash": tx.txhash,
        "transaction": bitcoin::hashes::hex::ToHex::to_hex(tx.transaction.as_slice()),

        "satoshi": balance_result_value(&tx.satoshi),

        "rbf_optin": tx.rbf_optin,
        "cap_cpfp": tx.cap_cpfp, // TODO
        "can_rbf": tx.can_rbf, // TODO
        "has_payment_request": tx.has_payment_request, // TODO
        "server_signed": tx.server_signed,
        "user_signed": tx.user_signed,
        "instant": tx.instant,

        "fee": tx.fee,
        "fee_rate": tx.fee_rate,

        "addressees": tx.addressees, // notice the extra "e" -- its intentional
        "inputs": inputs, // tx.input.iter().map(format_gdk_input).collect(),
        "outputs": outputs, //tx.output.iter().map(format_gdk_output).collect(),
    })
}

pub fn txs_result_value(txs: &TxsResult) -> Value {
    Value::Array(txs.0.iter().map(txitem_value).collect())
}

pub fn subaccounts_value(subaccounts: &Vec<Subaccount>) -> Value {
    Value::Array(subaccounts.iter().map(subaccount_value).collect())
}

pub fn subaccount_value(subaccount: &Subaccount) -> Value {
    json!({
        "type": subaccount.type_,
        "pointer": 0,
        "required_ca": 0,
        "receiving_id": "",
        "name": subaccount.name,
        "has_transactions": subaccount.has_transactions,
        "satoshi": balance_result_value(&subaccount.satoshi)
    })
}

pub fn login<S, E>(session: &mut S, input: &Value) -> Result<(), Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    let mnemonic = input["mnemonic"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Error::Other("login: missing mnemonic argument".into()))?;

    let pass = input["password"].as_str().map(|x| x.to_string());

    session.login(mnemonic, pass).map_err(Into::into)
}

pub fn get_subaccount<S, E>(session: &S, input: &Value) -> Result<Value, Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    let index = input["index"]
        .as_u64()
        .ok_or_else(|| Error::Other("get_subaccount: index argument not found".into()))?;

    let num_confs = input["num_confs"].as_u64().unwrap_or(0);

    session
        .get_subaccount(index as u32, num_confs as u32)
        .map(|x| subaccount_value(&x))
        .map_err(Into::into)
}

pub fn get_transaction_details<S, E>(session: &S, input: &Value) -> Result<Value, Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    // TODO: parse txid?
    let txid = input
        .as_str()
        .ok_or_else(|| Error::Other("get_transaction_details: input is not a string".into()))?;

    session.get_transaction_details(txid).map_err(Into::into)
}

pub fn set_transaction_memo<S, E>(session: &S, input: &Value) -> Result<Value, Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    // TODO: parse txid?.
    let txid = input["txid"]
        .as_str()
        .ok_or_else(|| Error::Other("get_transaction_details: missing txid".into()))?;

    let memo = input["memo"]
        .as_str()
        .ok_or_else(|| Error::Other("get_transaction_details: missing memo".into()))?;

    let memo_type = input["memo_type"]
        .as_u64()
        .ok_or_else(|| Error::Other("get_transaction_details: missing memo_type".into()))?;

    session.set_transaction_memo(txid, memo, memo_type as u32).map(|v| json!(v)).map_err(Into::into)
}

pub fn get_balance<S, E>(session: &S, input: &Value) -> Result<Value, Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    let num_confs = input["num_confs"].as_u64().unwrap_or(0);

    let subaccount = input["subaccount"].as_u64().map(|x| x as u32);

    let bal = session.get_balance(num_confs as u32, subaccount).map_err(Into::into)?;

    Ok(balance_result_value(&BalanceResult::new_btc(bal)))
}

pub fn send_transaction<S, E>(session: &S, input: &Value) -> Result<Value, Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    let txid = session.send_transaction(input).map_err(Into::into)?;
    Ok(json!({"error": "", "txid": txid}))
}

pub fn fee_estimate_values(estimates: &Vec<FeeEstimate>) -> Result<Value, Error> {
    if estimates.len() == 0 {
        // Current apps depend on this length
        return Err(Error::Other("Expected at least one feerate".into()));
    }

    Ok(json!({ "fees": estimates }))
}
