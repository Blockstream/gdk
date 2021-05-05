use crate::error::Error;

use gdk_common::model::*;
use gdk_common::session::Session;
use serde_json::Value;

pub fn balance_result_value(bal: &Balances) -> Value {
    json!(bal)
}

pub fn address_io_value(addr: &AddressIO) -> Value {
    json!({
        "address": addr.address,
        "address_type": addr.address_type.to_string(),
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
    let mut satoshi = tx.satoshi.clone();
    for (_, v) in satoshi.iter_mut() {
        *v = v.abs();
    }

    json!({
        "block_height": tx.block_height,
        "created_at": tx.created_at,

        "type": tx.type_,
        "memo": tx.memo,

        "txhash": tx.txhash,

        "satoshi": satoshi,

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

        "transaction_size" : tx.transaction_size,
        "transaction_vsize" : tx.transaction_vsize,
        "transaction_weight" : tx.transaction_weight,

        "spv_verified" : tx.spv_verified,
    })
}

pub fn txs_result_value(txs: &TxsResult) -> Value {
    Value::Array(txs.0.iter().map(txitem_value).collect())
}

pub fn subaccounts_value(subaccounts: &[AccountInfo]) -> Value {
    Value::Array(subaccounts.iter().map(subaccount_value).collect())
}

pub fn subaccount_value(subaccount: &AccountInfo) -> Value {
    json!({
        "type": subaccount.script_type,
        "pointer": subaccount.account_num,
        "required_ca": 0,
        "receiving_id": "",
        "name": subaccount.settings.name,
        "hidden": subaccount.settings.hidden,
        "has_transactions": subaccount.has_transactions,
        "satoshi": balance_result_value(&subaccount.satoshi)
    })
}

pub fn login<S, E>(session: &mut S, input: &Value) -> Result<Value, Error>
where
    E: Into<Error>,
    S: Session<E>,
{
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

pub fn login_with_pin<S, E>(session: &mut S, input: &Value) -> Result<Value, Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    let pin = input["pin"]
        .as_str()
        .map(|s| s.to_string())
        .ok_or_else(|| Error::Other("login_with_pin: missing pin argument".into()))?;
    let pin_data: PinGetDetails = serde_json::from_value(input["pin_data"].clone())?;
    session
        .login_with_pin(pin, pin_data)
        .map(|x| serde_json::to_value(&x).unwrap())
        .map_err(Into::into)
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

pub fn create_transaction<S, E>(session: &mut S, input: &Value) -> Result<Value, Error>
where
    E: Into<Error>,
    S: Session<E>,
{
    let mut create_tx: CreateTransaction = serde_json::from_value(input.clone())?;

    let res = session
        .create_transaction(&mut create_tx)
        .map(|v| serde_json::to_value(v).unwrap())
        .map_err(Into::into);

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

    session.set_transaction_memo(txid, memo).map(|v| json!(v)).map_err(Into::into)
}

pub fn fee_estimate_values(estimates: &[FeeEstimate]) -> Result<Value, Error> {
    if estimates.is_empty() {
        // Current apps depend on this length
        return Err(Error::Other("Expected at least one feerate".into()));
    }

    Ok(json!({ "fees": estimates }))
}
