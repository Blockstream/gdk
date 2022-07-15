use gdk_common::model::*;
use serde_json::Value;

use crate::{error::Error, ElectrumSession};

impl ElectrumSession {
    // dynamic dispatch shenanigans
    pub fn handle_call(&mut self, method: &str, input: Value) -> Result<Value, Error> {
        match method {
            "poll_session" => self.poll_session().map(|v| json!(v)).map_err(Into::into),

            "connect" => self.connect(&input).map(|v| json!(v)).map_err(Into::into),

            "disconnect" => self.disconnect().map(|v| json!(v)).map_err(Into::into),

            "login" => {
                self.login(serde_json::from_value(input)?).map(|v| json!(v)).map_err(Into::into)
            }
            "credentials_from_pin_data" => self
                .credentials_from_pin_data(serde_json::from_value(input)?)
                .map(|v| json!(v))
                .map_err(Into::into),
            "encrypt_with_pin" => self
                .encrypt_with_pin(&serde_json::from_value(input)?)
                .map(|v| json!(v))
                .map_err(Into::into),

            "get_block_height" => {
                self.get_block_height().map(|block_height| json!(block_height)).map_err(Into::into)
            }

            "get_subaccount_nums" => {
                self.get_subaccount_nums().map(|v| json!(v)).map_err(Into::into)
            }

            "get_subaccounts" => self.get_subaccounts().map(|v| json!(v)).map_err(Into::into),

            "get_subaccount" => get_subaccount(self, &input),

            "discover_subaccount" => self
                .discover_subaccount(serde_json::from_value(input)?)
                .map(|v| json!(v))
                .map_err(Into::into),
            "get_subaccount_root_path" => self
                .get_subaccount_root_path(serde_json::from_value(input)?)
                .map(|v| json!(v))
                .map_err(Into::into),
            "get_subaccount_xpub" => self
                .get_subaccount_xpub(serde_json::from_value(input)?)
                .map(|v| json!(v))
                .map_err(Into::into),
            "create_subaccount" => {
                let opt: CreateAccountOpt = serde_json::from_value(input)?;
                self.create_subaccount(opt).map(|v| json!(v)).map_err(Into::into)
            }
            "get_next_subaccount" => {
                let opt: GetNextAccountOpt = serde_json::from_value(input)?;
                self.get_next_subaccount(opt)
                    .map(|next_subaccount| json!(next_subaccount))
                    .map_err(Into::into)
            }
            "rename_subaccount" => {
                let opt: RenameAccountOpt = serde_json::from_value(input)?;
                self.rename_subaccount(opt).map(|_| json!(true)).map_err(Into::into)
            }
            "set_subaccount_hidden" => {
                let opt: SetAccountHiddenOpt = serde_json::from_value(input)?;
                self.set_subaccount_hidden(opt).map(|_| json!(true)).map_err(Into::into)
            }
            "update_subaccount" => {
                let opt: UpdateAccountOpt = serde_json::from_value(input)?;
                self.update_subaccount(opt).map(|_| json!(true)).map_err(Into::into)
            }

            "get_transactions" => {
                let opt: GetTransactionsOpt = serde_json::from_value(input)?;
                self.get_transactions(&opt).map(|x| txs_result_value(&x)).map_err(Into::into)
            }

            "get_transaction_hex" => {
                get_transaction_hex(self, &input).map(|v| json!(v)).map_err(Into::into)
            }
            "get_transaction_details" => self
                .get_transaction_details(input.as_str().ok_or_else(|| {
                    Error::Generic("get_transaction_details: input is not a string".into())
                })?)
                .map(|v| json!(v))
                .map_err(Into::into),
            "get_balance" => self
                .get_balance(&serde_json::from_value(input)?)
                .map(|v| json!(v))
                .map_err(Into::into),
            "set_transaction_memo" => set_transaction_memo(self, &input),
            "create_transaction" => create_transaction(self, input),
            "sign_transaction" => self
                .sign_transaction(&serde_json::from_value(input)?)
                .map_err(Into::into)
                .map(|v| json!(v)),
            "send_transaction" => self
                .send_transaction(&serde_json::from_value(input)?)
                .map(|v| json!(v))
                .map_err(Into::into),
            "broadcast_transaction" => self
                .broadcast_transaction(input.as_str().ok_or_else(|| {
                    Error::Generic("broadcast_transaction: input not a string".into())
                })?)
                .map(|v| json!(v))
                .map_err(Into::into),

            "get_receive_address" => {
                let a = self
                    .get_receive_address(&serde_json::from_value(input)?)
                    .map(|x| serde_json::to_value(&x).unwrap())
                    .map_err(Into::into);
                log::info!("gdk_rust get_receive_address returning {:?}", a);
                a
            }
            "get_previous_addresses" => self
                .get_previous_addresses(&serde_json::from_value(input)?)
                .map(|v| json!(v))
                .map_err(Into::into),

            "get_fee_estimates" => {
                self.get_fee_estimates().map_err(Into::into).and_then(|x| fee_estimate_values(&x))
            }

            "get_settings" => self.get_settings().map_err(Into::into).map(|s| json!(s)),
            "get_available_currencies" => self.get_available_currencies().map_err(Into::into),
            "change_settings" => self
                .change_settings(&serde_json::from_value(input)?)
                .map(|v| json!(v))
                .map_err(Into::into),

            "get_unspent_outputs" => self
                .get_unspent_outputs(&serde_json::from_value(input)?)
                .map(|v| json!(v))
                .map_err(Into::into),
            "load_store" => self
                .load_store(&serde_json::from_value(input)?)
                .map(|v| json!(v))
                .map_err(Into::into),
            "get_master_blinding_key" => {
                self.get_master_blinding_key().map_err(Into::into).map(|s| json!(s))
            }
            "set_master_blinding_key" => self
                .set_master_blinding_key(&serde_json::from_value(input)?)
                .map(|v| json!(v))
                .map_err(Into::into),
            "start_threads" => self.start_threads().map_err(Into::into).map(|s| json!(s)),
            "get_wallet_hash_id" => self.get_wallet_hash_id().map_err(Into::into).map(|s| json!(s)),

            "remove_account" => self.remove_account().map_err(Into::into).map(|s| json!(s)),

            // "auth_handler_get_status" => Ok(auth_handler.to_json()),
            _ => Err(Error::MethodNotFound {
                method: method.to_string(),
                in_session: true,
            }),
        }
    }
}

pub fn get_subaccount(session: &mut ElectrumSession, input: &Value) -> Result<Value, Error> {
    let index = input["subaccount"]
        .as_u64()
        .ok_or_else(|| Error::Generic("get_subaccount: index argument not found".into()))?;

    session.get_subaccount(index as u32).map(|v| json!(v)).map_err(Into::into)
}

pub fn get_transaction_hex(session: &ElectrumSession, input: &Value) -> Result<String, Error> {
    // TODO: parse txid?
    let txid = input
        .as_str()
        .ok_or_else(|| Error::Generic("get_transaction_hex: input is not a string".into()))?;

    session.get_transaction_hex(txid).map_err(Into::into)
}

pub fn txs_result_value(txs: &TxsResult) -> Value {
    json!(txs.0.clone())
}

pub fn create_transaction(session: &mut ElectrumSession, input: Value) -> Result<Value, Error> {
    let mut create_tx: CreateTransaction = serde_json::from_value(input.clone())?;

    let res = session.create_transaction(&mut create_tx).map(|v| serde_json::to_value(v).unwrap());

    Ok(match res {
        Err(ref err) => {
            log::warn!("err {:?}", err);
            let mut input = input;
            input["error"] = err.to_gdk_code().into();
            input
        }

        Ok(v) => v,
    })
}

pub fn set_transaction_memo(session: &ElectrumSession, input: &Value) -> Result<Value, Error> {
    // TODO: parse txid?.
    let txid = input["txid"]
        .as_str()
        .ok_or_else(|| Error::Generic("set_transaction_memo: missing txid".into()))?;

    let memo = input["memo"]
        .as_str()
        .ok_or_else(|| Error::Generic("set_transaction_memo: missing memo".into()))?;

    session.set_transaction_memo(txid, memo).map(|v| json!(v)).map_err(Into::into)
}

pub fn fee_estimate_values(estimates: &[FeeEstimate]) -> Result<Value, Error> {
    if estimates.is_empty() {
        // Current apps depend on this length
        return Err(Error::Generic("Expected at least one feerate".into()));
    }

    Ok(json!({ "fees": estimates }))
}
