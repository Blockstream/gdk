use std::{
    collections::{HashMap, HashSet},
    sync::{atomic::AtomicBool, Arc, Mutex, RwLock},
    time::SystemTime,
};

use gdk_common::{
    be::BEOutPoint,
    bitcoin::bip32::Fingerprint,
    exchange_rates::{ExchangeRatesCache, ExchangeRatesCacher},
    log,
    model::*,
    notification::NativeNotif,
    session::{JsonError, Session},
    ureq, NetworkParameters,
};
use serde_json::Value;

use crate::{
    account::Account, error::Error, interface::ElectrumUrl, socksify, ElectrumSession,
    DEFAULT_GAP_LIMIT,
};

impl ExchangeRatesCacher for ElectrumSession {
    fn xr_cache(&self) -> ExchangeRatesCache {
        Arc::clone(&self.xr_cache)
    }
}

impl Session for ElectrumSession {
    fn new(network_parameters: NetworkParameters) -> Result<Self, JsonError> {
        let url = determine_electrum_url(&network_parameters)?;
        let gap_limit = network_parameters.gap_limit.unwrap_or(DEFAULT_GAP_LIMIT);

        Ok(Self {
            proxy: socksify(network_parameters.proxy.as_deref()),
            network: network_parameters,
            url,
            accounts: Arc::new(RwLock::new(HashMap::<u32, Account>::new())),
            notify: NativeNotif::new(),
            handles: vec![],
            user_wants_to_sync: Arc::new(AtomicBool::new(false)),
            last_network_call_succeeded: Arc::new(AtomicBool::new(false)),
            timeout: None,
            store: None,
            is_initialized: false,
            master_xpub_fingerprint: Fingerprint::default(),
            recent_spent_utxos: Arc::new(RwLock::new(HashSet::<BEOutPoint>::new())),
            xr_cache: ExchangeRatesCache::default(),
            available_currencies: None,
            first_sync: Arc::new(AtomicBool::new(true)),
            gap_limit,
            fee_fetched_at: Arc::new(Mutex::new(SystemTime::UNIX_EPOCH)),
        })
    }

    fn native_notification(&mut self) -> &mut NativeNotif {
        &mut self.notify
    }

    fn network_parameters(&self) -> &NetworkParameters {
        &self.network
    }

    fn build_request_agent(&self) -> Result<ureq::Agent, ureq::Error> {
        gdk_common::network::build_request_agent(self.proxy.as_deref())
    }

    fn handle_call(&mut self, method: &str, input: Value) -> Result<Value, JsonError> {
        match method {
            "connect" => self.connect(&input).to_json(),

            "disconnect" => self.disconnect().to_json(),

            "login_wo" => self.login_wo(serde_json::from_value(input)?).to_json(),
            "credentials_from_pin_data" => {
                self.credentials_from_pin_data(&serde_json::from_value(input)?).to_json()
            }
            "encrypt_with_pin" => self.encrypt_with_pin(&serde_json::from_value(input)?).to_json(),
            "decrypt_with_pin" => self.decrypt_with_pin(&serde_json::from_value(input)?).to_json(),

            "get_block_height" => self.get_block_height().to_json(),

            "get_subaccount_nums" => self.get_subaccount_nums().to_json(),

            "get_subaccounts" => self.get_subaccounts().to_json(),

            "get_accounts_settings" => self.get_accounts_settings().to_json(),

            "discover_subaccount" => {
                self.discover_subaccount(serde_json::from_value(input)?).to_json()
            }
            "create_subaccount" => {
                let opt: CreateAccountOpt = serde_json::from_value(input)?;
                self.create_subaccount(opt).to_json()
            }
            "get_next_subaccount" => {
                let opt: GetNextAccountOpt = serde_json::from_value(input)?;
                self.get_next_subaccount(opt).to_json()
            }
            "get_last_empty_subaccount" => {
                let opt: GetLastEmptyAccountOpt = serde_json::from_value(input)?;
                self.get_last_empty_subaccount(opt).to_json()
            }
            "update_subaccount" => {
                let opt: UpdateAccountOpt = serde_json::from_value(input)?;
                self.update_subaccount(opt).to_json()
            }

            "get_transactions" => {
                let opt: GetTransactionsOpt = serde_json::from_value(input)?;
                self.get_transactions(&opt).map(|x| txs_result_value(&x)).map_err(Into::into)
            }

            "get_transaction_hex" => get_transaction_hex(self, &input).to_json(),
            "set_transaction_memo" => set_transaction_memo(self, &input),
            "get_scriptpubkey_data" => self
                .get_scriptpubkey_data(input.as_str().ok_or_else(|| {
                    Error::Generic("get_scriptpubkey_data: input is not a string".into())
                })?)
                .to_json(),
            "broadcast_transaction" => self
                .broadcast_transaction(input.as_str().ok_or_else(|| {
                    Error::Generic("broadcast_transaction: input not a string".into())
                })?)
                .to_json(),

            "get_receive_address" => {
                let a = self.get_receive_address(&serde_json::from_value(input)?).to_json();
                log::info!("gdk_rust get_receive_address returning {:?}", a);
                a
            }
            "get_previous_addresses" => {
                self.get_previous_addresses(&serde_json::from_value(input)?).to_json()
            }

            "get_fee_estimates" => {
                self.get_fee_estimates().map_err(Into::into).and_then(|x| fee_estimate_values(&x))
            }
            "get_min_fee_rate" => self.get_min_fee_rate().to_json(),

            "get_settings" => self.get_settings().to_json(),
            "get_available_currencies" => {
                self.get_available_currencies(&serde_json::from_value(input)?).to_json()
            }
            "change_settings" => self.change_settings(&serde_json::from_value(input)?).to_json(),

            "get_unspent_outputs" => {
                self.get_unspent_outputs(&serde_json::from_value(input)?).to_json()
            }

            "load_store" => self.load_store(&serde_json::from_value(input)?).to_json(),
            "set_fingerprint" => self
                .set_fingerprint(input.as_str().ok_or_else(|| {
                    Error::Generic("set_fingerprint: input is not a string".into())
                })?)
                .to_json(),
            "load_blob" => self.load_blob().to_json(),
            "save_blob" => self.save_blob(serde_json::from_value(input)?).to_json(),
            "get_memos" => self.get_memos().to_json(),
            "get_master_blinding_key" => self.get_master_blinding_key().to_json(),
            "set_master_blinding_key" => {
                self.set_master_blinding_key(&serde_json::from_value(input)?).to_json()
            }
            "start_threads" => self.start_threads().to_json(),
            "get_address_data" => self.get_address_data(serde_json::from_value(input)?).to_json(),

            "remove_account" => self.remove_account().to_json(),

            // "auth_handler_get_status" => Ok(auth_handler.to_json()),
            _ => Err(Error::MethodNotFound {
                method: method.to_string(),
                in_session: true,
            })
            .map_err(Into::into),
        }
    }
}

pub fn determine_electrum_url(network: &NetworkParameters) -> Result<ElectrumUrl, Error> {
    if let Some(true) = network.use_tor {
        if let Some(electrum_onion_url) = network.electrum_onion_url.as_ref() {
            if !electrum_onion_url.is_empty() {
                return Ok(ElectrumUrl::Plaintext(electrum_onion_url.into()));
            }
        }
    }
    let electrum_url = network
        .electrum_url
        .as_ref()
        .ok_or_else(|| Error::Generic("network url is missing".into()))?;
    if electrum_url == "" {
        return Err(Error::Generic("network url is empty".into()));
    }

    if network.electrum_tls.unwrap_or(false) {
        Ok(ElectrumUrl::Tls(electrum_url.into(), network.validate_domain.unwrap_or(false)))
    } else {
        Ok(ElectrumUrl::Plaintext(electrum_url.into()))
    }
}

impl From<Error> for JsonError {
    fn from(e: Error) -> Self {
        JsonError {
            message: e.to_string(),
            error: e.to_gdk_code(),
        }
    }
}

pub fn get_transaction_hex(session: &ElectrumSession, input: &Value) -> Result<String, Error> {
    // TODO: parse txid?
    let txid = input
        .as_str()
        .ok_or_else(|| Error::Generic("get_transaction_hex: input is not a string".into()))?;

    session.get_transaction_hex(txid)
}

pub fn txs_result_value(txs: &TxsResult) -> Value {
    json!(txs.0.clone())
}

pub fn set_transaction_memo(session: &ElectrumSession, input: &Value) -> Result<Value, JsonError> {
    // TODO: parse txid?.
    let txid = input["txid"]
        .as_str()
        .ok_or_else(|| JsonError::new("set_transaction_memo: missing txid"))?;

    let memo = input["memo"]
        .as_str()
        .ok_or_else(|| JsonError::new("set_transaction_memo: missing memo"))?;

    session.set_transaction_memo(txid, memo).to_json()
}

pub fn fee_estimate_values(estimates: &[FeeEstimate]) -> Result<Value, JsonError> {
    if estimates.is_empty() {
        // Current apps depend on this length
        return Err(JsonError::new("Expected at least one feerate"));
    }

    Ok(json!({ "fees": estimates }))
}

trait ToJson {
    fn to_json(self) -> Result<Value, JsonError>;
}

impl<V, E> ToJson for Result<V, E>
where
    V: serde::Serialize,
    JsonError: From<E>,
{
    fn to_json(self) -> Result<Value, JsonError> {
        Ok(self.map(serde_json::to_value)??)
    }
}

impl<V> ToJson for Option<V>
where
    V: serde::Serialize,
{
    fn to_json(self) -> Result<Value, JsonError> {
        Ok(match self {
            None => json!(null),
            Some(v) => serde_json::to_value(v)?,
        })
    }
}
