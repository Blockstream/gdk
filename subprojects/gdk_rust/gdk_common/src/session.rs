use serde_json::Value;

use crate::{
    notification::{NativeNotif, NativeType},
    NetworkParameters,
};

pub trait Session: Sized {
    fn new(network_parameters: NetworkParameters) -> Result<Self, JsonError>;
    fn handle_call(&mut self, method: &str, params: Value) -> Result<Value, JsonError>;
    fn native_notification(&mut self) -> &mut NativeNotif;
    fn network_parameters(&self) -> &NetworkParameters;

    fn build_request_agent(&self) -> Result<ureq::Agent, ureq::Error> {
        match &self.network_parameters().proxy {
            Some(proxy) if !proxy.is_empty() => {
                let proxy = ureq::Proxy::new(&proxy)?;
                Ok(ureq::AgentBuilder::new().proxy(proxy).build())
            }
            _ => Ok(ureq::agent()),
        }
    }
    fn set_native_notification(&mut self, native_type: NativeType) {
        self.native_notification().set_native(native_type)
    }
}

#[derive(serde::Serialize, Debug)]
pub struct JsonError {
    pub message: String,
    pub error: String,
}

impl JsonError {
    pub fn new<S: Into<String>>(message: S) -> Self {
        JsonError {
            message: message.into(),
            error: "id_unknown".to_string(),
        }
    }
}

impl From<serde_json::Error> for JsonError {
    fn from(e: serde_json::Error) -> Self {
        JsonError::new(e.to_string())
    }
}

impl From<JsonError> for Value {
    fn from(e: JsonError) -> Self {
        serde_json::to_value(&e).expect("standard serialize without maps")
    }
}