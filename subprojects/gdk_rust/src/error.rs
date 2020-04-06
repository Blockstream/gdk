use gdk_common::model::ExchangeRateError;
use gdk_electrum as electrum;
// use gdk_rpc as rpc;

#[derive(Debug)]
pub enum Error {
    Other(String),
    JsonFrom(serde_json::Error),
    Electrum(electrum::error::Error),
    Rates(ExchangeRateError), // Rpc(rpc::error::Error),
}

impl Error {
    /// Convert the error to a GDK-compatible code.
    pub fn to_gdk_code(&self) -> &'static str {
        // Unhandles error codes:
        // id_no_amount_specified
        // id_fee_rate_is_below_minimum
        // id_invalid_replacement_fee_rate
        // id_send_all_requires_a_single_output

        // TODO rpc
        match *self {
            Error::Electrum(electrum::error::Error::InsufficientFunds) => "id_insufficient_funds",
            _ => "id_unknown",
        }
    }

    pub fn gdk_display(&self) -> String {
        match self {
            Error::Other(s) => s.clone(),
            Error::JsonFrom(ref json) => format!("{}", json),
            Error::Electrum(ref electrum) => format!("{}", electrum),
            Error::Rates(ref rates_err) => format!("{:?}", rates_err),
        }
    }
}

impl From<String> for Error {
    fn from(e: String) -> Error {
        Error::Other(e)
    }
}

impl From<electrum::error::Error> for Error {
    fn from(e: electrum::error::Error) -> Error {
        Error::Electrum(e)
    }
}

impl From<ExchangeRateError> for Error {
    fn from(e: ExchangeRateError) -> Error {
        Error::Rates(e)
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::JsonFrom(e)
    }
}

// impl From<rpc::error::Error> for Error {
//     fn from(e: rpc::error::Error) -> Error {
//         Error::Rpc(e)
//     }
// }
