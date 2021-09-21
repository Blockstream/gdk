use gdk_common::model::ExchangeRateError;
use gdk_electrum as electrum;

#[derive(Debug)]
pub enum Error {
    Other(String),
    JsonFrom(serde_json::Error),
    Electrum(electrum::error::Error),
    Rates(ExchangeRateError),
    Common(gdk_common::error::Error),
}

impl Error {
    /// Convert the error to a GDK-compatible code.
    pub fn to_gdk_code(&self) -> String {
        // Unhandles error codes:
        // id_no_amount_specified
        // id_invalid_replacement_fee_rate
        // id_send_all_requires_a_single_output

        match *self {
            Error::Electrum(electrum::error::Error::InsufficientFunds) => {
                "id_insufficient_funds".to_string()
            }
            Error::Electrum(electrum::error::Error::InvalidAddress) => {
                "id_invalid_address".to_string()
            }
            Error::Electrum(electrum::error::Error::NonConfidentialAddress) => {
                "id_nonconfidential_addresses_not".to_string()
            }
            Error::Electrum(electrum::error::Error::InvalidAmount) => {
                "id_invalid_amount".to_string()
            }
            Error::Electrum(electrum::error::Error::FeeRateBelowMinimum) => {
                "id_fee_rate_is_below_minimum".to_string()
            }
            Error::Electrum(electrum::error::Error::PinError) => "id_connection_failed".to_string(),
            Error::Electrum(electrum::error::Error::InvalidPin) => "id_invalid_pin".to_string(),
            _ => "id_unknown".to_string(),
        }
    }

    pub fn gdk_display(&self) -> String {
        match self {
            Error::Other(s) => s.clone(),
            Error::JsonFrom(ref json) => format!("{}", json),
            Error::Electrum(ref electrum) => format!("{}", electrum),
            Error::Rates(ref rates_err) => format!("{:?}", rates_err),
            Error::Common(ref err) => format!("{:?}", err),
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
