use gdk_common::error::Error as CommonError;
use gdk_common::model::ExchangeRateError;
use gdk_electrum as electrum;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Other(String),

    #[error(transparent)]
    JsonFrom(#[from] serde_json::Error),

    #[error(transparent)]
    Electrum(#[from] electrum::error::Error),

    #[error(transparent)]
    Rates(#[from] ExchangeRateError),

    #[error(transparent)]
    Common(#[from] CommonError),

    #[error(transparent)]
    Registry(#[from] gdk_registry::Error),

    #[error(
        "{}method not found: {method:?}",
        if *.in_session { "session " } else {""}
    )]
    MethodNotFound {
        method: String,
        in_session: bool,
    },

    #[error("Greenlight method not found {0}")]
    GreenlightMethodNotFound(String),
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
            Error::Electrum(electrum::error::Error::InvalidAssetId) => {
                "id_invalid_asset_id".to_string()
            }
            Error::Electrum(electrum::error::Error::FeeRateBelowMinimum(_)) => {
                "id_fee_rate_is_below_minimum".to_string()
            }
            Error::Electrum(electrum::error::Error::PinError) => "id_connection_failed".to_string(),
            Error::Electrum(electrum::error::Error::InvalidPin) => "id_invalid_pin".to_string(),
            _ => "id_unknown".to_string(),
        }
    }
}

impl From<String> for Error {
    fn from(e: String) -> Error {
        Error::Other(e)
    }
}
