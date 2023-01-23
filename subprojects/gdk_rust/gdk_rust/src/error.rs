use gdk_common::error::Error as CommonError;
use gdk_common::exchange_rates;
use gdk_common::model::ExchangeRateError;
use gdk_common::ureq;
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

    #[error("The {0} currency pair is not currently supported")]
    UnsupportedCurrencyPair(exchange_rates::Pair),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Ureq(#[from] ureq::Error),
}

impl Error {
    /// Convert the error to a GDK-compatible code.
    pub fn to_gdk_code(&self) -> String {
        match self {
            Error::Electrum(err) => err.to_gdk_code(),
            _ => "id_unknown".to_string(),
        }
    }
}

impl From<String> for Error {
    fn from(e: String) -> Error {
        Error::Other(e)
    }
}
