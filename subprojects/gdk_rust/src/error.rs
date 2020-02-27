use gdk_common::model::ExchangeRateError;
use gdk_electrum as electrum;
// use gdk_rpc as rpc;

#[derive(Serialize, Debug)]
pub enum Error {
    Other(String),
    Electrum(electrum::error::Error),
    Rates(ExchangeRateError), // Rpc(rpc::error::Error),
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

// impl From<rpc::error::Error> for Error {
//     fn from(e: rpc::error::Error) -> Error {
//         Error::Rpc(e)
//     }
// }
