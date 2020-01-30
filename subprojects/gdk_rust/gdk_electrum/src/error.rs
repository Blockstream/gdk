#[derive(Debug)]
pub enum WGError {
    Generic(String),
    UnknownCall,
    DB(sled::Error),
    Bitcoin(bitcoin::util::Error),
    BitcoinBIP32Error(bitcoin::util::bip32::Error),
    BitcoinConsensus(bitcoin::consensus::encode::Error),
    JSON(serde_json::error::Error),
    StdIOError(std::io::Error),
    Hex(hex::FromHexError),
}

impl std::convert::From<serde_json::error::Error> for WGError {
    fn from(err: serde_json::error::Error) -> Self {
        WGError::JSON(err)
    }
}

impl std::convert::From<bitcoin::util::bip32::Error> for WGError {
    fn from(err: bitcoin::util::bip32::Error) -> Self {
        WGError::BitcoinBIP32Error(err)
    }
}

impl std::convert::From<String> for WGError {
    fn from(err: String) -> Self {
        WGError::Generic(err)
    }
}

impl std::convert::From<std::io::Error> for WGError {
    fn from(err: std::io::Error) -> Self {
        WGError::StdIOError(err)
    }
}

impl std::convert::From<sled::Error> for WGError {
    fn from(err: sled::Error) -> Self {
        WGError::DB(err)
    }
}

impl std::convert::From<bitcoin::consensus::encode::Error> for WGError {
    fn from(err: bitcoin::consensus::encode::Error) -> Self {
        WGError::BitcoinConsensus(err)
    }
}

impl std::convert::From<hex::FromHexError> for WGError {
    fn from(err: hex::FromHexError) -> Self {
        WGError::Hex(err)
    }
}
