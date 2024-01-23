use bitcoin;
use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error(transparent)]
    BitcoinHexToBytesError(#[from] bitcoin::hashes::hex::HexToBytesError),

    #[error("Invalid HMAC")]
    InvalidHmac,

    #[error("Couldn't decrypt data: {0}")]
    Decryption(#[from] block_modes::BlockModeError),

    #[error("Failed handshake with PIN server")]
    HandshakeFailed,

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("The PIN is not valid")]
    InvalidPin,

    #[error("Received an invalid response from the PIN server")]
    InvalidResponse,

    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),

    #[error("Failed calling the PIN server")]
    ServerCallFailed,
}

// Implementing `PartialEq` by hand because `serde_json::Error` and
// `block_modes::BlockModeError` don't implement this trait.
impl PartialEq for Error {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::BitcoinHexToBytesError(a), Self::BitcoinHexToBytesError(b)) => a == b,

            (Self::Secp256k1(a), Self::Secp256k1(b)) => a == b,

            (Self::HandshakeFailed, Self::HandshakeFailed)
            | (Self::InvalidPin, Self::InvalidPin)
            | (Self::InvalidResponse, Self::InvalidResponse)
            | (Self::ServerCallFailed, Self::ServerCallFailed) => true,

            _ => false,
        }
    }
}
