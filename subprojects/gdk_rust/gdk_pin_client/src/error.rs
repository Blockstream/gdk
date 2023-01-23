use bitcoin;
use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum Error {
    #[error(transparent)]
    BitcoinHexError(#[from] bitcoin::hashes::hex::Error),

    #[error("Couldn't decrypt data: {0}")]
    Decryption(#[from] block_modes::BlockModeError),

    #[error("Failed handshake with PIN server")]
    HandshakeFailed,

    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error("Received an invalid response from the PIN server")]
    InvalidResponse,

    #[error(transparent)]
    Secp256k1(#[from] bitcoin::secp256k1::Error),

    #[error("Failed calling the PIN server")]
    ServerCallFailed,
}
