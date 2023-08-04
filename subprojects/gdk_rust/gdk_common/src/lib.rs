pub mod be;
pub mod descriptor;
pub mod error;
pub mod exchange_rates;
pub mod mnemonic;
pub mod model;
pub mod network;
pub mod notification;
pub mod password;
pub mod scripts;
pub mod session;
pub mod slip132;
pub mod state;
pub mod store;
pub mod util;
pub mod wally;
pub mod aes {
    pub use aes::*;
    pub use aes_gcm_siv::*;
}

pub use bitcoin;
pub use ciborium;
pub use electrum_client;
pub use elements;
pub use error::*;
pub use log;
pub use miniscript;
pub use network::*;
pub use once_cell;
pub use rand;
pub use state::State;
pub use ureq;

pub static EC: once_cell::sync::Lazy<bitcoin::secp256k1::Secp256k1<bitcoin::secp256k1::All>> =
    once_cell::sync::Lazy::new(|| {
        let mut ctx = bitcoin::secp256k1::Secp256k1::new();
        let mut rng = rand::thread_rng();
        ctx.randomize(&mut rng);
        ctx
    });
