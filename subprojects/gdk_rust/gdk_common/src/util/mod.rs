use std::convert::TryFrom;
use std::time::{SystemTime, UNIX_EPOCH};

mod strser;

pub use strser::StringSerialized;

pub fn is_confidential_txoutsecrets(txoutsecrets: &elements::TxOutSecrets) -> bool {
    txoutsecrets.asset_bf != elements::confidential::AssetBlindingFactor::zero()
        && txoutsecrets.value_bf != elements::confidential::ValueBlindingFactor::zero()
}

pub fn weight_to_vsize(weight: usize) -> usize {
    (weight + 3) / 4
}

pub fn now() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    // Realistic timestamps can be converted to u64
    u64::try_from(since_the_epoch.as_micros()).unwrap_or(u64::MAX)
}
