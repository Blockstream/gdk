mod strser;

pub use strser::StringSerialized;

pub fn is_confidential_txoutsecrets(txoutsecrets: &elements::TxOutSecrets) -> bool {
    txoutsecrets.asset_bf == elements::confidential::AssetBlindingFactor::zero()
        && txoutsecrets.value_bf == elements::confidential::ValueBlindingFactor::zero()
}
