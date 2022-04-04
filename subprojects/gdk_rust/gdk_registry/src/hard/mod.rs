use crate::{AssetEntry, AssetsOrIcons, ElementsNetwork};
use elements::{hashes::hex::FromHex, AssetId};
use serde_json::Value;
use std::collections::HashMap;

pub(crate) fn hard_coded_values(n: ElementsNetwork, t: AssetsOrIcons) -> Value {
    use AssetsOrIcons::*;
    use ElementsNetwork::*;

    // include_str! parameter must be known at compile time
    let value_str = match (n, t) {
        (Liquid, Assets) => include_str!("liquid_assets.json"),
        (LiquidTestnet, Assets) => include_str!("liquid-testnet_assets.json"),
        (ElementsRegtest, Assets) => include_str!("elements-regtest_assets.json"),
        (Liquid, Icons) => include_str!("liquid_icons.json"),
        (LiquidTestnet, Icons) => include_str!("liquid-testnet_icons.json"),
        (ElementsRegtest, Icons) => include_str!("elements-regtest_icons.json"),
    };

    serde_json::from_str(value_str).expect("checked at test time")
}

pub fn hard_coded_assets(n: ElementsNetwork) -> HashMap<AssetId, AssetEntry> {
    let value = hard_coded_values(n, AssetsOrIcons::Assets);
    serde_json::from_value(value).expect("checked at test time")
}

pub fn hard_coded_icons(n: ElementsNetwork) -> HashMap<AssetId, String> {
    let value = hard_coded_values(n, AssetsOrIcons::Icons);
    serde_json::from_value(value).expect("checked at test time")
}

/// Return the policy asset of the network, for Liquid mainnet it is the Liquid Bitcoin
pub fn policy_asset_id(n: ElementsNetwork) -> AssetId {
    use ElementsNetwork::*;

    match n {
        Liquid => {
            AssetId::from_hex("6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d")
        }
        LiquidTestnet => {
            AssetId::from_hex("144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49")
        }
        ElementsRegtest => {
            AssetId::from_hex("5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225")
        }
    }
    .expect("verified at test time")
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn verify_hard_coded_values() {
        for n in crate::ElementsNetwork::iter() {
            let _ = hard_coded_assets(n);
            let _ = hard_coded_icons(n);
            let _ = policy_asset_id(n);
        }
    }
}
