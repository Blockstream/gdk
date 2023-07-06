use std::str::FromStr;

use gdk_common::elements::AssetId;

use crate::assets_or_icons::AssetsOrIcons;
use crate::params::ElementsNetwork;
use crate::registry_infos::{RegistryAssets, RegistryIcons};

const ASSETS: [&str; ElementsNetwork::len()] = [
    include_str!("./liquid_assets.json"),
    include_str!("./liquid-testnet_assets.json"),
    include_str!("./elements-regtest_assets.json"),
];

const ICONS: [&str; ElementsNetwork::len()] = [
    include_str!("./liquid_icons.json"),
    include_str!("./liquid-testnet_icons.json"),
    include_str!("./elements-regtest_icons.json"),
];

pub(crate) fn assets(network: ElementsNetwork) -> RegistryAssets {
    serde_json::from_str(to_str(network, AssetsOrIcons::Assets)).expect("checked at test time")
}

pub(crate) fn icons(network: ElementsNetwork) -> RegistryIcons {
    serde_json::from_str(to_str(network, AssetsOrIcons::Icons)).expect("checked at test time")
}

fn to_str(network: ElementsNetwork, what: AssetsOrIcons) -> &'static str {
    match what {
        AssetsOrIcons::Assets => ASSETS[network as usize],
        AssetsOrIcons::Icons => ICONS[network as usize],
    }
}

pub(crate) fn value(network: ElementsNetwork, what: AssetsOrIcons) -> serde_json::Value {
    serde_json::from_str(to_str(network, what)).expect("checked at test time")
}
const POLICY_ASSET: [&str; ElementsNetwork::len()] = [
    "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d", // liquid
    "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49", // liquid-testnet
    "5ac9f65c0efcc4775e0baec4ec03abdde22473cd3cf33c0419ca290e0751b225", // elements-regtest
];

/// Return the policy asset of the network, for Liquid mainnet it is the
/// Liquid Bitcoin
pub fn policy_asset_id(network: ElementsNetwork) -> AssetId {
    AssetId::from_str(POLICY_ASSET[network as usize]).expect("verified at test time")
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    #[test]
    fn verify_hard_coded_values() {
        for n in crate::params::ElementsNetwork::iter() {
            let _ = assets(n);
            let _ = icons(n);
            let _ = policy_asset_id(n);
        }
    }

    #[test]
    fn serialize_deserialize_round_trip() {
        let mut file = tempfile::tempfile().unwrap();

        for network in ElementsNetwork::iter() {
            let assets = crate::hard_coded::assets(network);
            crate::file::write(&assets, &mut file).unwrap();
            let deserialized = crate::file::read::<RegistryAssets>(&mut file).unwrap();
            assert_eq!(assets, deserialized);

            let icons = crate::hard_coded::icons(network);
            crate::file::write(&icons, &mut file).unwrap();
            let deserialized = crate::file::read::<RegistryIcons>(&mut file).unwrap();
            assert_eq!(icons, deserialized);

            // NOTE: the following doesn't work because writing the
            // assets/icons to file as a `serde_json::Value` causes the cbor
            // deserializer to call the `visit_str` method of the `Deserialize`
            // implementation of `AssetId`, which as of rust-elements v0.21 is
            // not defined for non human-readable formats (like cbor).
            //
            // let assets = crate::hard_coded::value(network, AssetsOrIcons::Assets);
            // crate::file::write(&assets, &mut file).unwrap();
            // let deserialized = crate::file::read::<RegistryAssets>(&mut file).unwrap();
            // assert_eq!(serde_json::from_value::<RegistryAssets>(assets).unwrap(), deserialized);
            //
            // let icons = crate::hard_coded::value(network, AssetsOrIcons::Icons);
            // crate::file::write(&icons, &mut file).unwrap();
            // let deserialized = crate::file::read::<RegistryIcons>(&mut file).unwrap();
            // assert_eq!(serde_json::from_value::<RegistryIcons>(icons).unwrap(), deserialized);
        }
    }
}
