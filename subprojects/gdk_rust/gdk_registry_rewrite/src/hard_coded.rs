use crate::assets_or_icons::AssetsOrIcons;
use crate::params::ElementsNetwork;

const ASSETS: [&str; ElementsNetwork::len()] = [
    include_str!("../../gdk_registry/src/hard/liquid_assets.json"),
    include_str!("../../gdk_registry/src/hard/liquid-testnet_assets.json"),
    include_str!("../../gdk_registry/src/hard/elements-regtest_assets.json"),
];

const ICONS: [&str; ElementsNetwork::len()] = [
    include_str!("../../gdk_registry/src/hard/liquid_icons.json"),
    include_str!("../../gdk_registry/src/hard/liquid-testnet_icons.json"),
    include_str!("../../gdk_registry/src/hard/elements-regtest_icons.json"),
];

pub(crate) fn value(
    network: ElementsNetwork,
    what: AssetsOrIcons,
) -> serde_json::Value {
    serde_json::from_str(match what {
        AssetsOrIcons::Assets => ASSETS[network as usize],
        AssetsOrIcons::Icons => ICONS[network as usize],
    })
    .expect("checked at test time")
}
