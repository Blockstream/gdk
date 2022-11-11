//!
//! Executable to updated hard coded assets in the library
//!
//! to be run in gdk_regsitry folder
//!

use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::Write,
    str::FromStr,
};

use gdk_common::elements::AssetId;
use gdk_registry::{
    get_assets, init, policy_asset_id, refresh_assets, AssetCategory, AssetEntry, Config,
    ElementsNetwork, GetAssetsBuilder, RefreshAssetsParams, RegistryInfos,
};
use once_cell::unsync::Lazy;
use tempfile::TempDir;

const FEATURED_ASSETS: Lazy<Vec<AssetId>> = Lazy::new(|| {
    [
        "ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2",
        "0e99c1a6da379d1f4151fb9df90449d40d0608f6cb33a5bcbfc8c265f42bab0a",
        "18729918ab4bca843656f08d4dd877bed6641fbd596a0a963abbf199cfeb3cec",
        "78557eb89ea8439dc1a519f4eb0267c86b261068648a0f84a5c6b55ca39b66f1",
        "11f91cb5edd5d0822997ad81f068ed35002daec33986da173461a8427ac857e1",
        "52d77159096eed69c73862a30b0d4012b88cedf92d518f98bc5fc8d34b6c27c9",
        "9c11715c79783d7ba09ecece1e82c652eccbb8d019aec50cf913f540310724a6",
    ]
    .into_iter()
    .map(AssetId::from_str)
    .collect::<Result<_, _>>()
    .unwrap()
});

fn main() {
    let temp_dir = TempDir::new().unwrap();
    init(&temp_dir).unwrap();
    make_liquid_hard_coded();
    make_testnet_regtest_hard_coded()
}

fn new_policy(asset_id: AssetId, name: &str, ticker: &str) -> AssetEntry {
    AssetEntry {
        asset_id,
        name: name.into(),
        ticker: Some(ticker.into()),
        precision: 8,
        ..Default::default()
    }
}

fn make_liquid_hard_coded() {
    refresh_assets(RefreshAssetsParams::new(true, true, Config::default(), None)).unwrap();

    let RegistryInfos {
        mut assets,
        mut icons,
        ..
    } = get_assets(GetAssetsBuilder::new().category(AssetCategory::All).build()).unwrap();

    println!("Downloaded {} assets information", assets.len());
    println!("Downloaded {} assets icons", icons.len());
    assets.retain(|k, v| icons.contains_key(k) && v.verifies().unwrap_or(false));
    println!("Kept {} assets information with icons and after verification", assets.len());

    let policy_asset_id = policy_asset_id(ElementsNetwork::Liquid);
    assets.insert(policy_asset_id, new_policy(policy_asset_id, "btc", "L-BTC"));
    println!("After inserting policy asset: {}", assets.len());

    let assets_ord = BTreeMap::from_iter(assets.into_iter());
    let mut file = File::create("src/hard_coded/liquid_assets.json").unwrap();
    file.write_all(serde_json::to_string_pretty(&assets_ord).unwrap().as_bytes()).unwrap();

    let mut file = File::create("src/hard_coded/liquid_icons.json").unwrap();
    icons.retain(|k, _| k == &policy_asset_id || FEATURED_ASSETS.contains(k));
    file.write_all(serde_json::to_string_pretty(&icons).unwrap().as_bytes()).unwrap();

    println!("wrote {:?}", file);
}

fn make_testnet_regtest_hard_coded() {
    // At the moment there are no icons at https://assets-testnet.blockstream.info, so we can skip
    // the call, this could change in the future.

    for (t, name, ticker) in [
        (ElementsNetwork::LiquidTestnet, "btc", "L-TEST"), // change name to "Testnet Liquid Bitcoin"
        (ElementsNetwork::ElementsRegtest, "btc", "L-TEST"), // change name to "Regtest Liquid Bitcoin"
    ] {
        let mut assets = HashMap::new();
        let policy_asset_id = policy_asset_id(t);
        assets.insert(policy_asset_id, new_policy(policy_asset_id, name, ticker));
        let mut file = File::create(format!("src/hard_coded/{}_assets.json", t)).unwrap();

        file.write_all(serde_json::to_string_pretty(&assets).unwrap().as_bytes()).unwrap();
        println!("wrote {:?}", file);
    }
}
