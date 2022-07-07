//!
//! Executable to updated hard coded assets in the library
//!
//! to be run in gdk_regsitry folder
//!

use elements::AssetId;
use gdk_registry::{
    init, policy_asset_id, refresh_assets, AssetEntry, Config, ElementsNetwork,
    RefreshAssetsParams, RegistryInfos,
};
use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::Write,
};
use tempfile::TempDir;

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
    let RegistryInfos {
        mut assets,
        mut icons,
        ..
    } = refresh_assets(RefreshAssetsParams::new(true, true, true, Config::default())).unwrap();

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
    icons.retain(|k, _| k == &policy_asset_id);
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
