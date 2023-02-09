//!
//! Executable to updated hard coded assets in the library
//!
//! to be run in gdk_regsitry folder
//!

use std::{collections::HashMap, fs::File, io::Write, str::FromStr};

use gdk_common::elements::AssetId;
use gdk_common::once_cell::unsync::Lazy;
use gdk_common::ureq;
use gdk_registry::{policy_asset_id, AssetEntry, ElementsNetwork};

const LIQUID_ASSETS_ENDPOINT: &str = "http://assets.blockstream.info";

const LIQUID_ICONS_ENDPOINT: &str = "http://assets.blockstream.info/icons.json";

const LIQUID_POLICY_ASSET: Lazy<AssetId> = Lazy::new(|| policy_asset_id(ElementsNetwork::Liquid));

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
    .collect::<std::result::Result<_, _>>()
    .unwrap()
});

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
type Assets = HashMap<AssetId, AssetEntry>;
type Icons = HashMap<AssetId, String>;

fn main() -> Result<()> {
    let agent = ureq::Agent::new();

    let mut icons = liquid_icons(&agent)?;

    let assets = liquid_assets(&agent, &icons)?;

    icons.retain(|asset_id, _| {
        asset_id == &*LIQUID_POLICY_ASSET || FEATURED_ASSETS.contains(asset_id)
    });

    println!("Kept {} icons after filtering", icons.len());

    let mut file = File::create("src/hard_coded/liquid_icons.json")?;
    file.write_all(serde_json::to_string_pretty(&icons)?.as_bytes())?;

    let mut file = File::create("src/hard_coded/liquid_assets.json")?;
    file.write_all(serde_json::to_string_pretty(&assets)?.as_bytes())?;

    Ok(())
}

fn liquid_icons(agent: &ureq::Agent) -> Result<Icons> {
    let icons = agent.get(LIQUID_ICONS_ENDPOINT).call()?.into_json::<Icons>()?;

    println!("Downloaded {} assets icons", icons.len());

    Ok(icons)
}

fn liquid_assets(agent: &ureq::Agent, icons: &HashMap<AssetId, String>) -> Result<Assets> {
    let mut assets = agent.get(LIQUID_ASSETS_ENDPOINT).call()?.into_json::<Assets>()?;

    println!("Downloaded {} assets information", assets.len());

    assets.retain(|id, entry| icons.contains_key(id) && entry.verifies().is_ok());

    println!("Kept {} assets information with icons and after verification", assets.len());

    assets.insert(*&*LIQUID_POLICY_ASSET, new_policy(*&*LIQUID_POLICY_ASSET, "btc", "L-BTC"));

    println!("After inserting policy asset: {}", assets.len());

    Ok(assets)
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
