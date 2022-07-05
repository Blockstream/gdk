use std::collections::HashMap;

use elements::AssetId;
use serde::{Deserialize, Serialize};

use crate::asset_entry::AssetEntry;

/// Asset informations returned by both [`crate::get_assets`] and
/// [`crate::refresh_assets`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegistryInfos {
    /// Assets metadata.
    assets: HashMap<AssetId, AssetEntry>,

    /// Assets icons: the hashmap value is a Base64 encoded image.
    icons: HashMap<AssetId, String>,
}
