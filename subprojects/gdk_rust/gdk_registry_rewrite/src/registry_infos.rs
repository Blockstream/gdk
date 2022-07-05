use std::collections::HashMap;

use elements::AssetId;
use serde::{Deserialize, Serialize};

use crate::asset_entry::AssetEntry;

pub(crate) type RegistryAssets = HashMap<AssetId, AssetEntry>;
pub(crate) type RegistryIcons = HashMap<AssetId, String>;

/// Asset informations returned by both [`crate::get_assets`] and
/// [`crate::refresh_assets`].
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RegistryInfos {
    /// Assets metadata.
    assets: RegistryAssets,

    /// Assets icons: the hashmap value is a Base64 encoded image.
    icons: RegistryIcons,
}

impl RegistryInfos {
    pub(crate) const fn new(
        assets: RegistryAssets,
        icons: RegistryIcons,
    ) -> Self {
        Self { assets, icons }
    }
}
