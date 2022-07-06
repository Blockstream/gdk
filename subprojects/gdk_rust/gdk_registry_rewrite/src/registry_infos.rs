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
    pub(crate) fn contains(&self, id: &AssetId) -> bool {
        self.assets.contains_key(id)
    }

    pub(crate) fn filter(&mut self, ids: &[AssetId]) {
        self.assets.retain(|id, _| ids.contains(id));
        self.icons.retain(|id, _| ids.contains(id));
    }

    pub(crate) fn merge(&mut self, other: Self) {
        self.assets.extend(other.assets);
        self.icons.extend(other.icons);
    }

    pub(crate) const fn new(
        assets: RegistryAssets,
        icons: RegistryIcons,
    ) -> Self {
        Self { assets, icons }
    }
}
