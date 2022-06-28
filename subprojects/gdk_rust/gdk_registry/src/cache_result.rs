use elements::AssetId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::result::{AssetEntry, RegistryResult};

/// Contains the result of the [`crate::get_assets`] call.
#[derive(Debug, Serialize, Deserialize, Clone, Default, PartialEq, Eq)]
pub struct CacheResult {
    /// Assets metadata.
    assets: HashMap<AssetId, AssetEntry>,

    /// Assets icons: the hashmap value is a Base64 encoded image.
    icons: HashMap<AssetId, String>,

    /// Assets missing from the asset registry.
    missing: Vec<AssetId>,
}

impl CacheResult {
    /// Splits the asset ids based on whether they are already contained in the
    /// cache.
    pub(crate) fn split_present<I>(&self, ids: I) -> (Vec<AssetId>, Vec<AssetId>)
    where
        I: IntoIterator<Item = AssetId>,
    {
        ids.into_iter().partition(|id| self.contains(id))
    }

    /// Filters the cache against a group of `AssetId`s, only keeping the
    /// `assets` and `icons` that match an `AssetId`.
    pub(crate) fn filter(&mut self, query: &[AssetId]) {
        self.assets.retain(|id, _| query.contains(&id));
        self.icons.retain(|id, _| query.contains(&id));
    }

    /// Returns whether the assets contain a certain `AssetId`.
    pub(crate) fn contains(&self, asset: &AssetId) -> bool {
        self.assets.contains_key(asset)
    }

    /// Extends the cache's assets map.
    pub(crate) fn extend_assets<A>(&mut self, assets: A)
    where
        A: IntoIterator<Item = (AssetId, AssetEntry)>,
    {
        self.assets.extend(assets);
    }

    /// Extends the cache's icons map.
    pub(crate) fn extend_icons<I>(&mut self, icons: I)
    where
        I: IntoIterator<Item = (AssetId, String)>,
    {
        self.icons.extend(icons);
    }

    /// Adds the asset ids to the internal vector of the current assets missing
    /// from the registry.
    pub(crate) fn register_missing(&mut self, assets: Vec<AssetId>) {
        self.missing.extend(assets);
    }

    /// Returns the ids of all the assets cached as missing from the full
    /// registry.
    pub(crate) fn missing_assets(&self) -> &[AssetId] {
        &self.missing
    }
}

impl From<CacheResult> for RegistryResult {
    fn from(cache: CacheResult) -> Self {
        Self {
            assets: cache.assets,
            icons: cache.icons,
        }
    }
}
