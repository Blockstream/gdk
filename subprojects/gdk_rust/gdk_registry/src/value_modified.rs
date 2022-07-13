use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::assets_or_icons::AssetsOrIcons;
use crate::hard_coded;
use crate::params::ElementsNetwork;
use crate::Result;

/// TODO: docs
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ValueModified {
    /// The JSON containing the assets and icons infos.
    pub(crate) value: serde_json::Value,

    /// TODO: docs
    pub(crate) last_modified: String,
}

impl ValueModified {
    pub(crate) const fn new(value: serde_json::Value, last_modified: String) -> Self {
        Self {
            value,
            last_modified,
        }
    }

    pub(crate) fn new_empty_map() -> Self {
        Self {
            value: serde_json::Value::Object(serde_json::Map::new()),
            ..Default::default()
        }
    }

    pub(crate) fn from_hard_coded(network: ElementsNetwork, what: AssetsOrIcons) -> Self {
        Self {
            value: hard_coded::value(network, what),
            ..Default::default()
        }
    }

    pub(crate) fn deserialize_into<T: DeserializeOwned>(self) -> Result<T> {
        serde_json::from_value(self.value).map_err(Into::into)
    }

    pub(crate) fn last_modified(&self) -> &'_ str {
        &self.last_modified
    }
}
