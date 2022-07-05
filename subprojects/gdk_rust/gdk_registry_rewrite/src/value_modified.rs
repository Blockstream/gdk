use serde::{Deserialize, Serialize};

use crate::assets_or_icons::AssetsOrIcons;
use crate::hard_coded;
use crate::params::ElementsNetwork;

/// TODO: docs
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ValueModified {
    /// The JSON containing the assets and icons infos.
    value: serde_json::Value,

    /// TODO: docs
    last_modified: String,
}

impl ValueModified {
    pub(crate) fn from_hard_coded(
        network: ElementsNetwork,
        what: AssetsOrIcons,
    ) -> Self {
        Self {
            value: hard_coded::value(network, what),
            ..Default::default()
        }
    }
}
