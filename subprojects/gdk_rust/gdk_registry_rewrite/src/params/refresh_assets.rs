use serde::{Deserialize, Serialize};
use std::fmt;

const BASE_URL: &str = "http://assets.blockstream.info";

/// Parameters passed to [`crate::refresh_assets`].
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct RefreshAssetsParams {
    /// Whether to return asset metadata like ticker and precision.
    #[serde(default)]
    assets: bool,

    /// Whether to return asset icons.
    #[serde(default)]
    icons: bool,

    /// Whether to update the local registry via an HTTP call to the asset
    /// registry. If `false` no network calls are performed and the locally
    /// stored value is returned.
    #[serde(default)]
    refresh: bool,

    /// Options to configure network used and registry connection.
    #[serde(default)]
    config: Config,
}

#[derive(Debug, Serialize, Deserialize)]
pub(super) struct Config {
    /// Optional proxy to use.
    proxy: Option<String>,

    url: String,

    /// Default to Liquid mainnet.
    network: ElementsNetwork,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy: None,
            url: BASE_URL.to_owned(),
            network: ElementsNetwork::Liquid,
        }
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(usize)]
pub(crate) enum ElementsNetwork {
    /// Liquid mainnet.
    Liquid = 0,

    /// Liquid testnet.
    LiquidTestnet = 1,

    /// Elements regtest.
    ElementsRegtest = 2,
}

impl fmt::Display for ElementsNetwork {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ElementsNetwork::*;

        f.write_str(match self {
            Liquid => "liquid",
            LiquidTestnet => "liquid-testnet",
            ElementsRegtest => "elements-regtest",
        })
    }
}

impl ElementsNetwork {
    /// Returns the number of possible networks.
    pub(crate) const fn len() -> usize {
        3
    }

    /// Returns an iterator over all the possible networks.
    pub(crate) fn iter() -> impl ExactSizeIterator<Item = Self> {
        [Self::Liquid, Self::LiquidTestnet, Self::ElementsRegtest].into_iter()
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_deserialization() {
        let str = r#"{"assets":true,"refresh":true}"#;
        let res = serde_json::from_str::<RefreshAssetsParams>(str);
        assert!(res.is_ok(), "{res:?}");

        let str = r#"{
            "assets":true,
            "icons":true,
            "refresh":true,
            "config":{
                "network":"liquid-testnet",
                "url":"some url",
                "proxy":"someproxy"
            }
        }"#;
        let res = serde_json::from_str::<RefreshAssetsParams>(str);
        assert!(res.is_ok(), "{res:?}");
    }

    #[test]
    fn networks_iter_len_in_sync() {
        assert_eq!(ElementsNetwork::len(), ElementsNetwork::iter().len())
    }
}
