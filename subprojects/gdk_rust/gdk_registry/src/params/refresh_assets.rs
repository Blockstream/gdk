use std::fmt;

use serde::{Deserialize, Serialize};

use crate::assets_or_icons::AssetsOrIcons;
use crate::Result;

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

impl RefreshAssetsParams {
    pub(crate) fn agent(&self) -> Result<ureq::Agent> {
        match &self.config.proxy {
            Some(proxy) if !proxy.is_empty() => {
                let proxy = ureq::Proxy::new(&proxy)?;
                Ok(ureq::AgentBuilder::new().proxy(proxy).build())
            }

            _ => Ok(ureq::agent()),
        }
    }

    pub(crate) const fn network(&self) -> ElementsNetwork {
        self.config.network
    }

    /// Creates a new [`crate::RefreshAssetsParams`].
    pub const fn new(assets: bool, icons: bool, refresh: bool, config: Config) -> Self {
        Self {
            assets,
            icons,
            refresh,
            config,
        }
    }

    pub(crate) const fn should_refresh(&self) -> bool {
        self.refresh
    }

    pub(crate) fn url(&self, what: AssetsOrIcons) -> String {
        format!("{}{}", self.config.url, what.endpoint())
    }

    pub(crate) const fn wants_something(&self) -> bool {
        self.assets | self.icons
    }

    pub(crate) const fn wants_assets(&self) -> bool {
        self.assets
    }

    pub(crate) const fn wants_icons(&self) -> bool {
        self.icons
    }
}

#[derive(Debug, Serialize, Deserialize)]
/// Network configurations used when fetching assets via HTTP.
pub struct Config {
    /// Defaults to Liquid mainnet.
    network: ElementsNetwork,

    /// Optional proxy to use.
    proxy: Option<String>,

    url: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: ElementsNetwork::Liquid,
            proxy: None,
            url: BASE_URL.to_owned(),
        }
    }
}

/// Discriminate the elements network
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[repr(usize)]
pub enum ElementsNetwork {
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
        assert!(res.is_ok(), "{:?}", res);

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
        assert!(res.is_ok(), "{:?}", res);
    }

    #[test]
    fn networks_iter_len_in_sync() {
        assert_eq!(ElementsNetwork::len(), ElementsNetwork::iter().len())
    }
}
