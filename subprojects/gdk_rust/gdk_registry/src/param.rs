use crate::Error;
use bitcoin::util::bip32::ExtendedPubKey;
use elements::AssetId;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, str::FromStr};

const BASE_URL: &str = "https://assets.blockstream.info";

/// The parameters given to the [`crate::refresh_assets`] call that will influence the result
/// [`crate::RefreshAssetsResult`].
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct RefreshAssetsParam {
    /// When true, it returns asset metadata (like ticker and precision)
    #[serde(default)]
    pub assets: bool,

    /// When true, it returns asset icons
    #[serde(default)]
    pub icons: bool,

    /// When true, an HTTP call is made to the asset registry, if there are new assets they will be
    /// downloaded and local cache updated.
    /// When false, the local cached value is returned
    #[serde(default)]
    pub refresh: bool,

    /// Optional configuration for network used and registry connection
    #[serde(default)]
    pub config: Config,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Config {
    /// Optional proxy to use
    pub proxy: Option<String>,

    pub url: String,

    /// defaults to Liquid mainnet
    pub network: ElementsNetwork,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy: None,
            url: BASE_URL.to_string(),
            network: ElementsNetwork::Liquid,
        }
    }
}

impl RefreshAssetsParam {
    pub(crate) fn asked(&self) -> Result<Vec<AssetsOrIcons>, Error> {
        if !self.assets && !self.icons {
            Err(Error::BothAssetsIconsFalse)
        } else {
            Ok(self.assets().into_iter().chain(self.icons().into_iter()).collect())
        }
    }

    fn icons(&self) -> Option<AssetsOrIcons> {
        self.icons.then(|| AssetsOrIcons::Icons)
    }

    fn assets(&self) -> Option<AssetsOrIcons> {
        self.assets.then(|| AssetsOrIcons::Assets)
    }

    pub(crate) fn network(&self) -> ElementsNetwork {
        self.config.network
    }

    pub(crate) fn url(&self, what: AssetsOrIcons) -> String {
        format!("{}{}", self.config.url, what.endpoint())
    }

    pub(crate) fn agent(&self) -> Result<Option<ureq::Agent>, Error> {
        if self.refresh {
            match self.config.proxy.as_ref() {
                Some(proxy) if !proxy.is_empty() => {
                    let proxy = ureq::Proxy::new(&proxy)?;
                    Ok(Some(ureq::AgentBuilder::new().proxy(proxy).build()))
                }
                _ => Ok(Some(ureq::agent())),
            }
        } else {
            Ok(None)
        }
    }
}

/// The parameters given to the [`crate::get_assets`].
#[derive(Serialize, Deserialize, Debug)]
pub struct GetAssetsParams {
    pub(crate) assets_id: Vec<AssetId>,

    /// The wallet's xpub key used to access the encrypted asset's cache.
    pub(crate) xpub: ExtendedPubKey,

    /// Optional configuration for network used and registry connection
    #[serde(default)]
    pub(crate) config: Config,
}

/// Discriminate the elements network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ElementsNetwork {
    /// Liquid mainnet
    #[serde(rename = "liquid")]
    Liquid,

    /// Liquid testnet
    #[serde(rename = "liquid-testnet")]
    LiquidTestnet,

    /// Elements regtest
    #[serde(rename = "elements-regtest")]
    ElementsRegtest,
}

impl Display for ElementsNetwork {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use ElementsNetwork::*;
        match self {
            Liquid => write!(f, "liquid"),
            LiquidTestnet => write!(f, "liquid-testnet"),
            ElementsRegtest => write!(f, "elements-regtest"),
        }
    }
}

impl FromStr for ElementsNetwork {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use ElementsNetwork::*;
        match s {
            "liquid" => Ok(Liquid),
            "liquid-testnet" => Ok(LiquidTestnet),
            "elements-regtest" => Ok(ElementsRegtest),
            s => Err(Error::InvalidNetwork(s.to_string())),
        }
    }
}

impl ElementsNetwork {
    /// Iterate over all variants of this enum
    pub fn iter() -> impl Iterator<Item = Self> {
        [Self::Liquid, Self::LiquidTestnet, Self::ElementsRegtest].into_iter()
    }
}

/// This enum discriminate if we are talking about assets metadata or assets icons
#[derive(Hash, Clone, Copy, PartialEq, Eq, Debug)]
pub enum AssetsOrIcons {
    /// Assets
    Assets,

    /// Icons
    Icons,
}

impl Display for AssetsOrIcons {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AssetsOrIcons::Assets => write!(f, "assets"),
            AssetsOrIcons::Icons => write!(f, "icons"),
        }
    }
}

impl AssetsOrIcons {
    /// Iterate over all the variants of this enum
    pub fn iter() -> impl Iterator<Item = Self> {
        [Self::Icons, Self::Assets].into_iter()
    }

    /// Return assets registry file name according to this variant
    pub fn endpoint(&self) -> &str {
        match self {
            AssetsOrIcons::Assets => "/index.json",
            AssetsOrIcons::Icons => "/icons.json",
        }
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_methods() {
        use AssetsOrIcons::*;
        let mut refresh_assets = RefreshAssetsParam {
            icons: true,
            assets: true,
            refresh: false,
            ..Default::default()
        };
        assert_eq!(refresh_assets.asked().unwrap(), vec![Assets, Icons]);
        refresh_assets.assets = false;
        assert_eq!(refresh_assets.asked().unwrap(), vec![Icons]);
        refresh_assets.icons = false;
        assert!(refresh_assets.asked().is_err());
        refresh_assets.assets = true;
        assert_eq!(refresh_assets.asked().unwrap(), vec![Assets]);

        assert_eq!(refresh_assets.network(), ElementsNetwork::Liquid);
    }

    #[test]
    fn test_iter_exhaustive() {
        // if test fails to compile because you added a variant in AssetsOrIcons or ElementsNetwork,
        // remember to update the `iter()` method to consider every variant
        use AssetsOrIcons::*;
        let mut count = 0;
        for t in AssetsOrIcons::iter() {
            match t {
                Assets => count += 1,
                Icons => count += 1,
            }
        }
        assert_eq!(2, count);

        use ElementsNetwork::*;
        let mut count = 0;
        for t in ElementsNetwork::iter() {
            match t {
                Liquid => count += 1,
                LiquidTestnet => count += 1,
                ElementsRegtest => count += 1,
            }
        }
        assert_eq!(3, count);
    }

    #[test]
    fn test_deser() {
        let test_input = r#"{"assets":true,"icons":true,"refresh":true,"config":{"network":"liquid-testnet","url":"some url","proxy":"someproxy"}}"#;
        let _: RefreshAssetsParam = serde_json::from_str(test_input).unwrap();

        let test_input = r#"{"assets":true,"refresh":true}"#;
        let _: RefreshAssetsParam = serde_json::from_str(test_input).unwrap();
    }
}
