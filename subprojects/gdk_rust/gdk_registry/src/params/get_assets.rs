use gdk_common::bitcoin::util::bip32::ExtendedPubKey;
use gdk_common::elements::AssetId;
use serde::{Deserialize, Serialize};

use super::Config;
use crate::{AssetEntry, Error};

/// Parameters passed to [`crate::get_assets`].
#[derive(Debug, Default, Serialize, Deserialize, Clone)]
pub struct GetAssetsParams {
    #[serde(default)]
    assets_id: Option<Vec<AssetId>>,

    #[serde(default)]
    xpub: Option<ExtendedPubKey>,

    #[serde(default)]
    names: Option<Vec<String>>,

    #[serde(default)]
    tickers: Option<Vec<String>>,

    #[serde(default)]
    category: Option<AssetCategory>,

    /// Options to configure network used and registry connection.
    #[serde(default)]
    pub(crate) config: Config,
}

///
#[derive(Debug, Copy, Serialize, Deserialize, Clone)]
#[serde(rename_all = "snake_case")]
pub enum AssetCategory {
    /// All the assets stored in the local copy of the registry.
    All,
    /// The assets hard coded in each gdk release.
    HardCoded,
    /// The assets with icons.
    WithIcons,
}

/// Describes how a query to [`get_assets`](crate::get_assets) should be
/// performed.
pub(crate) enum GetAssetsQuery {
    /// Fetch the assets metadata from the user's cache using a vec of
    /// [`AssetId`] and the wallet's xpub.
    FromCache(Vec<AssetId>, ExtendedPubKey),

    /// Query the local registry and filter it using a closure that takes two
    /// arguments: an `AssetEntry` representing an asset and an optional string
    /// slice representing that asset's icon (if it has one). The closure
    /// returns `true` if the given `(asset, icon)` pair is matched by these
    /// parameters.
    FromRegistry(Box<dyn Fn(&AssetEntry, Option<&str>) -> bool>),

    /// Same as `FromRegistry`, except the input asset and icon are restricted
    /// to the hard coded ones and not the whole liquid registry.
    FromHardCoded(Box<dyn Fn(&AssetEntry, Option<&str>) -> bool>),

    /// Simply return all the assets and icons in the local registry files.
    WholeRegistry,
}

impl GetAssetsParams {
    pub(crate) fn into_query(self) -> crate::Result<GetAssetsQuery> {
        match (self.assets_id, self.names, self.tickers, self.category) {
            // If both `assets_id` and any other field is set we return an
            // error.
            (Some(_), Some(_), _, _) | (Some(_), _, Some(_), _) | (Some(_), _, _, Some(_)) => {
                Err(Error::GetAssetsIdNotAlone)
            }

            (None, _, _, Some(AssetCategory::All)) => Ok(GetAssetsQuery::WholeRegistry),

            (None, None, None, None) => Err(Error::GetAssetsNoFields),

            (Some(assets_id), None, None, None) if self.xpub.is_some() => {
                Ok(GetAssetsQuery::FromCache(assets_id, self.xpub.unwrap()))
            }

            (assets_id, mut names, tickers, category) => {
                // If there's a list of names to match we uppercase them to
                // match ignoring the case. This is done outside of the closure
                // to allocate once instead of allocating every time the
                // closure is called.
                names = names.map(|v| v.iter().map(|s| s.to_ascii_uppercase()).collect::<Vec<_>>());
                let matcher: Box<dyn Fn(&AssetEntry, Option<&str>) -> bool> =
                    Box::new(move |asset, icon| {
                        let mut matched = true;
                        if let Some(assets_id) = assets_id.as_deref() {
                            matched &= assets_id.contains(&asset.asset_id);
                        }
                        if let Some(names) = names.as_deref() {
                            let uppercased = asset.name.to_ascii_uppercase();
                            matched &= names.iter().any(|name| uppercased.contains(&**name));
                        }
                        if let Some(tickers) = tickers.as_deref() {
                            if let Some(ticker) = asset.ticker.as_ref() {
                                matched &= tickers.contains(ticker);
                            } else {
                                matched = false;
                            }
                        }
                        if let Some(AssetCategory::WithIcons) = category {
                            matched &= icon.is_some();
                        }
                        matched
                    });

                if let Some(AssetCategory::HardCoded) = category {
                    Ok(GetAssetsQuery::FromHardCoded(matcher))
                } else {
                    Ok(GetAssetsQuery::FromRegistry(matcher))
                }
            }
        }
    }
}

/// A builder for the parameters passed to [`get_assets`](crate::get_assets).
#[derive(Clone)]
pub struct GetAssetsBuilder(GetAssetsParams);

impl GetAssetsBuilder {
    /// Initializes the builder.
    pub fn new() -> Self {
        Self(GetAssetsParams::default())
    }

    ///
    pub fn assets_id<I: IntoIterator<Item = AssetId>>(
        mut self,
        ids: I,
        xpub: ExtendedPubKey,
    ) -> Self {
        self.0.assets_id = Some(ids.into_iter().collect());
        self.0.xpub = Some(xpub);
        self
    }

    ///
    pub fn names<I: IntoIterator<Item = S>, S: Into<String>>(mut self, names: I) -> Self {
        self.0.names = Some(names.into_iter().map(Into::into).collect());
        self
    }

    ///
    pub fn tickers<I: IntoIterator<Item = S>, S: Into<String>>(mut self, tickers: I) -> Self {
        self.0.tickers = Some(tickers.into_iter().map(Into::into).collect());
        self
    }

    ///
    pub fn category(mut self, category: AssetCategory) -> Self {
        self.0.category = Some(category);
        self
    }

    ///
    pub fn config(mut self, config: Config) -> Self {
        self.0.config = config;
        self
    }

    /// Finishes the build and returns the generated parameters.
    pub fn build(self) -> GetAssetsParams {
        self.0
    }
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;

    #[test]
    fn test_deserialization() {
        let str = r#"{
            "assets_id":[
                "6f0279e9ed041c3d710a9f57d0c02928416460c4b722ae3457a11eec381c526d",
                "144c654344aa716d6f3abcc1ca90e5641e4e2a7f633bc09fe3baf64585819a49"
            ],
            "xpub":"tpubD97UxEEcrMpkE8yG3NQveraWveHzTAJx3KwPsUycx9ABfxRjMtiwfm6BtrY5yhF9yF2eyMg2hyDtGDYXx6gVLBox1m2Mq4u8zB2NXFhUZmm"
        }"#;
        let res = serde_json::from_str::<GetAssetsParams>(str);
        assert!(res.is_ok(), "{:?}", res);
    }
}
