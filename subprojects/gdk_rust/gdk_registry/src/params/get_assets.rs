use gdk_common::bitcoin::util::bip32::ExtendedPubKey;
use gdk_common::elements::AssetId;
use serde::{Deserialize, Serialize};

use super::Config;
use crate::AssetEntry;

/// Parameters passed to [`crate::get_assets`].
#[derive(Debug, Serialize, Deserialize)]
pub struct GetAssetsParams {
    #[serde(default)]
    assets_id: Option<Vec<AssetId>>,

    xpub: ExtendedPubKey,

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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum AssetCategory {
    All,
    WithIcons,
}

/// Describes how a query to [`get_assets`](crate::get_assets) should be
/// performed.
pub(crate) enum GetAssetsQuery {
    /// Fetch the assets metadata from the user's cache using a vec of
    /// [`AssetId`] and the wallet's xpub.
    FromCache(Vec<AssetId>, ExtendedPubKey),

    /// Query the whole registry and filter it using a closure that takes two
    /// arguments: an `AssetEntry` representing an asset and an optional string
    /// slice representing that asset's icon (if it has one). The closure
    /// returns `true` if the given `(asset, icon)` pair is matched by these
    /// parameters.
    FromRegistry(Box<dyn Fn(&AssetEntry, Option<&str>) -> bool>),

    /// Simply return all the assets and icons in the local registry files.
    WholeRegistry,
}

impl GetAssetsParams {
    #[cfg(test)]
    pub(crate) fn new_cache_query<I>(
        assets_id: I,
        xpub: ExtendedPubKey,
        config: Option<Config>,
    ) -> Self
    where
        I: IntoIterator<Item = AssetId>,
    {
        Self {
            assets_id: Some(assets_id.into_iter().collect()),
            xpub,
            config: config.unwrap_or_default(),
            names: None,
            tickers: None,
            category: None,
        }
    }

    pub(crate) fn into_query(self) -> crate::Result<GetAssetsQuery> {
        match (self.assets_id, self.names, self.tickers, self.category) {
            // If both `assets_id` and any other field is set we return an
            // error.
            (Some(_), Some(_), _, _) | (Some(_), _, Some(_), _) | (Some(_), _, _, Some(_)) => {
                // return error
                todo!()
            }

            (None, _, _, Some(AssetCategory::All)) => Ok(GetAssetsQuery::WholeRegistry),

            (None, None, None, None) => todo!(), // return error

            (Some(assets_id), None, None, None) => {
                Ok(GetAssetsQuery::FromCache(assets_id, self.xpub))
            }

            (None, names, tickers, category) => {
                let matcher: Box<dyn Fn(&AssetEntry, Option<&str>) -> bool> =
                    Box::new(move |asset, icon| {
                        let mut matched = true;
                        if let Some(names) = names.as_deref() {
                            matched &= names.iter().any(|name| asset.name.contains(&**name));
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

                Ok(GetAssetsQuery::FromRegistry(matcher))
            }
        }
    }
}

#[cfg(test)]
mod test {
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
