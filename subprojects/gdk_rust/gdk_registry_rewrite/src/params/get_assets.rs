use bitcoin::util::bip32::ExtendedPubKey;
use elements::AssetId;
use serde::{Deserialize, Serialize};

use super::Config;

/// Parameters passed to [`crate::get_assets`].
#[derive(Debug, Serialize, Deserialize)]
pub struct GetAssetsParams {
    assets_id: Vec<AssetId>,

    xpub: ExtendedPubKey,

    /// Options to configure network used and registry connection.
    #[serde(default)]
    config: Config,
}

impl GetAssetsParams {
    pub(crate) fn explode(self) -> (Vec<AssetId>, ExtendedPubKey, Config) {
        (self.assets_id, self.xpub, self.config)
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
