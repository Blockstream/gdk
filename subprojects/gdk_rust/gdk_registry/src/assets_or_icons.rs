use std::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub(crate) enum AssetsOrIcons {
    Assets,
    Icons,
}

impl fmt::Display for AssetsOrIcons {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str(match self {
            Self::Assets => "assets",
            Self::Icons => "icons",
        })
    }
}

impl AssetsOrIcons {
    pub(crate) const fn endpoint(&self) -> &'static str {
        match self {
            Self::Assets => "/index.json",
            Self::Icons => "/icons.json",
        }
    }

    pub(crate) const fn len() -> usize {
        2
    }

    pub(crate) fn iter() -> impl ExactSizeIterator<Item = Self> {
        [Self::Assets, Self::Icons].into_iter()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::hard_coded;
    use crate::registry_infos::{RegistryAssets, RegistryIcons};
    use crate::ElementsNetwork;
    use serde_json::Map;

    #[test]
    fn networks_iter_len_in_sync() {
        assert_eq!(AssetsOrIcons::len(), AssetsOrIcons::iter().len())
    }

    impl AssetsOrIcons {
        pub(crate) fn liquid_data(&self) -> String {
            let mut hard = hard_coded::value(ElementsNetwork::Liquid, *self);
            let data = hard.as_object_mut().unwrap();
            let other = serde_json::from_str::<Map<_, _>>(match self {
                // adds 4 more assets
                Self::Assets => include_str!("./data/test/assets.json"),

                // adds 2 more icons
                Self::Icons => include_str!("./data/test/icons.json"),
            })
            .unwrap();

            data.extend(other);
            serde_json::to_string(&data).unwrap()
        }
    }

    #[test]
    fn test_local_liquid_data() {
        let data = AssetsOrIcons::Assets.liquid_data();
        let res = serde_json::from_str::<RegistryAssets>(&data);
        assert!(res.is_ok(), "{:?}", res);

        let data = AssetsOrIcons::Icons.liquid_data();
        let res = serde_json::from_str::<RegistryIcons>(&data);
        assert!(res.is_ok(), "{:?}", res);
    }
}
