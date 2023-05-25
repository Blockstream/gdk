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
}

#[cfg(test)]
pub(crate) mod test {
    use super::*;
    use crate::hard_coded;
    use crate::registry_infos::{RegistryAssets, RegistryIcons};
    use crate::ElementsNetwork;
    use gdk_common::once_cell::unsync::Lazy;
    use serde_json::{to_string, Map, Value};
    use std::cell::RefCell;

    thread_local! {
        static LIQUID_ASSETS: Lazy<RefCell<Map<String, Value>>> = Lazy::new(|| {
            let mut hard = match hard_coded::value(ElementsNetwork::Liquid, AssetsOrIcons::Assets) {
                Value::Object(map) => map,
                _ => unreachable!(),
            };
            let other = serde_json::from_str::<Map<_, _>>(include_str!("./data/test/assets.json")).unwrap();
            hard.extend(other);
            RefCell::new(hard)
        });

        static LIQUID_ICONS: Lazy<RefCell<Map<String, Value>>> = Lazy::new(|| {
            let mut hard = match hard_coded::value(ElementsNetwork::Liquid, AssetsOrIcons::Icons) {
                Value::Object(map) => map,
                _ => unreachable!(),
            };
            let other = serde_json::from_str::<Map<_, _>>(include_str!("./data/test/icons.json")).unwrap();
            hard.extend(other);
            RefCell::new(hard)
        });

        static LAST_MODIFIED: Lazy<RefCell<String>> = Lazy::new(|| RefCell::new(String::from( "Thu, 14 Jul 2022 06:05:26 GMT")));
    }

    pub(crate) fn update_liquid_data() {
        let extra_assets =
            serde_json::from_str::<Map<_, _>>(include_str!("./data/test/extra_assets.json"))
                .unwrap();

        let extra_icons =
            serde_json::from_str::<Map<_, _>>(include_str!("./data/test/extra_icons.json"))
                .unwrap();

        LIQUID_ASSETS.with(move |assets| {
            let assets = &mut *assets.borrow_mut();
            assets.extend(extra_assets);
        });

        LIQUID_ICONS.with(move |icons| {
            let icons = &mut *icons.borrow_mut();
            icons.extend(extra_icons);
        });

        LAST_MODIFIED.with(move |when| {
            let when = &mut *when.borrow_mut();
            *when = "Wed, 27 Jul 2022 10:27:47 GMT".into();
        });
    }

    #[test]
    fn networks_iter_len_in_sync() {
        assert_eq!(AssetsOrIcons::len(), AssetsOrIcons::iter().len())
    }

    impl AssetsOrIcons {
        pub(crate) fn iter() -> impl ExactSizeIterator<Item = Self> {
            [Self::Assets, Self::Icons].into_iter()
        }

        pub(crate) fn liquid_data(&self) -> (String, String) {
            let data = match self {
                Self::Assets => LIQUID_ASSETS.with(|map| to_string(&*map.borrow())),
                Self::Icons => LIQUID_ICONS.with(|map| to_string(&*map.borrow())),
            }
            .unwrap();

            let last_modified = LAST_MODIFIED.with(|when| when.borrow().clone());

            (data, last_modified)
        }

        pub(crate) fn emptify_icons(&self) -> (String, String) {
            let (data, _) = self.liquid_data();

            let data = match self {
                Self::Assets => data,
                Self::Icons => {
                    let mut map = serde_json::from_str::<Map<_, _>>(&data).unwrap();
                    for (_k, v) in map.iter_mut() {
                        *v = Value::String("".to_string())
                    }
                    to_string(&map).unwrap()
                }
            };

            (data, "new_last_modified".to_string())
        }
    }

    #[test]
    fn test_local_liquid_data() {
        let data = AssetsOrIcons::Assets.liquid_data();
        let res = serde_json::from_str::<RegistryAssets>(&data.0);
        assert!(res.is_ok(), "{:?}", res);

        let data = AssetsOrIcons::Icons.liquid_data();
        let res = serde_json::from_str::<RegistryIcons>(&data.0);
        assert!(res.is_ok(), "{:?}", res);
    }
}
