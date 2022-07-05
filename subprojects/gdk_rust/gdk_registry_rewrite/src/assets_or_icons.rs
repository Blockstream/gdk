use std::fmt;

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
#[repr(usize)]
pub(crate) enum AssetsOrIcons {
    Assets = 0,
    Icons = 1,
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
    pub(crate) const fn len() -> usize {
        2
    }

    pub(crate) fn iter() -> impl ExactSizeIterator<Item = Self> {
        [Self::Assets, Self::Icons].into_iter()
    }
}
