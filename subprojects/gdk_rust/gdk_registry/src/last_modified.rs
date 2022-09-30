use std::ops::{Index, IndexMut};

use crate::AssetsOrIcons;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct LastModified {
    assets: String,
    icons: String,
}

impl Index<AssetsOrIcons> for LastModified {
    type Output = String;

    fn index(&self, what: AssetsOrIcons) -> &Self::Output {
        match what {
            AssetsOrIcons::Assets => &self.assets,
            AssetsOrIcons::Icons => &self.icons,
        }
    }
}

impl IndexMut<AssetsOrIcons> for LastModified {
    fn index_mut(&mut self, what: AssetsOrIcons) -> &mut String {
        match what {
            AssetsOrIcons::Assets => &mut self.assets,
            AssetsOrIcons::Icons => &mut self.icons,
        }
    }
}
