use serde::{Deserialize, Serialize};

/// A PIN used to encrypt and decrypt
#[derive(Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Pin {
    /// The PIN doesn't actually have to be a sequence of 6 digits, it can be
    /// of any length and can also contain alphanumeric characters.
    data: String,
}

impl std::fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Pin").field(&self.data).finish()
    }
}

impl From<&str> for Pin {
    #[inline]
    fn from(s: &str) -> Self {
        s.to_owned().into()
    }
}

impl From<String> for Pin {
    #[inline]
    fn from(s: String) -> Self {
        Self {
            data: s,
        }
    }
}

impl std::str::FromStr for Pin {
    type Err = std::convert::Infallible;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(s.into())
    }
}

impl Pin {
    #[inline]
    pub(crate) fn as_bytes(&self) -> &[u8] {
        self.data.as_bytes()
    }
}
