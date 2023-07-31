use std::fmt::{self, Display};
use std::ops::{Deref, DerefMut};
use std::str::FromStr;

/// A wrapper for anything that implements FromStr to make it serde::Deserialize. Will turn
/// Display to serde::Serialize.
/// https://github.com/rs-ipfs/rust-ipfs/blob/4bce4679de6c4f206864de843f14e2c273560dcb/http/src/v0/support/serdesupport.rs

#[derive(Clone, Copy)]
pub struct StringSerialized<T>(pub T);

impl<T> From<T> for StringSerialized<T> {
    fn from(t: T) -> Self {
        StringSerialized(t)
    }
}

impl<T> Deref for StringSerialized<T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T> DerefMut for StringSerialized<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: fmt::Debug> fmt::Debug for StringSerialized<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(fmt)
    }
}

impl<T: fmt::Display> fmt::Display for StringSerialized<T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(fmt)
    }
}

impl<T: Display> serde::Serialize for StringSerialized<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_str(self)
    }
}

impl<'de, T: FromStr> serde::Deserialize<'de> for StringSerialized<T>
where
    //<T as FromStr>::Err: Display,
    T: Sized,
{
    fn deserialize<D>(deserializer: D) -> Result<StringSerialized<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map(StringSerialized)
            //.map_err(serde::de::Error::custom)
            .map_err(|_| serde::de::Error::custom("invalid value"))
    }
}
