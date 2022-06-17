use crate::{AssetEntry, Error};
use elements::AssetId;
use log::{info, log_enabled, Level};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashMap;
use std::{
    fs::File,
    io::{BufReader, BufWriter, Seek},
};

/// This struct is persisted locally and contains the `value` returned by the registry and the
/// `last_modified` date returned  by the sever so that the following query to the server could avoid
/// downloading data if those are not updated.
#[derive(Serialize, Deserialize, PartialEq, Eq, Debug, Clone)]
pub struct ValueModified {
    /// The last modified returned by the registry server, it is a date but saved as string as it
    /// is presented back to the server as is.
    pub last_modified: String,

    /// The JSON containing the assets or the icons information.
    pub value: Value,
}

pub(crate) fn read<V: DeserializeOwned>(file: &mut File) -> Result<V, Error> {
    file.seek(std::io::SeekFrom::Start(0))?;
    if log_enabled!(Level::Info) {
        info!("file {:?} size {}", &file, file.metadata()?.len());
    }
    let buffered = BufReader::new(file);
    Ok(serde_cbor::from_reader(buffered)?)
}

pub(crate) fn write<V: Serialize>(value: &V, file: &mut File) -> Result<(), Error> {
    file.seek(std::io::SeekFrom::Start(0))?;
    let buffered = BufWriter::new(file);
    Ok(serde_cbor::to_writer(buffered, value)?)
}

impl ValueModified {
    /// Try to parse the inner value as it contains the assets metadata and fail otherwise.
    pub fn assets(self) -> Result<HashMap<AssetId, AssetEntry>, Error> {
        Ok(serde_json::from_value(self.value)?)
    }

    /// Try to parse the inner value as it contains the icons and fail otherwise.
    pub fn icons(self) -> Result<HashMap<AssetId, String>, Error> {
        Ok(serde_json::from_value(self.value)?)
    }
}

#[cfg(test)]
mod test {

    use super::*;

    #[test]
    fn test_roundtrip() {
        let mut tempfile = tempfile::tempfile().unwrap();
        let content = ValueModified {
            last_modified: "modified".into(),
            value: Value::String(format!("{:?}", (1..100).collect::<Vec<_>>())),
        };
        write(&content, &mut tempfile).unwrap();
        let value = read(&mut tempfile).unwrap();
        assert_eq!(content, value, "roundtrip failing");
    }
}
