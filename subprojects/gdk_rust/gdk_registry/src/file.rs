use std::fs::File;
use std::io::{self, BufReader, BufWriter, Seek};

use log::{info, log_enabled, Level};
use serde::{de::DeserializeOwned, Serialize};

use crate::Result;

pub(crate) fn read<V: DeserializeOwned>(file: &mut File) -> Result<V> {
    file.seek(io::SeekFrom::Start(0))?;
    if log_enabled!(Level::Info) {
        info!("file {:?} size {}", &file, file.metadata()?.len());
    }
    let buffered = BufReader::new(file);
    Ok(serde_cbor::from_reader(buffered)?)
}

pub(crate) fn write<V: Serialize>(value: &V, file: &mut File) -> Result<()> {
    // Empty the file before writing to avoid having leftover trailing bytes if
    // the new contents are shorter than the old ones (e.g. old file was
    // `foobar`, we write `baz`, new contents should be `baz` and not
    // `bazbar`).
    file.set_len(0)?;

    file.seek(std::io::SeekFrom::Start(0))?;
    let buffered = BufWriter::new(file);
    Ok(serde_cbor::to_writer(buffered, value)?)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::value_modified::ValueModified;
    use serde_json::Value;

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
