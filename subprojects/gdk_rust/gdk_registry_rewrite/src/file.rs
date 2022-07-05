use std::fs::File;
use std::io::{self, BufReader, BufWriter, Seek};

use log::{info, log_enabled, Level};
use serde::{de::DeserializeOwned, Serialize};

use crate::Result;

pub(crate) fn _read<V: DeserializeOwned>(file: &mut File) -> Result<V> {
    file.seek(io::SeekFrom::Start(0))?;
    if log_enabled!(Level::Info) {
        info!("file {:?} size {}", &file, file.metadata()?.len());
    }
    let buffered = BufReader::new(file);
    Ok(serde_cbor::from_reader(buffered)?)
}

pub(crate) fn write<V: Serialize>(value: &V, file: &mut File) -> Result<()> {
    file.seek(std::io::SeekFrom::Start(0))?;
    let buffered = BufWriter::new(file);
    Ok(serde_cbor::to_writer(buffered, value)?)
}
