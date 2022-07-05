use std::io::BufReader;
use std::time::{Duration, Instant};

use log::info;

use crate::value_modified::ValueModified;
use crate::Result;

pub(crate) fn call(
    url: &str,
    agent: &ureq::Agent,
    last_modified: &str,
) -> Result<ValueModified> {
    let start = Instant::now();

    let response = agent
        .get(url)
        .timeout(Duration::from_secs(30))
        .set("If-Modified-Since", last_modified)
        .call()?;

    let status = response.status();

    info!(
        "call to {} returned w/ status {} in {:?}",
        url,
        status,
        start.elapsed()
    );

    if status == 304 {
        return Ok(ValueModified::new(
            serde_json::Value::Null,
            last_modified.to_owned(),
        ));
    }

    let last_modified = response
        .header("Last-Modified")
        .or_else(|| response.header("last-modified"))
        .unwrap_or_default()
        .to_string();

    // `respone.into_json()` is slow because of many syscalls. See:
    // https://github.com/algesten/ureq/pull/506.
    let buffered_reader = BufReader::new(response.into_reader());
    let value = serde_json::from_reader(buffered_reader)?;

    info!("END call {} {} took: {:?}", &url, status, start.elapsed());

    Ok(ValueModified::new(value, last_modified))
}
