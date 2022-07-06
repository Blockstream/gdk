use std::io::BufReader;
use std::time::{Duration, Instant};

use log::info;

use crate::value_modified::ValueModified;
use crate::Result;

pub(crate) fn call(url: &str, agent: &ureq::Agent, last_modified: &str) -> Result<ValueModified> {
    let start = Instant::now();

    let response = agent
        .get(url)
        .timeout(Duration::from_secs(30))
        .set("If-Modified-Since", last_modified)
        .call()?;

    let status = response.status();

    info!("call to {} returned w/ status {} in {:?}", url, status, start.elapsed());

    if status == 304 {
        return Ok(ValueModified::new(serde_json::Value::Null, last_modified.to_owned()));
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::assets_or_icons::AssetsOrIcons;

    #[test]
    fn test_call() {
        use httptest::{matchers::*, responders::*, Expectation, Server};

        let _ = env_logger::try_init();
        let agent = ureq::agent();

        for what in AssetsOrIcons::iter() {
            let server = Server::run();
            let expected_last_modified = "date";
            server.expect(
                Expectation::matching(all_of![
                    request::method_path("GET", what.endpoint().to_string()),
                    request::headers(contains(key("if-modified-since"))), // HTTP headers are case insensitive, and ureq it's downcasing them
                    request::headers(contains(("accept-encoding", "gzip, br"))),
                ])
                .respond_with(
                    status_code(200)
                        .body("{}")
                        .append_header("last-modified", expected_last_modified),
                ),
            );
            let value = call(&server.url_str(what.endpoint()), &agent, "".into()).unwrap();
            assert_eq!(expected_last_modified, value.last_modified());
        }
    }
}
