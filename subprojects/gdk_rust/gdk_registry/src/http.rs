use std::collections::HashMap;
use std::io::BufReader;
use std::time::{Duration, Instant};

use gdk_common::log::info;
use gdk_common::ureq;

use crate::Result;
use serde_json::Value;

/// Returns `None` if the response status is `304 Not Modified`.
pub(crate) fn call(
    url: &str,
    agent: &ureq::Agent,
    last_modified: &str,
    custom_params: &HashMap<String, String>,
) -> Result<Option<(Value, String)>> {
    let start = Instant::now();

    let mut request =
        agent.get(url).timeout(Duration::from_secs(30)).set("If-Modified-Since", last_modified);
    for param in custom_params {
        request = request.set(param.0, param.1);
    }
    let response = request.call()?;

    let status = response.status();

    info!("call to {} returned w/ status {} in {:?}", url, status, start.elapsed());

    if status == 304 {
        return Ok(None);
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

    Ok(Some((value, last_modified)))
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
                    request::method_path("GET", what.endpoint()),
                    request::headers(contains(key("if-modified-since"))), // HTTP headers are case insensitive, and ureq it's downcasing them
                    request::headers(contains(("accept-encoding", "gzip, br"))),
                ])
                .respond_with(
                    status_code(200)
                        .body("{}")
                        .append_header("last-modified", expected_last_modified),
                ),
            );

            let (_, last_modified) =
                call(&server.url_str(what.endpoint()), &agent, "", &HashMap::new())
                    .unwrap()
                    .unwrap();

            assert_eq!(expected_last_modified, last_modified);
        }
    }
}
