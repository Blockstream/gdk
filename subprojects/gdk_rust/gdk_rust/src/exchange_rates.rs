use std::thread;
use std::time::{Duration, SystemTime};

use gdk_common::exchange_rates::{Currency, Pair, Ticker};
use gdk_common::log::{debug, info};
use gdk_common::session::Session;
use gdk_common::ureq;
use serde::{de::Deserializer, Deserialize};
use serde_json::Value;

use crate::Error;

// TODO: change name?
pub(crate) fn fetch_cached<S: Session>(
    sess: &mut S,
    params: &ConvertAmountParams,
) -> Result<Option<Ticker>, Error> {
    let pair = Pair::new(Currency::BTC, params.currency);

    if let Some(rate) = sess.get_cached_rate(&pair, params.cache_limit) {
        debug!("hit exchange rate cache");
        return Ok(Some(Ticker::new(pair, rate)));
    }

    info!("missed exchange rate cache");

    let agent = sess.build_request_agent()?;
    let cache = sess.xr_cache();
    let url = params.url.clone();

    let handle = thread::spawn(move || {
        let ticker = self::fetch(&agent, pair, &url)?;
        let cache = &mut *cache.lock().unwrap();
        cache.insert(ticker.pair, (SystemTime::now(), ticker.rate));
        Ok::<_, Error>(Some(ticker))
    });

    if params.fallback_rate.is_none() {
        return handle.join().unwrap();
    }

    Ok(None)
}

pub(crate) fn fetch(agent: &ureq::Agent, pair: Pair, url: &str) -> Result<Ticker, Error> {
    if !matches!(
        (pair.first(), pair.second()),
        (Currency::USD, Currency::BTC) | (Currency::BTC, Currency::USD),
    ) {
        return Err(Error::UnsupportedCurrencyPair(pair));
    };

    let (endpoint, price_field) = Currency::endpoint(pair.first(), pair.second(), url);
    info!("fetching {} price data from {}", pair, endpoint);

    agent
        .get(&endpoint)
        .call()?
        .into_json::<serde_json::Map<String, Value>>()?
        .get(price_field)
        .ok_or_else(|| Error::ExchangeRateBadResponse {
            expected: format!("field `{}` to be set", price_field),
        })?
        .as_str()
        .and_then(|str| str.parse::<f64>().ok())
        .ok_or(Error::ExchangeRateBadResponse {
            expected: "string representing a price".into(),
        })
        .map(|rate| {
            let ticker = Ticker::new(pair, rate);
            info!("got exchange rate {:?}", ticker);
            ticker
        })
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct ConvertAmountParams {
    #[serde(default, rename(deserialize = "currencies"))]
    pub(crate) currency: Currency,

    /// The url of the endpoint used to fetch the exchange rate data.
    #[serde(rename = "price_url")]
    url: String,

    #[serde(deserialize_with = "deserialize_rate")]
    fallback_rate: Option<f64>,

    #[serde(default = "one_minute")]
    cache_limit: Duration,
}

fn one_minute() -> Duration {
    Duration::from_secs(60)
}

fn deserialize_rate<'de, D>(deserializer: D) -> Result<Option<f64>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;

    let str = String::deserialize(deserializer)?;

    if str.is_empty() {
        Ok(None)
    } else {
        str.parse::<f64>().map_err(D::Error::custom).map(Some)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;
    use gdk_common::exchange_rates::{ExchangeRatesCache, ExchangeRatesCacher};
    use gdk_common::network::NetworkParameters;
    use gdk_common::notification::NativeNotif;

    #[derive(Default)]
    struct TestSession {
        xr_cache: ExchangeRatesCache,
    }

    impl ExchangeRatesCacher for TestSession {
        fn xr_cache(&self) -> ExchangeRatesCache {
            Arc::clone(&self.xr_cache)
        }
    }

    impl Session for TestSession {
        fn new(_: NetworkParameters) -> Result<Self, gdk_common::session::JsonError> {
            todo!()
        }

        fn handle_call(
            &mut self,
            _: &str,
            _: Value,
        ) -> Result<Value, gdk_common::session::JsonError> {
            todo!()
        }

        fn native_notification(&mut self) -> &mut NativeNotif {
            todo!()
        }

        fn network_parameters(&self) -> &NetworkParameters {
            todo!()
        }

        fn build_request_agent(&self) -> Result<ureq::Agent, ureq::Error> {
            Ok(ureq::agent())
        }

        fn is_mainnet(&self) -> bool {
            true
        }
    }

    #[test]
    fn test_fetch_xr_with_fallback() {
        let mut session = TestSession::default();

        // TODO: loop over all currencies once they are supported.

        let params = ConvertAmountParams {
            currency: Currency::USD,
            url: "https://deluge-green.blockstream.com/feed/del-v0r7-green".into(),
            fallback_rate: Some(1.0),
            cache_limit: one_minute(),
        };

        let mut i = 0;

        let ticker = loop {
            i += 1;

            if i == 60 {
                panic!("Exchange rate couldn't be fetched");
            }

            if let Some(ticker) = fetch_cached(&mut session, &params).unwrap() {
                break ticker;
            }

            thread::sleep(Duration::from_millis(500));
        };

        // Now the fetched exchange rate should have been cached.
        let res = fetch_cached(&mut session, &params).unwrap();
        assert!(res.is_some());
        assert_eq!(ticker, res.unwrap());
    }

    #[test]
    fn test_fetch_xr_without_fallback() {
        let mut session = TestSession::default();

        let params = ConvertAmountParams {
            currency: Currency::USD,
            url: "https://deluge-green.blockstream.com/feed/del-v0r7-green".into(),
            fallback_rate: None,
            cache_limit: one_minute(),
        };

        let res = fetch_cached(&mut session, &params).unwrap();
        assert!(res.is_some());
    }

    #[test]
    fn test_fetch_xr_cache_expired() {
        let mut session = TestSession::default();

        let params = ConvertAmountParams {
            currency: Currency::USD,
            url: "https://deluge-green.blockstream.com/feed/del-v0r7-green".into(),
            fallback_rate: None,
            cache_limit: one_minute(),
        };

        let res = fetch_cached(&mut session, &params).unwrap();
        assert!(res.is_some());

        // A new request with a cache limit of 0 should return None.
        let params = ConvertAmountParams {
            currency: Currency::USD,
            url: "https://deluge-green.blockstream.com/feed/del-v0r7-green".into(),
            fallback_rate: Some(1.0),
            cache_limit: Duration::from_millis(0),
        };

        let res = fetch_cached(&mut session, &params).unwrap();
        assert!(res.is_none());
    }
}
