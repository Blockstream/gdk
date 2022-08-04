use std::iter::FromIterator;

use crate::Error;
use gdk_common::exchange_rates::{Currency, Pair, Ticker};
use gdk_common::session::Session;
use serde::Deserialize;
use serde_json::{Map, Value};

/// Whether an exchange rate returned by `fetch_cached` came from a previously
/// cached value of from a network request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum ExchangeRateSource {
    Cached,
    Fetched,
}

// TODO: change name?
pub(crate) fn fetch_cached<S: Session>(
    sess: &mut S,
    params: ConvertAmountParams,
) -> Result<(Ticker, ExchangeRateSource), Error> {
    let pair = Pair::new(Currency::BTC, params.currency);

    if let Some(rate) = sess.get_cached_rate(&pair) {
        debug!("hit exchange rate cache");
        return Ok((Ticker::new(pair, rate), ExchangeRateSource::Cached));
    }

    info!("missed exchange rate cache");

    let agent = sess.build_request_agent()?;

    let ticker = if sess.is_mainnet() {
        self::fetch(&agent, pair)?
    } else {
        Ticker::new(pair, 1.1)
    };

    sess.cache_ticker(ticker);

    Ok((ticker, ExchangeRateSource::Fetched))
}

pub(crate) fn fetch(agent: &ureq::Agent, _pair: Pair) -> Result<Ticker, Error> {
    agent
        .get("https://api-pub.bitfinex.com/v2/tickers?symbols=tBTCUSD")
        .call()?
        .into_json::<Vec<Vec<serde_json::Value>>>()?
        .into_iter()
        .flatten()
        // using BIDPRICE https://docs.bitfinex.com/reference#rest-public-tickers
        .nth(1)
        .expect("the bid price is the 2nd element of the returned JSON array")
        .as_f64()
        .ok_or(Error::ExchangeRateBadResponse {
            expected: "number representing a price",
        })
        .map(|rate| {
            let pair = Pair::new(Currency::BTC, Currency::USD);
            let ticker = Ticker::new(pair, rate);
            info!("got exchange rate {:?}", ticker);
            ticker
        })
}

pub(crate) fn ticker_to_json(ticker: &Ticker) -> Value {
    let currency = ticker.pair.second();

    let currency_map =
        Map::from_iter([(currency.to_string(), format!("{:.8}", ticker.rate).into())]);

    json!({ "currencies": currency_map })
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct ConvertAmountParams {
    #[serde(default, rename(deserialize = "currencies"))]
    currency: Currency,
}

#[cfg(test)]
mod tests {
    use super::*;
    use gdk_common::exchange_rates::{ExchangeRatesCache, ExchangeRatesCacher};
    use gdk_common::network::NetworkParameters;
    use gdk_common::notification::NativeNotif;

    #[derive(Default)]
    struct TestSession {
        xr_cache: ExchangeRatesCache,
    }

    impl ExchangeRatesCacher for TestSession {
        fn xr_cache(&self) -> &ExchangeRatesCache {
            &self.xr_cache
        }
        fn xr_cache_mut(&mut self) -> &mut ExchangeRatesCache {
            &mut self.xr_cache
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
    fn test_fetch_exchange_rates() {
        let mut session = TestSession::default();

        // TODO: loop over all currencies once we use the new blockstream API.

        let params = ConvertAmountParams {
            currency: Currency::USD,
        };

        let res = fetch_cached(&mut session, params.clone());
        assert!(res.is_ok(), "{:?}", res);
        assert_eq!(ExchangeRateSource::Fetched, res.unwrap().1);

        let res = fetch_cached(&mut session, params);
        assert!(res.is_ok(), "{:?}", res);
        assert_eq!(ExchangeRateSource::Cached, res.unwrap().1);
    }
}
