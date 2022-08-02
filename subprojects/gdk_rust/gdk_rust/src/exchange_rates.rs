use std::iter::FromIterator;

use crate::Error;
use gdk_common::exchange_rates::{Currency, Pair, Ticker};
use gdk_common::session::Session;
use serde::Deserialize;
use serde_json::{Map, Value};

const XR_API_KEY: &str = "";

pub(crate) fn fetch_cached<S: Session>(
    sess: &mut S,
    params: ConvertAmountParams,
) -> Result<Ticker, Error> {
    let pair = Pair::new(Currency::BTC, params.currency);

    if let Some(rate) = sess.get_cached_rate(&pair) {
        debug!("hit exchange rate cache");
        return Ok(Ticker::new(pair, rate));
    }

    info!("missed exchange rate cache");

    let agent = sess.build_request_agent()?;
    let is_mainnet = true; // TODO: what is this for?

    let ticker = if is_mainnet {
        self::fetch(&agent, pair)?
    } else {
        Ticker::new(pair, 1.1)
    };

    // TODO: avoid cloning once `Pair` is `Copy`
    sess.cache_ticker(ticker.clone());

    Ok(ticker)
}

pub(crate) fn fetch(agent: &ureq::Agent, pair: Pair) -> Result<Ticker, Error> {
    let (endpoint, price_field) = Currency::endpoint(pair.first(), pair.second());
    log::info!("fetching {} price data from {}", pair, endpoint);

    agent
        .get(&endpoint)
        .set("X-API-Key", XR_API_KEY)
        .call()?
        .into_json::<serde_json::Map<String, Value>>()?
        .get(price_field)
        .expect(&format!("`{}` field is always set", price_field))
        .as_str()
        .and_then(|str| str.parse::<f64>().ok())
        .ok_or(Error::ExchangeRateBadResponse {
            expected: "string representing a price",
        })
        .map(|rate| {
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

#[derive(Debug, Default, Deserialize)]
pub(crate) struct ConvertAmountParams {
    #[serde(default, rename(deserialize = "currencies"))]
    currency: Currency,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fetch_exchange_rates() {
        let agent = ureq::agent();

        for currency in Currency::iter().filter(Currency::is_fiat) {
            let res = fetch(&agent, Pair::new(Currency::BTC, currency));
            assert!(res.is_ok(), "{:?}", res);
        }
    }
}
