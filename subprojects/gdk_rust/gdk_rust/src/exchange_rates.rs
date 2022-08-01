use std::fmt;
use std::time::{Duration, SystemTime};

use crate::{Error, GdkBackend, GdkSession};
use serde::Deserialize;
use serde_json::Value;

const XR_API_KEY: &str = "";

pub(crate) fn fetch_cached(
    sess: &mut GdkSession,
    params: ConvertAmountParams,
) -> Result<Option<&Ticker>, Error> {
    if SystemTime::now() < (sess.last_xr_fetch + Duration::from_secs(60)) {
        debug!("hit exchange rate cache");
    } else {
        info!("missed exchange rate cache");
        let (agent, is_mainnet) = match sess.backend {
            GdkBackend::Electrum(ref s) => (s.build_request_agent(), s.network.mainnet),
            GdkBackend::Greenlight(ref _s) => (
                Err(gdk_electrum::error::Error::Generic(
                    "build_request_agent not yet implemented".to_string(),
                )),
                false,
            ),
        };
        if let Ok(agent) = agent {
            let rates = if is_mainnet {
                self::fetch(&agent, params.currency)?
            } else {
                Ticker {
                    pair: Pair::new(Currency::BTC, params.currency),
                    rate: 1.1,
                }
            };
            sess.last_xr_fetch = SystemTime::now();
            sess.last_xr = Some(rates);
        }
    }

    Ok(sess.last_xr.as_ref())
}

pub(crate) fn fetch(agent: &ureq::Agent, fiat: Currency) -> Result<Ticker, Error> {
    let (endpoint, price_field) = Currency::endpoint(&Currency::BTC, &fiat);
    log::info!("fetching {} price data from {}", fiat, endpoint);

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
            let pair = Pair::new(Currency::BTC, fiat);
            let ticker = Ticker {
                pair,
                rate,
            };
            info!("got exchange rate {:?}", ticker);
            ticker
        })
}

pub(crate) fn tickers_to_json(tickers: &[&Ticker]) -> Value {
    let empty_map = serde_json::map::Map::new();
    let currency_map = Value::Object(tickers.iter().fold(empty_map, |mut acc, ticker| {
        let currency = ticker.pair.second();
        acc.insert(currency.to_string(), format!("{:.8}", ticker.rate).into());
        acc
    }));

    json!({ "currencies": currency_map })
}

#[derive(PartialEq, Eq, Debug, Clone, Deserialize)]
pub enum Currency {
    BTC,
    USD,
    EUR,
    GBP,
    JPY,
    // LBTC,
    Other(String),
}

impl Currency {
    #[inline]
    fn endpoint_name(&self) -> String {
        match self {
            Currency::BTC => "XBT".to_string(),
            _ => self.to_string(),
        }
    }

    /// Returns a `(url, field)` pair where `url` is the endpoint used to fetch
    /// the rate between the two currencies and `field` is the name of the
    /// `json` field where the price is defined.
    fn endpoint(a: &Self, b: &Self) -> (String, &'static str) {
        match (a, b) {
            (Currency::BTC, Currency::USD) | (Currency::USD, Currency::BTC) => (
                format!(
                    "https://deluge-dev.blockstream.com/feed/del-v0r7-ws/index/{}{}",
                    a.endpoint_name(),
                    b.endpoint_name()
                ),
                "price",
            ),

            _ => (
                format!(
                    "https://deluge-dev.blockstream.com/feed/del-v0r7-ws/price/{}{}/bitfinex",
                    a.endpoint_name(),
                    b.endpoint_name()
                ),
                "last-trade",
            ),
        }
    }

    pub(crate) fn is_fiat(&self) -> bool {
        matches!(self, Self::USD | Self::EUR | Self::GBP | Self::JPY)
    }

    pub(crate) fn iter() -> impl ExactSizeIterator<Item = Self> {
        vec![Self::BTC, Self::USD, Self::EUR, Self::GBP, Self::JPY].into_iter()
    }
}

impl Default for Currency {
    #[inline]
    fn default() -> Self {
        Self::USD
    }
}

impl std::str::FromStr for Currency {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Error> {
        // println!("currency from_str {}", s);
        if s.len() < 3 {
            return Err("ticker length less than 3".to_string().into());
        }

        // TODO: support harder to parse pairs (LBTC?)
        match s {
            "BTC" => Ok(Currency::BTC),
            "USD" => Ok(Currency::USD),
            "EUR" => Ok(Currency::EUR),
            "GBP" => Ok(Currency::GBP),
            "JPY" => Ok(Currency::JPY),
            "" => Err("empty ticker".to_string().into()),
            other => Ok(Currency::Other(other.into())),
        }
    }
}

impl fmt::Display for Currency {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Currency::BTC => "BTC",
            Currency::USD => "USD",
            Currency::EUR => "EUR",
            Currency::GBP => "GBP",
            Currency::JPY => "JPY",
            // Currency::LBTC => "LBTC",
            Currency::Other(ref s) => s,
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Pair(Currency, Currency);

impl Pair {
    pub fn new(c1: Currency, c2: Currency) -> Pair {
        Pair(c1, c2)
    }

    pub fn new_btc(c: Currency) -> Pair {
        Pair(Currency::BTC, c)
    }

    pub fn first(&self) -> &Currency {
        &self.0
    }

    pub fn second(&self) -> &Currency {
        &self.1
    }
}

impl fmt::Display for Pair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.first(), self.second())
    }
}

#[derive(Debug, Clone)]
pub struct Ticker {
    pub pair: Pair,
    pub rate: f64,
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
            let res = fetch(&agent, currency);
            assert!(res.is_ok(), "{:?}", res);
        }
    }
}
