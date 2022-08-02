use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, SystemTime};

use crate::Error;
use serde::Deserialize;

/// The exchange rates cache. The keys are currency pairs (like BTC-USD)
/// and the values are a `(time, rate)` tuple, where `time` represents the
/// last time the exchange rate was fetched and `rate` is the result of the
/// fetching.
pub type ExchangeRatesCache = HashMap<Pair, (std::time::SystemTime, f64)>;

pub trait ExchangeRatesCacher {
    fn xr_cache(&self) -> &ExchangeRatesCache;
    fn xr_cache_mut(&mut self) -> &mut ExchangeRatesCache;

    /// Returns `true` if the given `pair` has a cached exchange rate that
    /// hasn't expired yet.
    fn is_cached(&self, pair: &Pair) -> bool {
        if let Some((last, _)) = self.xr_cache().get(pair) {
            if *last + Duration::from_secs(60) > SystemTime::now() {
                return true;
            }
        }

        false
    }

    /// Returns the exchange rate of `pair` if it's cached, `None` otherwise.
    fn get_cached_rate(&self, pair: &Pair) -> Option<f64> {
        self.xr_cache().get(pair).and_then(|(_, rate)| self.is_cached(pair).then(|| *rate))
    }

    /// Caches `ticker` for future queries.
    fn cache_ticker(&mut self, ticker: Ticker) {
        self.xr_cache_mut().insert(ticker.pair, (SystemTime::now(), ticker.rate));
    }
}

// TODO: derive `Copy` once the `Other` variant is removed.
#[derive(PartialEq, Eq, Debug, Clone, Deserialize, Hash)]
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
    pub fn endpoint_name(&self) -> String {
        match self {
            Currency::BTC => "XBT".to_string(),
            _ => self.to_string(),
        }
    }

    /// Returns a `(url, field)` pair where `url` is the endpoint used to fetch
    /// the rate between the two currencies and `field` is the name of the
    /// `json` field where the price is defined.
    pub fn endpoint(a: &Self, b: &Self) -> (String, &'static str) {
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

    pub fn is_fiat(&self) -> bool {
        matches!(self, Self::USD | Self::EUR | Self::GBP | Self::JPY)
    }

    pub fn iter() -> impl ExactSizeIterator<Item = Self> {
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

// TODO: derive `Copy` once  `Pair` is `Copy`.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
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

impl Ticker {
    pub fn new(pair: Pair, rate: f64) -> Self {
        Self {
            pair,
            rate,
        }
    }
}
