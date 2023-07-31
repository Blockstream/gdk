use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use crate::Error;
use serde::{de, ser};

/// The exchange rates cache. The keys are currency pairs (like BTC-USD)
/// and the values are a `(time, rate)` tuple, where `time` represents the
/// last time the exchange rate was fetched and `rate` is the result of the
/// fetching.
pub type ExchangeRatesCache = Arc<Mutex<HashMap<Pair, (std::time::SystemTime, f64)>>>;

pub trait ExchangeRatesCacher {
    fn xr_cache(&self) -> ExchangeRatesCache;

    /// Returns the exchange rate of `pair` if it's cached, `None` otherwise.
    fn get_cached_rate(&self, pair: &Pair, cache_limit: Duration) -> Option<f64> {
        let cache = self.xr_cache();
        let cache = &*cache.lock().unwrap();
        let &(time_fetched, rate) = cache.get(pair)?;
        (time_fetched + cache_limit > SystemTime::now()).then(|| rate)
    }

    /// Caches `ticker` for future queries.
    fn cache_ticker(&mut self, ticker: Ticker) {
        let cache = self.xr_cache();
        let cache = &mut *cache.lock().unwrap();
        cache.insert(ticker.pair, (SystemTime::now(), ticker.rate));
    }
}

#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
#[cfg_attr(test, derive(strum_macros::EnumIter))]
pub enum Currency {
    BTC,
    USD,
    EUR,
    GBP,
    JPY,
    USDT,
    RUB,
    NGN,
    CAD,
    UAH,
    AUD,
    PLN,
    CHF,
    TRY,
    INR,
    IDR,
    MXN,
    ARS,
    COP,
    ZAR,
    AED,
    KRW,
    MYR,
    KHD,
    SGD,
    CLP,
    PEN,
    UGX,

    /// Storing a catch-all variant as a byte array to keep this enum `Copy`.
    /// Tickers can have 3 to 24 letters/numbers/dots, the second value in the
    /// pair is the length of the ticker. The last `24 - len` bytes in the
    /// array are left as null.
    Other([u8; 24], usize),
}

impl<'de> de::Deserialize<'de> for Currency {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct CurrencyVisitor;

        impl<'de> de::Visitor<'de> for CurrencyVisitor {
            type Value = Currency;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a string of 3 to 24 characters representing a currency ticker")
            }

            fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                Currency::from_str(s).map_err(E::custom)
            }
        }

        deserializer.deserialize_str(CurrencyVisitor)
    }
}

impl ser::Serialize for Currency {
    fn serialize<S: ser::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl Currency {
    #[inline]
    pub fn endpoint_name(&self) -> String {
        match self {
            Currency::BTC => "XBT".to_string(),
            _ => self.to_string(),
        }
    }

    pub fn is_fiat(&self) -> bool {
        !matches!(self, Self::BTC)
    }
}

impl Default for Currency {
    #[inline]
    fn default() -> Self {
        Self::USD
    }
}

impl FromStr for Currency {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Error> {
        // println!("currency from_str {}", s);
        if s.len() < 3 {
            return Err("ticker length less than 3".to_string().into());
        }

        match s {
            "BTC" | "XBT" => Ok(Currency::BTC),
            "USD" => Ok(Currency::USD),
            "EUR" => Ok(Currency::EUR),
            "GBP" => Ok(Currency::GBP),
            "JPY" => Ok(Currency::JPY),
            "USDT" => Ok(Currency::USDT),
            "RUB" => Ok(Currency::RUB),
            "NGN" => Ok(Currency::NGN),
            "CAD" => Ok(Currency::CAD),
            "UAH" => Ok(Currency::UAH),
            "AUD" => Ok(Currency::AUD),
            "PLN" => Ok(Currency::PLN),
            "CHF" => Ok(Currency::CHF),
            "TRY" => Ok(Currency::TRY),
            "INR" => Ok(Currency::INR),
            "IDR" => Ok(Currency::IDR),
            "MXN" => Ok(Currency::MXN),
            "ARS" => Ok(Currency::ARS),
            "COP" => Ok(Currency::COP),
            "ZAR" => Ok(Currency::ZAR),
            "AED" => Ok(Currency::AED),
            "KRW" => Ok(Currency::KRW),
            "MYR" => Ok(Currency::MYR),
            "KHD" => Ok(Currency::KHD),
            "SGD" => Ok(Currency::SGD),
            "CLP" => Ok(Currency::CLP),
            "PEN" => Ok(Currency::PEN),
            "UGX" => Ok(Currency::UGX),
            "" => Err("empty ticker".to_string().into()),

            other if other.len() >= 3 && other.len() <= 24 => {
                let mut ticker = [0u8; 24];
                ticker[..other.len()].copy_from_slice(other.as_bytes());
                Ok(Currency::Other(ticker, other.len()))
            }

            other => Err(format!("unknown currency {}", other).into()),
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
            Currency::USDT => "USDT",
            Currency::RUB => "RUB",
            Currency::NGN => "NGN",
            Currency::CAD => "CAD",
            Currency::UAH => "UAH",
            Currency::AUD => "AUD",
            Currency::PLN => "PLN",
            Currency::CHF => "CHF",
            Currency::TRY => "TRY",
            Currency::INR => "INR",
            Currency::IDR => "IDR",
            Currency::MXN => "MXN",
            Currency::ARS => "ARS",
            Currency::COP => "COP",
            Currency::ZAR => "ZAR",
            Currency::AED => "AED",
            Currency::KRW => "KRW",
            Currency::MYR => "MYR",
            Currency::KHD => "KHD",
            Currency::SGD => "SGD",
            Currency::CLP => "CLP",
            Currency::PEN => "PEN",
            Currency::UGX => "UGX",
            Currency::Other(bytes, len) => std::str::from_utf8(&bytes[..*len]).unwrap(),
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, PartialEq, Eq, Copy, Clone, Hash)]
pub struct Pair(Currency, Currency);

impl Pair {
    pub fn new(c1: Currency, c2: Currency) -> Pair {
        Pair(c1, c2)
    }

    pub fn first(&self) -> Currency {
        self.0
    }

    pub fn second(&self) -> Currency {
        self.1
    }
}

impl fmt::Display for Pair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}{}", self.first(), self.second())
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_str_currency_roundtrip() {
        for currency in <Currency as strum::IntoEnumIterator>::iter() {
            if matches!(currency, Currency::Other(_, _)) {
                continue;
            }
            let str = currency.to_string();
            let res = Currency::from_str(&str);
            assert_eq!(currency, res.unwrap());
        }
    }

    #[test]
    fn deserialize_currency() {
        let s = "[\"BTC\",\"USD\",\"ABCE\"]";
        let currencies = serde_json::from_str::<Vec<Currency>>(s).unwrap();

        match &currencies[..] {
            [btc, usd, abce] => {
                assert_eq!(Currency::BTC, *btc);
                assert_eq!(Currency::USD, *usd);
                assert_eq!("ABCE", abce.to_string());
            }
            _ => unreachable!(),
        }
    }

    #[test]
    fn serialize_currency() {
        let s = "[\"BTC\",\"USD\",\"ABCE\"]";
        let currencies = vec![Currency::BTC, Currency::USD, Currency::from_str("ABCE").unwrap()];
        assert_eq!(s, serde_json::to_string(&currencies).unwrap());
    }
}
