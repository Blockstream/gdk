use std::thread;
use std::time::{Duration, SystemTime};

use gdk_common::exchange_rates::{Currency, Pair, Ticker};
use gdk_common::log::{debug, info};
use gdk_common::session::Session;
use gdk_common::ureq;
use serde::{de::Deserializer, Deserialize};

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

    if sess.network_parameters().development {
        // TODO: remove once mocked up price endpoint is available in localtest
        if &params.exchange == "BROKEN" {
            return Ok(None);
        } else {
            let ticker = Ticker::new(pair, 1.1);
            sess.cache_ticker(ticker);
            return Ok(Some(ticker));
        }
    }

    info!("missed exchange rate cache");

    let agent = sess.build_request_agent()?;
    let cache = sess.xr_cache();
    let currency = params.currency;
    let url = params.url.clone();
    let exchange = params.exchange.clone();

    let handle = thread::spawn(move || {
        let ticker = self::fetch(&agent, currency, &url, &exchange)?;
        let cache = &mut *cache.lock().unwrap();
        cache.insert(ticker.pair, (SystemTime::now(), ticker.rate));
        Ok::<_, Error>(Some(ticker))
    });

    if params.fallback_rate.is_none() {
        return handle.join().unwrap();
    }

    Ok(None)
}

pub(crate) fn fetch(
    agent: &ureq::Agent,
    currency: Currency,
    url: &str,
    exchange: &str,
) -> Result<Ticker, Error> {
    #[derive(serde::Deserialize)]
    struct ExchangeRateResponse {
        // TODO: this should be returned as a number by the server.
        // rate: f64,
        rate: String,
    }

    let endpoint = format!(
        "{}/v0/venues/{}/pairs/{}/{}",
        url,
        exchange.to_ascii_uppercase(),
        Currency::BTC.endpoint_name(),
        currency.endpoint_name()
    );

    let pair = Pair::new(Currency::BTC, currency);

    info!("fetching {} price data from {}", pair, endpoint);

    let response = agent.get(&endpoint).call()?.into_json::<ExchangeRateResponse>()?;

    let ticker = Ticker::new(pair, response.rate.parse::<f64>().unwrap());

    info!("got exchange rate {:?}", ticker);
    Ok(ticker)
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

    /// The name of the currency exchange to use for the `BTC-currency`
    /// exchange rate.
    exchange: String,

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
