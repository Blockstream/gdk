use std::str::FromStr;
use std::thread;
use std::time::{Duration, SystemTime};

use gdk_common::elements::AssetId;
use gdk_common::exchange_rates::{Currency, Pair, PairBase, Ticker};
use gdk_common::log::{debug, info};
use gdk_common::model::Pricing;
use gdk_common::session::Session;
use gdk_common::ureq;
use serde::{de::Deserializer, Deserialize};

use crate::Error;

// TODO: change name?
pub(crate) fn fetch_cached<S: Session>(
    sess: &mut S,
    params: &ConvertAmountParams,
    pricing_settings: &Pricing,
) -> Result<Option<Ticker>, Error> {
    let pair = if let Some(asset_id) = params.asset_id {
        Pair::new_asset(asset_id, params.currency)
    } else {
        Pair::new(Currency::BTC, params.currency)
    };

    let cache_refresh_secs = Duration::from_secs(params.cache_refresh_secs);
    if pricing_settings.currency == params.currency.to_string()
        && (sess.network_parameters().liquid || pricing_settings.exchange == params.exchange)
        && !sess.is_cache_rate_expired(&pair, &cache_refresh_secs)
    {
        debug!("hit exchange rate cache");
        let rate = sess.get_cached_rate(&pair, &cache_refresh_secs);
        return Ok(Some(Ticker::new(
            pair,
            match rate {
                Some(it) => it,
                None => return Ok(None),
            },
        )));
    }

    if sess.network_parameters().development {
        // TODO: remove once mocked up price endpoint is available in localtest
        if &params.exchange == "BROKEN" {
            return Ok(None);
        }
    }

    info!("missed exchange rate cache");

    let agent = sess.build_request_agent()?;
    let cache = sess.xr_cache();
    let currency = params.currency;
    let url = params.url.clone();
    let exchange = params.exchange.clone();

    let handle = thread::spawn(move || {
        let cache = &mut *cache.lock().unwrap();
        let ticker = match pair.base() {
            PairBase::Currency(_) => {
                let t = self::fetch(&agent, currency, &url, &exchange)?;
                let now = SystemTime::now();
                cache.insert(t.pair, (now, t.rate));
                Some(t)
            }
            PairBase::Asset(_) => {
                let assets = self::fetch_assets(&agent, currency, &url)?;
                let mut ticker = None;
                let now = SystemTime::now();
                for asset in &assets {
                    if asset.pair.base() == pair.base() {
                        ticker = Some(asset.clone());
                    }
                    cache.insert(asset.pair, (now, asset.rate));
                }
                ticker
            }
        };
        Ok::<_, Error>(ticker)
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

    let response = agent.get(&endpoint).call()?.into_body().read_json::<ExchangeRateResponse>()?;

    let result = response
        .rate
        .parse::<f64>()
        .map(|r| {
            let ticker = Ticker::new(pair, r);
            info!("got exchange rate {:?}", ticker);
            ticker
        })
        .map_err(|e| Error::from(format!("Failed to parse exchange rate: {}", e)));

    result
}

pub(crate) fn fetch_assets(
    agent: &ureq::Agent,
    currency: Currency,
    url: &str,
) -> Result<Vec<Ticker>, Error> {
    use std::collections::HashMap;

    #[derive(serde::Deserialize, Debug)]
    struct AssetPricesResponse {
        currency: Currency,
        data: HashMap<String, String>,
    }

    let endpoint = format!("{}/v1/liquid/{}", url, currency.to_string());

    info!("fetching asset prices for {} from {}", currency, endpoint);

    let response = agent.get(&endpoint).call()?.into_body().read_json::<AssetPricesResponse>()?;
    let mut result = Vec::new();

    for (asset_id, price) in response.data.iter() {
        let rate = price
            .parse::<f64>()
            .map_err(|e| Error::from(format!("Failed to parse asset price: {}", e)))?;
        let asset_id = AssetId::from_str(asset_id)
            .map_err(|e| Error::from(format!("Failed to parse asset id: {}", e)))?;

        let pair = Pair::new_asset(asset_id, response.currency);
        result.push(Ticker::new(pair, rate));
    }

    info!("got {} asset prices for {}", result.len(), currency);
    debug!("result: {:?}", result);

    Ok(result)
}

#[derive(Clone, Debug, Default, Deserialize)]
pub(crate) struct ConvertAmountParams {
    #[serde(default, rename(deserialize = "currencies"))]
    pub(crate) currency: Currency,

    // Optional asset id to fetch the exchange rate for.
    // If not provided, the exchange rate for `BTC-currency` will be fetched.
    #[serde(default)]
    asset_id: Option<AssetId>,

    /// The url of the endpoint used to fetch the exchange rate data.
    #[serde(rename = "price_url")]
    url: String,

    #[serde(deserialize_with = "deserialize_rate")]
    fallback_rate: Option<f64>,

    /// The name of the currency exchange to use for the `BTC-currency`
    /// exchange rate.
    exchange: String,

    #[serde(default = "one_minute")]
    cache_refresh_secs: u64,
}

fn one_minute() -> u64 {
    60
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
