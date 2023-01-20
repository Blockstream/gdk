mod crypto;
mod error;
mod pin;
mod pin_client;
mod pin_data;
mod pin_request;

pub use error::Error;
pub use pin::Pin;
pub use pin_client::PinClient;
pub use pin_data::PinData;

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod tests {
    //! Types and constants to be shared between unit tests.

    use std::env;
    use std::str::FromStr;

    use once_cell::sync::Lazy;

    /// A dummy Result type to be returned from unit tests.
    ///
    /// Allows to ignore errors using `?` instead of `.unwrap()`.
    pub(crate) type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    /// The URL of the production PIN server.
    pub(crate) const PIN_SERVER_PROD_URL: &str = "https://jadepin.blockstream.com";

    /// The onion URL of the production PIN server.
    pub(crate) const PIN_SERVER_PROD_ONION_URL: &str =
        "http://mrrxtq6tjpbnbm7vh5jt6mpjctn7ggyfy5wegvbeff3x7jrznqawlmid.onion";

    /// The public key of the production PIN server.
    pub(crate) const PIN_SERVER_PROD_PUBLIC_KEY: &str =
        "0332b7b1348bde8ca4b46b9dcc30320e140ca26428160a27bdbfc30b34ec87c547";

    /// The value of the `$PIN_SERVER_URL` environment variable, or the URL of
    /// the production PIN server if that's not set.
    pub(crate) const PIN_SERVER_URL: Lazy<url::Url> = Lazy::new(|| {
        check_env();
        let s = env::var("PIN_SERVER_URL").unwrap_or(PIN_SERVER_PROD_URL.to_owned());
        url::Url::from_str(&s).unwrap()
    });

    /// The value of the `$PIN_SERVER_PUBLIC_KEY` environment variable, or the
    /// public key of the production PIN server if that's not set.
    pub(crate) const PIN_SERVER_PUBLIC_KEY: Lazy<bitcoin::PublicKey> = Lazy::new(|| {
        check_env();
        let s = env::var("PIN_SERVER_PUBLIC_KEY").unwrap_or(PIN_SERVER_PROD_PUBLIC_KEY.to_owned());
        bitcoin::PublicKey::from_str(&s).unwrap()
    });

    /// Panics if only one of the `PIN_SERVER_URL`, `PIN_SERVER_PUBLIC_KEY`
    /// environment variables is set.
    fn check_env() {
        // Actually we can still allow one env variable to be set as long as
        // its value is the same as that of the production PIN server.
        match (env::var("PIN_SERVER_URL"), env::var("PIN_SERVER_PUBLIC_KEY")) {
            (Ok(url), Err(_)) if url != PIN_SERVER_PROD_URL => panic!(),
            (Err(_), Ok(pubkey)) if pubkey != PIN_SERVER_PROD_PUBLIC_KEY => panic!(),
            _ => {}
        }
    }
}
