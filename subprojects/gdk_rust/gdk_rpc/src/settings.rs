#[derive(Serialize, Deserialize, Debug)]
pub struct Settings {
    unit: Unit,
    pricing: FiatPricing,
    notifications: NotificationSettings,
    required_num_blocks: u32,
    sound: bool,
    altimeout: u32,
    // XXX mnemonic?
}

impl Settings {
    pub fn default() -> Self {
        Settings {
            unit: Unit::Btc,
            pricing: FiatPricing {
                currency: FiatCurrency::USD,
                exchange: RateExchange::Bitstamp,
            },
            notifications: NotificationSettings {
                email_incoming: false,
                email_outgoing: false,
            },
            required_num_blocks: 2, // XXX
            sound: true,
            altimeout: 5,
        }
    }
}

#[derive(Serialize, Deserialize, Debug)]
enum Unit {
    #[serde(rename = "btc")]
    Btc,
    #[serde(rename = "mbtc")]
    Mili,
    #[serde(rename = "bits")]
    Bits,
    #[serde(rename = "satoshi")]
    Satoshi,
}

#[derive(Serialize, Deserialize, Debug)]
struct FiatPricing {
    currency: FiatCurrency,
    exchange: RateExchange,
}

#[derive(Serialize, Deserialize, Debug)]
enum FiatCurrency {
    USD,
}

#[derive(Serialize, Deserialize, Debug)]
enum RateExchange {
    #[serde(rename = "BITSTAMP")]
    Bitstamp,
}

#[derive(Serialize, Deserialize, Debug)]
struct NotificationSettings {
    email_incoming: bool,
    email_outgoing: bool,
}
