use bitcoin::Script;

#[derive(Debug)]
pub enum BEAddress {
    Bitcoin(bitcoin::Address),
    Elements(elements::Address),
}

impl BEAddress {
    pub fn script_pubkey(&self) -> Script {
        match self {
            BEAddress::Bitcoin(addr) => addr.script_pubkey(),
            BEAddress::Elements(addr) => addr.script_pubkey(),
        }
    }
}

impl ToString for BEAddress {
    fn to_string(&self) -> String {
        match self {
            BEAddress::Bitcoin(addr) => addr.to_string(),
            BEAddress::Elements(addr) => addr.to_string(),
        }
    }
}
