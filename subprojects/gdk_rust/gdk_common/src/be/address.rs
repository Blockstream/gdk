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
    pub fn blinding_pubkey(&self) -> Option<bitcoin::secp256k1::PublicKey> {
        match self {
            BEAddress::Bitcoin(_) => None,
            BEAddress::Elements(addr) => addr.blinding_pubkey,
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
