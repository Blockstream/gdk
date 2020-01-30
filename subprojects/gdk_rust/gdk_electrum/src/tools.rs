use bitcoin::Address;
use sha2::{Digest, Sha256};
use std::str::FromStr;

pub fn decode_address_helper(addr: &str) -> String {
    let addr = Address::from_str(&addr).unwrap();
    let locking_script = addr.script_pubkey();

    let mut hasher = Sha256::new();
    hasher.input(locking_script.as_bytes());
    let mut result = hasher.result();

    result.reverse();
    format!("{:x}", result)
}
