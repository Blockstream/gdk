use bitcoin::blockdata::script::Builder;
use bitcoin::hash_types::PubkeyHash;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Network, PublicKey, Script};

// The following scripts are always using regtest network,
// it is always ok because I am not interested in the address just in the script

pub fn p2shwpkh_script(pk: &PublicKey) -> Script {
    Address::p2shwpkh(pk, Network::Regtest).unwrap().script_pubkey()
}

pub fn p2pkh_script(pk: &PublicKey) -> Script {
    Address::p2pkh(pk, Network::Regtest).script_pubkey()
}

pub fn p2shwpkh_script_sig(public_key: &PublicKey) -> Script {
    let internal = Builder::new()
        .push_int(0)
        .push_slice(&PubkeyHash::hash(&public_key.to_bytes())[..])
        .into_script();
    Builder::new().push_slice(internal.as_bytes()).into_script()
}
