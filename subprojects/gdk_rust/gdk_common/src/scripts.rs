use serde::{Deserialize, Serialize};

use bitcoin::blockdata::script::Builder;
use bitcoin::hash_types::PubkeyHash;
use bitcoin::hashes::Hash;
use bitcoin::{Address, Network, PublicKey, Script};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScriptType {
    #[serde(rename(serialize = "p2sh-p2wpkh"))]
    P2shP2wpkh,
    #[serde(rename(serialize = "p2wpkh"))]
    P2wpkh,
    #[serde(rename(serialize = "p2pkh"))]
    P2pkh,
}

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

impl ScriptType {
    pub fn is_segwit(self) -> bool {
        matches!(self, ScriptType::P2wpkh | ScriptType::P2shP2wpkh)
    }

    /// Returns a mock witness with the expected size
    pub fn mock_witness(self) -> Vec<Vec<u8>> {
        match self {
            // signature (72) + compressed public key (33)
            ScriptType::P2wpkh | ScriptType::P2shP2wpkh => vec![vec![0u8; 72], vec![0u8; 33]],
            // empty for non-witness inputs
            ScriptType::P2pkh => vec![],
        }
    }

    /// Returns a mock script sig with the expected size
    pub fn mock_script_sig(self) -> Vec<u8> {
        match self {
            // empty for native segwit
            ScriptType::P2wpkh => vec![],
            // OP_PUSHBYTES <22 bytes>
            ScriptType::P2shP2wpkh => vec![0u8; 23],
            // OP_PUSHBYTES <72 bytes sig> OP_PUSHBYTES <33 bytes compressed key>
            ScriptType::P2pkh => vec![0u8; 107],
        }
    }

    /// Returns a mock scriptPubkey with the expected size
    pub fn mock_script_pubkey(self) -> Vec<u8> {
        match self {
            // OP_0 PUSHBYTES <20 bytes hash>
            ScriptType::P2wpkh => vec![0u8; 22],
            // OP_HASH160 PUSHBYTES <20 bytes hash> OP_EQUAL
            ScriptType::P2shP2wpkh => vec![0u8; 23],
            // OP_DUP OP_HASH160 OP_PUSHBYTES_20 <20 bytes hash> OP_EQUALVERIFY OP_CHECKSIG
            ScriptType::P2pkh => vec![0u8; 25],
        }
    }
}
