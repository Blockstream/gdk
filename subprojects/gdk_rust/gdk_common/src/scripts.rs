use bitcoin::script::PushBytesBuf;
use serde::{Deserialize, Serialize};

use bitcoin::blockdata::script::Builder;
use bitcoin::hashes::Hash;
use bitcoin::PubkeyHash;
use bitcoin::{Address, CompressedPublicKey, Network, ScriptBuf};

use std::convert::TryFrom;
use std::fmt;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScriptType {
    #[serde(rename = "p2sh-p2wpkh")]
    P2shP2wpkh = 0,
    #[serde(rename = "p2wpkh")]
    P2wpkh = 1,
    #[serde(rename = "p2pkh")]
    P2pkh = 2,
}

impl fmt::Display for ScriptType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::P2shP2wpkh => write!(f, "p2sh-p2wpkh"),
            Self::P2wpkh => write!(f, "p2wpkh"),
            Self::P2pkh => write!(f, "p2pkh"),
        }
    }
}

impl ScriptType {
    /// An integer associated to the scipt/account type to compute the GDK pointer (account_num)
    pub fn num(&self) -> u32 {
        match self {
            Self::P2shP2wpkh => 0,
            Self::P2wpkh => 1,
            Self::P2pkh => 2,
        }
    }
}

// The following scripts are always using regtest network,
// it is always ok because I am not interested in the address just in the script

pub fn p2pkh_script(pk: impl Into<PubkeyHash>) -> ScriptBuf {
    Address::p2pkh(pk, Network::Regtest).script_pubkey()
}

pub fn p2shwpkh_script_sig(public_key: &CompressedPublicKey) -> ScriptBuf {
    let mut vec = vec![0, 20];
    vec.extend(PubkeyHash::hash(&public_key.to_bytes()).as_byte_array());
    Builder::new().push_slice(&PushBytesBuf::try_from(vec).unwrap()).into_script()
}

impl ScriptType {
    pub fn first_account_num(self) -> u32 {
        self as u32
    }

    pub fn is_segwit(self) -> bool {
        matches!(self, ScriptType::P2wpkh | ScriptType::P2shP2wpkh)
    }
}
