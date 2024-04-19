use bitcoin::secp256k1;
use elements_miniscript::confidential::slip77::MasterBlindingKey as Slip77MasterBlindingKey;
use pbkdf2::pbkdf2_hmac_array;
use sha2::Sha512;
use std::borrow::Cow;
use std::convert::TryFrom;
use std::ffi::{CStr, CString};
use std::fmt;
use std::os::raw::c_char;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::EC;

mod strser;

pub use strser::StringSerialized;

pub fn is_confidential_txoutsecrets(txoutsecrets: &elements::TxOutSecrets) -> bool {
    txoutsecrets.asset_bf != elements::confidential::AssetBlindingFactor::zero()
        && txoutsecrets.value_bf != elements::confidential::ValueBlindingFactor::zero()
}

pub fn weight_to_vsize(weight: usize) -> usize {
    (weight + 3) / 4
}

pub fn now() -> u64 {
    let start = SystemTime::now();
    let since_the_epoch = start.duration_since(UNIX_EPOCH).expect("Time went backwards");
    // Realistic timestamps can be converted to u64
    u64::try_from(since_the_epoch.as_micros()).unwrap_or(u64::MAX)
}

/// Wrapper of elements_miniscript's slip77::MasterBlindindingKey
///
/// Used to gain backward compatibility with the old/wally serialization,
/// i.e. 64 bytes instead of 32
/// TODO: remove this code once the master blinding key is always (de)serialized as 32 bytes

#[derive(Clone, PartialEq, Debug)]
pub struct MasterBlindingKey(pub Slip77MasterBlindingKey);

impl serde::Serialize for MasterBlindingKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use elements::hex::ToHex;
        let mut key64: [u8; 64] = [0; 64];
        key64[32..].copy_from_slice(self.0.as_bytes());
        serde::Serialize::serialize(&key64.as_slice().to_hex(), serializer)
    }
}
impl<'de> serde::Deserialize<'de> for MasterBlindingKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use elements::hex::FromHex;
        let hex: String = serde::Deserialize::deserialize(deserializer)?;

        let is_32bytes = <[u8; 32]>::from_hex(&hex);
        if is_32bytes.is_ok() {
            return Ok(MasterBlindingKey(Slip77MasterBlindingKey::from(is_32bytes.unwrap())));
        }

        let is_64bytes = <[u8; 64]>::from_hex(&hex);
        if is_64bytes.is_ok() {
            let raw_bytes = <[u8; 32]>::try_from(&is_64bytes.unwrap()[32..]);
            return Ok(MasterBlindingKey(Slip77MasterBlindingKey::from(raw_bytes.unwrap())));
        }
        Err(serde::de::Error::custom("invalid length"))
    }
}
impl fmt::Display for MasterBlindingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::convert::From<[u8; 64]> for MasterBlindingKey {
    fn from(bytes: [u8; 64]) -> Self {
        let raw_bytes = <[u8; 32]>::try_from(&bytes[32..]);
        MasterBlindingKey(Slip77MasterBlindingKey::from(raw_bytes.unwrap()))
    }
}

impl std::convert::From<[u8; 32]> for MasterBlindingKey {
    fn from(bytes: [u8; 32]) -> Self {
        MasterBlindingKey(Slip77MasterBlindingKey::from(bytes))
    }
}

pub fn asset_blinding_key_from_seed(seed: &[u8]) -> MasterBlindingKey {
    MasterBlindingKey(Slip77MasterBlindingKey::from_seed(seed))
}

pub fn asset_blinding_key_to_ec_private_key(
    master_blinding_key: &MasterBlindingKey,
    script_pubkey: &elements::Script,
) -> secp256k1::SecretKey {
    master_blinding_key.0.blinding_private_key(script_pubkey)
}

pub fn ec_public_key_from_private_key(priv_key: secp256k1::SecretKey) -> secp256k1::PublicKey {
    secp256k1::PublicKey::from_secret_key(&EC, &priv_key)
}

pub fn pbkdf2_hmac_sha512_256(password: Vec<u8>, salt: Vec<u8>, cost: u32) -> [u8; 32] {
    pbkdf2_hmac_array::<Sha512, 32>(&password, &salt, cost)
}

pub fn make_str<'a, S: Into<Cow<'a, str>>>(data: S) -> *mut c_char {
    CString::new(data.into().into_owned()).unwrap().into_raw()
}

#[allow(clippy::not_unsafe_ptr_arg_deref)]
pub fn read_str(s: *const c_char) -> String {
    unsafe { CStr::from_ptr(s) }.to_str().unwrap().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bip39;
    use elements::hex::FromHex;
    use elements::hex::ToHex;
    use elements::Script;
    use std::convert::TryInto;
    use std::str::FromStr;

    #[test]
    /// test vectors taken from libwally-core test_confidential_addr.py test_master_blinding_key
    fn test_elements_master_blinding_key() {
        let mnemonic = "all all all all all all all all all all all all";
        let passphrase = "";
        let mnemonic = bip39::Mnemonic::parse(mnemonic).unwrap();
        let seed = mnemonic.to_seed(passphrase);
        assert_eq!(seed.len(), 64);
        assert_eq!(seed.to_hex(), "c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8");
        let master_blinding_key = asset_blinding_key_from_seed(&seed);
        assert_eq!(
            master_blinding_key.0.to_string(),
            "6c2de18eabeff3f7822bc724ad482bef0557f3e1c1e1c75b7a393a5ced4de616"
        );

        let unconfidential_addr = "2dpWh6jbhAowNsQ5agtFzi7j6nKscj6UnEr";
        let script =
            Script::from_hex("76a914a579388225827d9f2fe9014add644487808c695d88ac").unwrap();
        let blinding_key = asset_blinding_key_to_ec_private_key(&master_blinding_key, &script);
        let public_key = ec_public_key_from_private_key(blinding_key);
        let unconfidential_addr = elements::Address::from_str(&unconfidential_addr).unwrap();
        let conf_addr = unconfidential_addr.to_confidential(public_key);
        assert_eq!(
            conf_addr,
            elements::Address::from_str(
                "CTEkf75DFff5ReB7juTg2oehrj41aMj21kvvJaQdWsEAQohz1EDhu7Ayh6goxpz3GZRVKidTtaXaXYEJ"
            )
            .unwrap()
        );
    }

    #[test]
    fn test_pbkdf2() {
        // abandon abandon ... about
        // expected value got from a session with server_type green
        let xpub = bitcoin::bip32::Xpub::from_str("tpubD6NzVbkrYhZ4XYa9MoLt4BiMZ4gkt2faZ4BcmKu2a9te4LDpQmvEz2L2yDERivHxFPnxXXhqDRkUNnQCpZggCyEZLBktV7VaSmwayqMJy1s").unwrap();
        let password = xpub.encode().to_vec();
        let salt = "testnet".as_bytes().to_vec();
        let cost = 2048;
        let bytes = pbkdf2_hmac_sha512_256(password, salt, cost);
        assert_eq!(
            bytes.to_hex(),
            "657a9de33d1f7753edbb86c90b0ba064bd1b986570f1a5019ed80459877b013b"
        );
    }

    #[test]
    fn test_master_blinding_key_serde() {
        let m_array: [u8; 64] = (0..64).collect::<Vec<_>>().try_into().unwrap();
        let m = MasterBlindingKey::from(m_array);
        let s = serde_json::to_string(&m).unwrap();
        assert_eq!(
            &s,
            "\"0000000000000000000000000000000000000000000000000000000000000000202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\""
        );
        let m2: MasterBlindingKey = serde_json::from_str(&s).unwrap();
        assert_eq!(m, m2);

        let hex =
            String::from("\"202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f\"");
        let m3: MasterBlindingKey = serde_json::from_str(&hex).unwrap();
        assert_eq!(m, m3);
    }
}
