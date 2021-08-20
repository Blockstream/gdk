//!
//! Links to libwally methods used.
//!

use std::ptr;

use bitcoin::secp256k1;
use std::fmt;

use std::borrow::Cow;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;

pub mod ffi;

#[derive(Clone)]
pub struct MasterBlindingKey(pub [u8; 64]);

// need to manually implement Debug cause it's not supported for array>32
impl fmt::Debug for MasterBlindingKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MasterBlindingKey ({})", hex::encode(&self.0[..]))
    }
}

/// The size of BIP39-derived seeds in bytes.
const BIP39_SEED_BYTES: usize = 64;

/// Validate a BIP-39 mnemonic.
fn bip39_mnemonic_validate(mnemonic: &str) -> bool {
    let c_mnemonic = make_str(mnemonic);
    let ret = unsafe {
        let ret = ffi::bip39_mnemonic_validate(ptr::null(), c_mnemonic);
        let _ = CString::from_raw(c_mnemonic);
        ret
    };
    ret == ffi::WALLY_OK
}

/// Convert the mnemonic phrase and passphrase to a binary seed.
pub fn bip39_mnemonic_to_seed(mnemonic: &str, passphrase: &str) -> Option<[u8; BIP39_SEED_BYTES]> {
    if !bip39_mnemonic_validate(mnemonic) {
        return None;
    }

    let c_mnemonic = make_str(mnemonic);
    let c_passphrase = make_str(passphrase);
    let mut out = [0u8; BIP39_SEED_BYTES];
    let mut written = 0usize;
    let ret = unsafe {
        let ret = ffi::bip39_mnemonic_to_seed(
            c_mnemonic,
            c_passphrase,
            out.as_mut_ptr(),
            BIP39_SEED_BYTES,
            &mut written,
        );
        let _ = CString::from_raw(c_mnemonic);
        let _ = CString::from_raw(c_passphrase);
        ret
    };
    assert_eq!(ret, ffi::WALLY_OK);
    assert_eq!(written, BIP39_SEED_BYTES);
    Some(out)
}

pub fn asset_blinding_key_from_seed(seed: &[u8]) -> MasterBlindingKey {
    assert_eq!(seed.len(), 64);
    let mut out = [0u8; 64];
    let ret = unsafe {
        ffi::wally_asset_blinding_key_from_seed(
            seed.as_ptr(),
            seed.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    MasterBlindingKey(out)
}

pub fn asset_blinding_key_to_ec_private_key(
    master_blinding_key: &MasterBlindingKey,
    script_pubkey: &elements::Script,
) -> secp256k1::SecretKey {
    let mut out = [0; 32];
    let ret = unsafe {
        ffi::wally_asset_blinding_key_to_ec_private_key(
            master_blinding_key.0.as_ptr(),
            master_blinding_key.0.len(),
            script_pubkey.as_bytes().as_ptr(),
            script_pubkey.as_bytes().len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    secp256k1::SecretKey::from_slice(&out).expect("size is 32")
}

//TODO to be replaced by secp256k1::PublicKey::from_secret_key
pub fn ec_public_key_from_private_key(priv_key: secp256k1::SecretKey) -> secp256k1::PublicKey {
    let mut pub_key = [0; 33];

    let ret = unsafe {
        ffi::wally_ec_public_key_from_private_key(
            priv_key.as_ptr(),
            priv_key.len(),
            pub_key.as_mut_ptr(),
            pub_key.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    secp256k1::PublicKey::from_slice(&pub_key[..]).unwrap() // TODO return Result?
}

pub fn pbkdf2_hmac_sha512_256(password: Vec<u8>, salt: Vec<u8>, cost: u32) -> [u8; 32] {
    let mut tmp = [0; 64];
    let mut out = [0; 32];
    let ret = unsafe {
        ffi::wally_pbkdf2_hmac_sha512(
            password.as_ptr(),
            password.len(),
            salt.as_ptr(),
            salt.len(),
            0,
            cost,
            tmp.as_mut_ptr(),
            tmp.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    out.copy_from_slice(&tmp[..32]);
    out
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
    use elements::Script;
    use hex;
    use std::str::FromStr;

    #[test]
    fn test_bip39_mnemonic_to_seed() {
        // test vector from the BIP spec
        let v_mnem = "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length";
        let v_seed = "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440";
        let v_passphrase = "TREZOR";

        let seed = bip39_mnemonic_to_seed(&v_mnem, &v_passphrase).unwrap();
        assert_eq!(v_seed, &hex::encode(&seed[..]));
    }

    #[test]
    /// test vectors taken from libwally-core test_confidential_addr.py test_master_blinding_key
    fn test_elements_master_blinding_key() {
        let mnemonic = "all all all all all all all all all all all all";
        let passphrase = "";
        let seed = bip39_mnemonic_to_seed(mnemonic, passphrase);
        assert!(seed.is_some());
        let seed = seed.unwrap();
        assert_eq!(seed.len(), 64);
        assert_eq!(hex::encode(&seed[..]), "c76c4ac4f4e4a00d6b274d5c39c700bb4a7ddc04fbc6f78e85ca75007b5b495f74a9043eeb77bdd53aa6fc3a0e31462270316fa04b8c19114c8798706cd02ac8");
        let master_blinding_key = asset_blinding_key_from_seed(&seed);
        assert_eq!(
            hex::encode(&master_blinding_key.0[32..]),
            "6c2de18eabeff3f7822bc724ad482bef0557f3e1c1e1c75b7a393a5ced4de616"
        );

        let unconfidential_addr = "2dpWh6jbhAowNsQ5agtFzi7j6nKscj6UnEr";
        let script: Script =
            hex::decode("76a914a579388225827d9f2fe9014add644487808c695d88ac").unwrap().into();
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
        let xpub = bitcoin::util::bip32::ExtendedPubKey::from_str("tpubD6NzVbkrYhZ4XYa9MoLt4BiMZ4gkt2faZ4BcmKu2a9te4LDpQmvEz2L2yDERivHxFPnxXXhqDRkUNnQCpZggCyEZLBktV7VaSmwayqMJy1s").unwrap();
        let password = xpub.encode().to_vec();
        let salt = "testnet".as_bytes().to_vec();
        let cost = 2048;
        let bytes = pbkdf2_hmac_sha512_256(password, salt, cost);
        assert_eq!(
            hex::encode(bytes),
            "657a9de33d1f7753edbb86c90b0ba064bd1b986570f1a5019ed80459877b013b"
        );
    }
}
