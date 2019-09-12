//!
//! Links to libwally methods used.
//!

use std::ptr;

use bitcoin::secp256k1;

use crate::errors::Error;
use crate::util::{make_str, read_str};

mod ffi {
    use libc::{c_char, c_int, c_uchar, c_void};

    #[allow(non_camel_case_types)]
    type size_t = usize;

    pub const WALLY_OK: c_int = 0;
    #[allow(unused)]
    pub const WALLY_ERROR: c_int = -1;
    #[allow(unused)]
    pub const WALLY_EINVAL: c_int = -2;
    #[allow(unused)]
    pub const WALLY_ENOMEM: c_int = -3;

    /// Encode witness data if present.
    pub const WALLY_TX_FLAG_USE_WITNESS: u32 = 0x1;
    /// Encode/Decode as an elements transaction.
    #[allow(unused)]
    pub const WALLY_TX_FLAG_USE_ELEMENTS: u32 = 0x2;

    #[repr(C)]
    pub struct WallyTx {
        _private: [u8; 0],
    }

    extern "C" {
        //WALLY_CORE_API int bip39_mnemonic_from_bytes(
        //    const struct words *w,
        //    const unsigned char *bytes,
        //    size_t bytes_len,
        //    char **output);
        pub fn bip39_mnemonic_from_bytes(
            word_list: *const c_void,
            bytes: *const c_uchar,
            bytes_len: size_t,
            output: *mut *const c_char,
        ) -> c_int;

        //WALLY_CORE_API int bip39_mnemonic_to_bytes(
        //    const struct words *w,
        //    const char *mnemonic,
        //    unsigned char *bytes_out,
        //    size_t len,
        //    size_t *written);
        pub fn bip39_mnemonic_to_bytes(
            word_list: *const c_void,
            mnemonic: *const c_char,
            bytes_out: *mut c_uchar,
            len: size_t,
            written: *mut size_t,
        ) -> c_int;

        //WALLY_CORE_API int bip39_mnemonic_to_seed(
        //    const char *mnemonic,
        //    const char *passphrase,
        //    unsigned char *bytes_out,
        //    size_t len,
        //    size_t *written);
        pub fn bip39_mnemonic_to_seed(
            mnemonic: *const c_char,
            passphrase: *const c_char,
            bytes_out: *mut c_uchar,
            len: size_t,
            written: *mut size_t,
        ) -> c_int;

        //WALLY_CORE_API int bip39_mnemonic_validate(
        //    const struct words *w,
        //    const char *mnemonic);
        pub fn bip39_mnemonic_validate(word_list: *const c_void, mnemonic: *const c_char) -> c_int;

        //WALLY_CORE_API int wally_tx_from_bytes(
        //    const unsigned char *bytes,
        //    size_t bytes_len,
        //    uint32_t flags,
        //    struct wally_tx **output);
        pub fn wally_tx_from_bytes(
            bytes: *const c_uchar,
            bytes_len: size_t,
            flags: u32,
            output: *mut *const WallyTx,
        ) -> c_int;

        //WALLY_CORE_API int wally_tx_get_elements_signature_hash(
        //  const struct wally_tx *tx,
        //  size_t index,
        //  const unsigned char *script, size_t script_len,
        //  const unsigned char *value, size_t value_len,
        //  uint32_t sighash, uint32_t flags,
        //  unsigned char *bytes_out, size_t len)
        pub fn wally_tx_get_elements_signature_hash(
            tx: *const WallyTx,
            index: usize,
            script: *const c_uchar,
            script_len: usize,
            value: *const c_uchar,
            value_len: usize,
            sighash: u32,
            flags: u32,
            bytes_out: *mut c_uchar,
            len: usize,
        ) -> c_int;

        //WALLY_CORE_API int wally_asset_blinding_key_from_seed(
        //    const unsigned char *bytes,
        //    size_t bytes_len,
        //    unsigned char *bytes_out,
        //    size_t len);
        pub fn wally_asset_blinding_key_from_seed(
            bytes: *const c_uchar,
            bytes_len: size_t,
            bytes_out: *mut c_uchar,
            len: size_t,
        ) -> c_int;

        //WALLY_CORE_API int wally_asset_blinding_key_to_ec_private_key(
        //    const unsigned char *bytes,
        //    size_t bytes_len,
        //    const unsigned char *script,
        //    size_t script_len,
        //    unsigned char *bytes_out,
        //    size_t len);
        //    }
        pub fn wally_asset_blinding_key_to_ec_private_key(
            bytes: *const c_uchar,
            bytes_len: size_t,
            script: *const c_uchar,
            script_len: size_t,
            bytes_out: *mut c_uchar,
            len: size_t,
        ) -> c_int;
    }
}

/// The max entropy size in bytes for BIP39 mnemonics.
const BIP39_MAX_ENTROPY_BYTES: usize = 32;
/// The size of BIP39-derived seeds in bytes.
const BIP39_SEED_BYTES: usize = 64;

/// Generate a BIP39 mnemonic from entropy bytes.
pub fn bip39_mnemonic_from_bytes(entropy: &[u8]) -> String {
    let mut out = ptr::null();
    let ret = unsafe {
        ffi::bip39_mnemonic_from_bytes(ptr::null(), entropy.as_ptr(), entropy.len(), &mut out)
    };
    assert_eq!(ret, ffi::WALLY_OK);
    read_str(out)
}

/// Validate the validity of a BIP-39 mnemonic.
pub fn bip39_mnemonic_validate(mnemonic: &str) -> Result<(), Error> {
    let ret = unsafe { ffi::bip39_mnemonic_validate(ptr::null(), make_str(mnemonic)) };
    if ret == ffi::WALLY_OK {
        Ok(())
    } else {
        Err(Error::InvalidMnemonic)
    }
}

/// Convert the mnemonic back into the entropy bytes.
pub fn bip39_mnemonic_to_bytes(mnemonic: &str) -> Result<Vec<u8>, Error> {
    bip39_mnemonic_validate(mnemonic)?;

    let c_mnemonic = make_str(mnemonic);
    let mut out = Vec::with_capacity(BIP39_MAX_ENTROPY_BYTES);
    let mut written = 0usize;
    let ret = unsafe {
        ffi::bip39_mnemonic_to_bytes(
            ptr::null(),
            c_mnemonic,
            out.as_mut_ptr(),
            BIP39_MAX_ENTROPY_BYTES,
            &mut written,
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    assert!(written <= BIP39_MAX_ENTROPY_BYTES);
    unsafe {
        out.set_len(written);
    }
    Ok(out)
}

/// Convert the mnemonic phrase and passphrase to a binary seed.
pub fn bip39_mnemonic_to_seed(
    mnemonic: &str,
    passphrase: &str,
) -> Result<[u8; BIP39_SEED_BYTES], Error> {
    bip39_mnemonic_validate(mnemonic)?;

    let c_mnemonic = make_str(mnemonic);
    let c_passphrase = make_str(passphrase);
    let mut out = [0u8; BIP39_SEED_BYTES];
    let mut written = 0usize;
    let ret = unsafe {
        ffi::bip39_mnemonic_to_seed(
            c_mnemonic,
            c_passphrase,
            out.as_mut_ptr(),
            BIP39_SEED_BYTES,
            &mut written,
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    assert_eq!(written, BIP39_SEED_BYTES);
    Ok(out)
}

/// Calculate the signature hash for a specific index of
/// an Elements transaction.

#[cfg(feature = "liquid")]
pub fn tx_get_elements_signature_hash(
    tx: &elements::Transaction,
    index: usize,
    script_code: &bitcoin::Script,
    value: &elements::confidential::Value,
    sighash: u32,
    segwit: bool,
) -> sha256d::Hash {
    let flags = if segwit {
        ffi::WALLY_TX_FLAG_USE_WITNESS
    } else {
        0
    };

    let tx_bytes = serialize(tx);
    let mut wally_tx = ptr::null();
    let ret = unsafe {
        ffi::wally_tx_from_bytes(
            tx_bytes.as_ptr(),
            tx_bytes.len(),
            flags | ffi::WALLY_TX_FLAG_USE_ELEMENTS,
            &mut wally_tx,
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);

    let value = serialize(value);
    let mut out = [0u8; sha256d::Hash::LEN];
    let ret = unsafe {
        ffi::wally_tx_get_elements_signature_hash(
            wally_tx,
            index,
            script_code.as_bytes().as_ptr(),
            script_code.as_bytes().len(),
            value.as_ptr(),
            value.len(),
            sighash,
            flags,
            out.as_mut_ptr(),
            sha256d::Hash::LEN,
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    //TODO(stevenroose) use from_inner with hashes 0.7 in bitcoin 0.19
    sha256d::Hash::from_slice(&out[..]).unwrap()
}

pub fn asset_blinding_key_from_seed(seed: &[u8]) -> [u8; 64] {
    assert_eq!(seed.len(), 64);
    let mut out = [0; 64];
    let ret = unsafe {
        ffi::wally_asset_blinding_key_from_seed(
            seed.as_ptr(),
            seed.len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    out
}

pub fn asset_blinding_key_to_ec_private_key(
    master_blinding_key: &[u8; 64],
    script_pubkey: &bitcoin::Script,
) -> secp256k1::SecretKey {
    let mut out = [0; 32];
    let ret = unsafe {
        ffi::wally_asset_blinding_key_to_ec_private_key(
            master_blinding_key.as_ptr(),
            master_blinding_key.len(),
            script_pubkey.as_bytes().as_ptr(),
            script_pubkey.as_bytes().len(),
            out.as_mut_ptr(),
            out.len(),
        )
    };
    assert_eq!(ret, ffi::WALLY_OK);
    secp256k1::SecretKey::from_slice(&out).expect("size is 32")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;

    #[test]
    fn test_bip39_mnemonic_to_seed() {
        // test vector from the BIP spec
        let v_entropy = "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c";
        let v_mnem = "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length";
        let v_seed = "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440";
        let v_passphrase = "TREZOR";

        let mnemonic = bip39_mnemonic_from_bytes(&hex::decode(v_entropy).unwrap());
        assert_eq!(mnemonic, v_mnem);
        assert!(bip39_mnemonic_validate(&mnemonic).is_ok());
        assert_eq!(hex::encode(&bip39_mnemonic_to_bytes(&mnemonic).unwrap()), v_entropy);
        let seed = bip39_mnemonic_to_seed(&mnemonic, &v_passphrase).unwrap();
        assert_eq!(v_seed, &hex::encode(&seed[..]));
    }
}
