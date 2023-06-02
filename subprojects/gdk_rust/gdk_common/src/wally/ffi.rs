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
#[allow(unused)]
pub struct WallyTx {
    _private: [u8; 0],
}

extern "C" {
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

    //WALLY_CORE_API int bip39_mnemonic_from_bytes(
    //    const struct words *w,
    //    const unsigned char *bytes,
    //    size_t bytes_len,
    //    char **output);
    pub fn bip39_mnemonic_from_bytes(
        word_list: *const c_void,
        bytes: *const c_uchar,
        bytes_len: size_t,
        output: *mut *mut c_char,
    ) -> c_int;

    //WALLY_CORE_API int wally_tx_from_bytes(
    //    const unsigned char *bytes,
    //    size_t bytes_len,
    //    uint32_t flags,
    //    struct wally_tx **output);
    #[allow(unused)]
    pub fn wally_tx_from_bytes(
        bytes: *const c_uchar,
        bytes_len: size_t,
        flags: u32,
        output: *mut *const WallyTx,
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

    //WALLY_CORE_API int wally_ec_public_key_from_private_key(const unsigned char *priv_key, size_t priv_key_len,
    //                                         unsigned char *bytes_out, size_t len)
    pub fn wally_ec_public_key_from_private_key(
        priv_key: *const c_uchar,
        priv_key_len: size_t,
        bytes_out: *mut c_uchar,
        len: size_t,
    ) -> c_int;

    //WALLY_CORE_API int wally_pbkdf2_hmac_sha512(
    //    const unsigned char *pass,
    //    size_t pass_len,
    //    const unsigned char *salt,
    //    size_t salt_len,
    //    uint32_t flags,
    //    uint32_t cost,
    //    unsigned char *bytes_out,
    //    size_t len);
    pub fn wally_pbkdf2_hmac_sha512(
        pass: *const c_uchar,
        pass_len: size_t,
        salt: *const c_uchar,
        salt_len: size_t,
        flags: u32,
        cost: u32,
        bytes_out: *mut c_uchar,
        len: size_t,
    ) -> c_int;

    /**
     * Convert satoshi to an explicit confidential value representation.
     *
     * :param satoshi: The value in satoshi to convert.
     * :param bytes_out: Destination for the confidential value bytes.
     * :param len: Size of ``bytes_out`` in bytes. Must be ``WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN``.
     */
    /*WALLY_CORE_API int wally_tx_confidential_value_from_satoshi(
    uint64_t satoshi,
    unsigned char *bytes_out,
    size_t len);*/
    pub fn wally_tx_confidential_value_from_satoshi(
        satoshi: u64,
        bytes_out: *mut c_uchar,
        len: size_t,
    ) -> c_int;

}
