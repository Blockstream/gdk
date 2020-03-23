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
//pub const WALLY_TX_FLAG_USE_WITNESS: u32 = 0x1;
/// Encode/Decode as an elements transaction.
#[allow(unused)]
pub const WALLY_TX_FLAG_USE_ELEMENTS: u32 = 0x2;

#[repr(C)]
#[allow(unused)]
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
    #[allow(unused)]
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
    #[allow(unused)]
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

    //WALLY_CORE_API int wally_asset_unblind(const unsigned char *pub_key, size_t pub_key_len,
    //                        const unsigned char *priv_key, size_t priv_key_len,
    //                        const unsigned char *proof, size_t proof_len,
    //                        const unsigned char *commitment, size_t commitment_len,
    //                        const unsigned char *extra, size_t extra_len,
    //                        const unsigned char *generator, size_t generator_len,
    //                        unsigned char *asset_out, size_t asset_out_len,
    //                        unsigned char *abf_out, size_t abf_out_len,
    //                        unsigned char *vbf_out, size_t vbf_out_len,
    //                        uint64_t *value_out)
    pub fn wally_asset_unblind(
        pub_key: *const c_uchar,
        pub_key_len: size_t,
        priv_key: *const c_uchar,
        priv_key_len: size_t,
        proof: *const c_uchar,
        proof_len: size_t,
        commitment: *const c_uchar,
        commitment_len: size_t,
        extra: *const c_uchar,
        extra_len: size_t,
        generator: *const c_uchar,
        generator_len: size_t,
        asset_out: *mut c_uchar,
        asset_out_len: size_t,
        abf_out: *mut c_uchar,
        abf_out_len: size_t,
        vbf_out: *mut c_uchar,
        vbf_out_len: size_t,
        value_out: *mut u64,
    ) -> c_int;

    //WALLY_CORE_API int wally_ec_public_key_from_private_key(const unsigned char *priv_key, size_t priv_key_len,
    //                                         unsigned char *bytes_out, size_t len)
    pub fn wally_ec_public_key_from_private_key(
        priv_key: *const c_uchar,
        priv_key_len: size_t,
        bytes_out: *mut c_uchar,
        len: size_t,
    ) -> c_int;

    //WALLY_CORE_API int wally_confidential_addr_from_addr(
    //    const char *address,
    //    uint32_t prefix,
    //    const unsigned char *pub_key,
    //    size_t pub_key_len,
    //    char **output)
    pub fn wally_confidential_addr_from_addr(
        address: *const c_char,
        prefix: u32,
        pub_key: *const c_uchar,
        pub_key_len: size_t,
        output: *mut *const c_char,
    ) -> c_int;

    // WALLY_CORE_API int wally_asset_unblind_with_nonce(
    //     const unsigned char *nonce_hash,
    //     size_t nonce_hash_len,
    //     const unsigned char *proof,
    //     size_t proof_len,
    //     const unsigned char *commitment,
    //     size_t commitment_len,
    //     const unsigned char *extra,
    //     size_t extra_len,
    //     const unsigned char *generator,
    //     size_t generator_len,
    //     unsigned char *asset_out,
    //     size_t asset_out_len,
    //     unsigned char *abf_out,
    //     size_t abf_out_len,
    //     unsigned char *vbf_out,
    //     size_t vbf_out_len,
    //     uint64_t *value_out);
    pub fn wally_asset_unblind_with_nonce(
        nonce_hash: *const c_uchar,
        nonce_hash_len: size_t,
        proof: *const c_uchar,
        proof_len: size_t,
        commitment: *const c_uchar,
        commitment_len: size_t,
        extra: *const c_uchar,
        extra_len: size_t,
        generator: *const c_uchar,
        generator_len: size_t,
        asset_out: *mut c_uchar,
        asset_out_len: size_t,
        abf_out: *mut c_uchar,
        abf_out_len: size_t,
        vbf_out: *mut c_uchar,
        vbf_out_len: size_t,
        value_out: *mut u64,
    ) -> c_int;
}
