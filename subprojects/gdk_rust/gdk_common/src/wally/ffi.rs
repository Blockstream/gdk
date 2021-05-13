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

    /**
     * Create a blinded Asset Generator from an Asset Tag and Asset Blinding Factor.
     *
     * :param asset: Asset Tag to create a blinding generator for.
     * :param asset_len: Length of ``asset`` in bytes. Must be ``ASSET_TAG_LEN``.
     * :param abf: Asset Blinding Factor (Random entropy to blind with).
     * :param abf_len: Length of ``abf`` in bytes. Must be ``ASSET_TAG_LEN``.
     * :param bytes_out: Destination for the resulting Asset Generator.
     * :param len: The length of ``bytes_out`` in bytes. Must be ``ASSET_GENERATOR_LEN``.
     */
    /*WALLY_CORE_API int wally_asset_generator_from_bytes(
        const unsigned char *asset,
        size_t asset_len,
        const unsigned char *abf,
        size_t abf_len,
        unsigned char *bytes_out,
        size_t len);
    */
    pub fn wally_asset_generator_from_bytes(
        asset: *const c_uchar,
        asset_len: size_t,
        abf: *const c_uchar,
        abf_len: size_t,
        bytes_out: *mut c_uchar,
        len: size_t,
    ) -> c_int;

    /**
     * Generate the final value blinding factor required for blinding a confidential transaction.
     *
     * :param values: Array of transaction input values in satoshi
     * :param values_len: Length of ``values``, also the number of elements in all three of the input arrays, which is equal
     *|     to ``num_inputs`` plus the number of outputs.
     * :param num_inputs: Number of elements in the input arrays that represent transaction inputs. The number of outputs is
     *|     implicitly ``values_len`` - ``num_inputs``.
     * :param abf:  Array of bytes representing ``values_len`` asset blinding factors.
     * :param abf_len: Length of ``abf`` in bytes. Must be ``values_len`` * ``BLINDING_FACTOR_LEN``.
     * :param vbf: Array of bytes representing (``values_len`` - 1) value blinding factors.
     * :param vbf_len: Length of ``vbf`` in bytes. Must be (``values_len`` - 1) * ``BLINDING_FACTOR_LEN``.
     * :param bytes_out: Buffer to received the final value blinding factor.
     * :param len: Length of ``bytes_out``. Must be ``BLINDING_FACTOR_LEN``.
     */
    /*WALLY_CORE_API int wally_asset_final_vbf(
     const uint64_t *values,
     size_t values_len,
     size_t num_inputs,
     const unsigned char *abf,
     size_t abf_len,
     const unsigned char *vbf,
     size_t vbf_len,
     unsigned char *bytes_out,
     size_t len);
    */
    pub fn wally_asset_final_vbf(
        values: *const u64,
        values_len: size_t,
        num_inputs: u32,
        abf: *const c_uchar,
        abf_len: size_t,
        vbf: *const c_uchar,
        vbf_len: size_t,
        bytes_out: *mut c_uchar,
        len: size_t,
    ) -> c_int;

    /**
     * Calculate the value commitment for a transaction output.
     *
     * :param value: Output value in satoshi.
     * :param vbf: Value Blinding Factor.
     * :param vbf_len: Length of ``vbf``. Must be ``BLINDING_FACTOR_LEN``.
     * :param generator: Asset generator from `wally_asset_generator_from_bytes`.
     * :param generator_len: Length of ``generator``. Must be ``ASSET_GENERATOR_LEN``.
     * :param bytes_out: Buffer to receive value commitment.
     * :param len: Length of ``bytes_out``. Must be ``ASSET_GENERATOR_LEN``.
     */
    /*WALLY_CORE_API int wally_asset_value_commitment(
    uint64_t value,
    const unsigned char *vbf,
    size_t vbf_len,
    const unsigned char *generator,
    size_t generator_len,
    unsigned char *bytes_out,
    size_t len);*/
    pub fn wally_asset_value_commitment(
        value: u64,
        vbf: *const c_uchar,
        vbf_len: size_t,
        generator: *const c_uchar,
        generator_len: size_t,
        bytes_out: *mut c_uchar,
        len: size_t,
    ) -> c_int;

    /**
     * Generate a rangeproof for a transaction output.
     *
     * :param value: Value of the output in satoshi.
     * :param pub_key: Public blinding key for the output. See `wally_confidential_addr_to_ec_public_key`.
     * :param pub_key_len: Length of ``pub_key``. Must be ``EC_PUBLIC_KEY_LEN``
     * :param priv_key: Pivate ephemeral key. Should be randomly generated for each output.
     * :param priv_key_length: Length of ``priv_key``.
     * :param asset: Asset id of output.
     * :param asset_len: Length of ``asset``. Must be ``ASSET_TAG_LEN``.
     * :param abf: Asset blinding factor. Randomly generated for each output.
     * :param abf_len: Length of ``abf``. Must be ``BLINDING_FACTOR_LEN``.
     * :param vbf: Value blinding factor. Randomly generated for each output except the last, which is generate by calling
     *|     `wally_asset_final_vbf`.
     * :param vbf_len: Length of ``vbf``. Must be ``BLINDING_FACTOR_LEN``.
     * :param commitment: Value commitment from `wally_asset_value_commitment`.
     * :param commitment_len: Length of ``commitment``. Must be ``ASSET_COMMITMENT_LEN``.
     * :param extra: Set this to the script pubkey of the output.
     * :param extra_len: Length of ``extra``, i.e. script pubkey.
     * :param generator: Asset generator from `wally_asset_generator_from_bytes`.
     * :param generator_len: Length of ``generator`. Must be ``ASSET_GENERATOR_LEN``.
     * :param min_value: Recommended value 1.
     * :param exp: Exponent value. -1 >= ``exp`` >= 18. Recommended value 0.
     * :param min_bits: 0 >= min_bits >= 64. Recommended value 36.
     * :param bytes_out: Buffer to receive rangeproof.
     * :param len: Length of ``bytes_out``. See ``ASSET_RANGEPROOF_MAX_LEN``.
     * :param written: Number of bytes actually written to ``bytes_out``.
     */
    /*
    WALLY_CORE_API int wally_asset_rangeproof(
        uint64_t value,
        const unsigned char *pub_key,
        size_t pub_key_len,
        const unsigned char *priv_key,
        size_t priv_key_len,
        const unsigned char *asset,
        size_t asset_len,
        const unsigned char *abf,
        size_t abf_len,
        const unsigned char *vbf,
        size_t vbf_len,
        const unsigned char *commitment,
        size_t commitment_len,
        const unsigned char *extra,
        size_t extra_len,
        const unsigned char *generator,
        size_t generator_len,
        uint64_t min_value,
        int exp,
        int min_bits,
        unsigned char *bytes_out,
        size_t len,
        size_t *written);
        */
    pub fn wally_asset_rangeproof(
        value: u64,
        pub_key: *const c_uchar,
        pub_key_len: size_t,
        priv_key: *const c_uchar,
        priv_key_len: size_t,
        asset: *const c_uchar,
        asset_len: size_t,
        abf: *const c_uchar,
        abf_len: size_t,
        vbf: *const c_uchar,
        vbf_len: size_t,
        commitment: *const c_uchar,
        commitment_len: size_t,
        extra: *const c_uchar,
        extra_len: size_t,
        generator: *const c_uchar,
        generator_len: size_t,
        min_value: u64,
        exp: c_int,
        min_bits: c_int,
        bytes_out: *mut c_uchar,
        len: size_t,
        written: *mut size_t,
    ) -> c_int;

    /**
     * Return the required buffer size for receiving a surjection proof
     *
     * :param num_inputs: Number of transaction inputs.
     * :param written: Destination for the surjection proof size.
     */
    /*WALLY_CORE_API int wally_asset_surjectionproof_size(
    size_t num_inputs,
    size_t *written);*/
    pub fn wally_asset_surjectionproof_size(len: size_t, written: *mut size_t) -> c_int;

    /**
     * Generate a surjection proof for a transaction output
     *
     * :param output_asset: asset id for the output.
     * :param output_asset_len: Length of ``asset``. Must be ``ASSET_TAG_LEN``.
     * :param output_abf: Asset blinding factor for the output. Generated randomly for each output.
     * :param output_abf_len: Length of ``output_abf``. Must be ``BLINDING_FACTOR_LEN``.
     * :param output_generator: Asset generator from `wally_asset_generator_from_bytes`.
     * :param output_generator_len: Length of ``output_generator`. Must be ``ASSET_GENERATOR_LEN``.
     * :param bytes: Must be generated randomly for each output.
     * :param bytes_len: Length of ``bytes``. Must be 32.
     * :param asset: Array of input asset tags.
     * :param asset_len: Length of ``asset`. Must be ``ASSET_TAG_LEN`` * number of inputs.
     * :param abf: Array of asset blinding factors from the transaction inputs.
     * :param abf_len: Length of ``abf``. Must be ``BLINDING_FACTOR_LEN`` * number of inputs.
     * :param generator: Array of asset generators from transaction inputs.
     * :param generator_len: Length of ``generator``. Must be ``ASSET_GENERATOR_LEN`` * number of inputs.
     * :param bytes_out: Buffer to receive surjection proof.
     * :param bytes_out_len: Length of ``bytes_out``. See `wally_asset_surjectionproof_size`.
     * :param written: Number of bytes actually written to ``bytes_out``.
     */
    /*WALLY_CORE_API int wally_asset_surjectionproof(
    const unsigned char *output_asset,
    size_t output_asset_len,
    const unsigned char *output_abf,
    size_t output_abf_len,
    const unsigned char *output_generator,
    size_t output_generator_len,
    const unsigned char *bytes,
    size_t bytes_len,
    const unsigned char *asset,
    size_t asset_len,
    const unsigned char *abf,
    size_t abf_len,
    const unsigned char *generator,
    size_t generator_len,
    unsigned char *bytes_out,
    size_t len,
    size_t *written);
    */
    pub fn wally_asset_surjectionproof(
        output_asset: *const c_uchar,
        output_asset_len: size_t,
        output_abf: *const c_uchar,
        output_abf_len: size_t,
        output_generator: *const c_uchar,
        output_generator_len: size_t,
        bytes: *const c_uchar,
        bytes_len: size_t,
        asset: *const c_uchar,
        asset_len: size_t,
        abf: *const c_uchar,
        abf_len: size_t,
        generator: *const c_uchar,
        generator_len: size_t,
        bytes_out: *mut c_uchar,
        len: size_t,
        written: *mut size_t,
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
