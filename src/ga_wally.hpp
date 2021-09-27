#ifndef GDK_CORE_WALLY_HPP
#define GDK_CORE_WALLY_HPP
#pragma once

#include <array>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "gsl_wrapper.hpp"
#include "include/wally_wrapper.h"

#include "assertion.hpp"

namespace std {
template <> struct default_delete<struct ext_key> {
    void operator()(struct ext_key* ptr) const { ::bip32_key_free(ptr); }
};

template <> struct default_delete<struct wally_tx_input> {
    void operator()(struct wally_tx_input* ptr) const { wally_tx_input_free(ptr); }
};

template <> struct default_delete<struct wally_tx_witness_stack> {
    void operator()(struct wally_tx_witness_stack* ptr) const { wally_tx_witness_stack_free(ptr); }
};

template <> struct default_delete<struct wally_tx_output> {
    void operator()(struct wally_tx_output* ptr) const { wally_tx_output_free(ptr); }
};

template <> struct default_delete<struct wally_tx> {
    void operator()(struct wally_tx* ptr) const { wally_tx_free(ptr); }
};
} // namespace std

namespace ga {
namespace sdk {
    using wally_ext_key_ptr = std::unique_ptr<struct ext_key>;
    using wally_tx_input_ptr = std::unique_ptr<struct wally_tx_input>;
    using wally_tx_witness_stack_ptr = std::unique_ptr<struct wally_tx_witness_stack>;
    using wally_tx_output_ptr = std::unique_ptr<struct wally_tx_output>;
    using wally_tx_ptr = std::unique_ptr<struct wally_tx>;

    using byte_span_t = gsl::span<const unsigned char>;
    using uint32_span_t = gsl::span<const uint32_t>;
    using uint64_span_t = gsl::span<const uint64_t>;

    using ecdsa_sig_t = std::array<unsigned char, EC_SIGNATURE_LEN>;
    using chain_code_t = std::array<unsigned char, 32>;
    using pbkdf2_hmac512_t = std::array<unsigned char, PBKDF2_HMAC_SHA512_LEN>;
    using pub_key_t = std::array<unsigned char, EC_PUBLIC_KEY_LEN>;
    using priv_key_t = std::array<unsigned char, EC_PRIVATE_KEY_LEN>;
    using xpub_t = std::pair<chain_code_t, pub_key_t>;

    using asset_id_t = std::array<unsigned char, ASSET_TAG_LEN>;
    using vbf_t = std::array<unsigned char, 32>;
    using abf_t = std::array<unsigned char, 32>;
    using unblind_t = std::tuple<asset_id_t, vbf_t, abf_t, uint64_t>;
    using cvalue_t = std::array<unsigned char, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN>;
    using blinding_key_t = std::array<unsigned char, HMAC_SHA512_LEN>;

    struct wally_string_dtor {
        void operator()(char* p) { wally_free_string(p); }
    };
    using wally_string_ptr = std::unique_ptr<char, wally_string_dtor>;
    inline std::string make_string(char* p) { return std::string(wally_string_ptr(p).get()); }

#ifdef __GNUC__
#define GA_USE_RESULT __attribute__((warn_unused_result))
#else
#define GA_USE_RESULT
#endif

    //
    // Hashing/HMAC
    //
    std::array<unsigned char, HASH160_LEN> hash160(byte_span_t data);

    std::array<unsigned char, SHA256_LEN> sha256(byte_span_t data);

    std::array<unsigned char, SHA256_LEN> sha256d(byte_span_t data);

    std::array<unsigned char, SHA512_LEN> sha512(byte_span_t data);

    std::array<unsigned char, HMAC_SHA256_LEN> hmac_sha256(byte_span_t key, byte_span_t data);

    std::array<unsigned char, HMAC_SHA512_LEN> hmac_sha512(byte_span_t key, byte_span_t data);

    pbkdf2_hmac512_t pbkdf2_hmac_sha512(byte_span_t password, byte_span_t salt, uint32_t cost = 2048);

    // PBKDF2-HMAC-SHA512, truncated to 256 bits
    std::array<unsigned char, PBKDF2_HMAC_SHA256_LEN> pbkdf2_hmac_sha512_256(
        byte_span_t password, byte_span_t salt, uint32_t cost = 2048);

    //
    // BIP 32
    //
    std::array<unsigned char, BIP32_SERIALIZED_LEN> bip32_key_serialize(const ext_key& hdkey, uint32_t flags);

    wally_ext_key_ptr bip32_key_unserialize_alloc(byte_span_t data);

    ext_key bip32_public_key_from_parent_path(const ext_key& parent, uint32_span_t path);

    ext_key bip32_public_key_from_parent(const ext_key& parent, uint32_t pointer);

    wally_ext_key_ptr bip32_public_key_from_bip32_xpub(const std::string& bip32_xpub);

    wally_ext_key_ptr bip32_key_from_parent_path_alloc(
        const wally_ext_key_ptr& parent, uint32_span_t path, uint32_t flags);

    wally_ext_key_ptr bip32_key_init_alloc(uint32_t version, uint32_t depth, uint32_t child_num, byte_span_t chain_code,
        byte_span_t public_key, byte_span_t private_key = byte_span_t(), byte_span_t hash = byte_span_t(),
        byte_span_t parent = byte_span_t());

    wally_ext_key_ptr bip32_key_from_seed_alloc(
        byte_span_t seed, uint32_t version, uint32_t flags = BIP32_FLAG_SKIP_HASH);

    // BIP 38
    std::vector<unsigned char> bip38_raw_to_private_key(byte_span_t priv_key, byte_span_t passphrase, uint32_t flags);

    size_t bip38_raw_get_flags(byte_span_t priv_key);

    //
    // Scripts
    //
    void scriptsig_multisig_from_bytes(
        byte_span_t script, byte_span_t signatures, uint32_span_t sighashes, std::vector<unsigned char>& out);

    std::vector<unsigned char> scriptsig_p2pkh_from_der(byte_span_t public_key, byte_span_t sig);

    void scriptpubkey_csv_2of2_then_1_from_bytes(
        byte_span_t keys, uint32_t csv_blocks, bool optimize, std::vector<unsigned char>& out);

    void scriptpubkey_csv_2of3_then_2_from_bytes(
        byte_span_t keys, uint32_t csv_blocks, std::vector<unsigned char>& out);

    uint32_t get_csv_blocks_from_csv_redeem_script(byte_span_t redeem_script);

    std::vector<ecdsa_sig_t> get_sigs_from_multisig_script_sig(byte_span_t script_sig);

    void scriptpubkey_multisig_from_bytes(byte_span_t keys, uint32_t threshold, std::vector<unsigned char>& out);

    std::vector<unsigned char> scriptpubkey_p2pkh_from_hash160(byte_span_t hash);

    std::vector<unsigned char> scriptpubkey_p2sh_from_hash160(byte_span_t hash);

    std::vector<unsigned char> witness_program_from_bytes(byte_span_t script, uint32_t flags);

    std::array<unsigned char, SHA256_LEN> format_bitcoin_message_hash(byte_span_t message);

    std::string electrum_script_hash_hex(byte_span_t script_bytes);

    void scrypt(byte_span_t password, byte_span_t salt, uint32_t cost, uint32_t block_size, uint32_t parallelism,
        std::vector<unsigned char>& out);

    std::string bip39_mnemonic_from_bytes(byte_span_t data);

    void bip39_mnemonic_validate(const std::string& mnemonic);

    std::vector<unsigned char> bip39_mnemonic_to_seed(
        const std::string& mnemonic, const std::string& password = std::string());

    std::vector<unsigned char> bip39_mnemonic_to_bytes(const std::string& mnemonic);

    //
    // Strings/Addresses
    //
    std::string b2h(byte_span_t data);
    std::string b2h_rev(byte_span_t data);

    std::vector<unsigned char> h2b(const char* hex);
    std::vector<unsigned char> h2b(const std::string& hex);
    std::vector<unsigned char> h2b(const std::string& hex, uint8_t prefix);
    template <size_t N> std::array<unsigned char, N> h2b_array(const std::string& hex)
    {
        const auto vec = h2b(hex);
        GDK_RUNTIME_ASSERT(vec.size() == N);
        std::array<unsigned char, N> ret;
        std::copy(vec.begin(), vec.end(), ret.begin());
        return ret;
    }

    std::vector<unsigned char> h2b_rev(const char* hex);
    std::vector<unsigned char> h2b_rev(const std::string& hex);
    std::vector<unsigned char> h2b_rev(const std::string& hex, uint8_t prefix);

    template <std::size_t N> std::array<unsigned char, N> h2b(const std::string& hex)
    {
        GDK_RUNTIME_ASSERT(hex.size() / 2 == N);
        std::array<unsigned char, N> buff{ { 0 } };

        const std::vector<unsigned char> bin = h2b(hex);
        GDK_RUNTIME_ASSERT(bin.size() == N);

        std::copy(std::begin(bin), std::end(bin), buff.begin());
        return buff;
    }

    template <std::size_t N> std::array<unsigned char, N> h2b_rev(const std::string& hex)
    {
        GDK_RUNTIME_ASSERT(hex.size() / 2 == N);
        std::array<unsigned char, N> buff{ { 0 } };

        const std::vector<unsigned char> bin = h2b_rev(hex);
        GDK_RUNTIME_ASSERT(bin.size() == N);

        std::copy(std::begin(bin), std::end(bin), buff.begin());
        return buff;
    }

    // Returns true if 'hex' decodes correctly to 'len' bytes
    bool validate_hex(const std::string& hex, size_t len);

    std::vector<unsigned char> addr_segwit_v0_to_bytes(const std::string& addr, const std::string& family);

    std::string public_key_to_p2pkh_addr(unsigned char btc_version, byte_span_t public_key);

    std::string base58check_from_bytes(byte_span_t data);

    std::vector<unsigned char> base58check_to_bytes(const std::string& base58);

    wally_string_ptr base64_string_from_bytes(byte_span_t bytes);

    std::string base64_from_bytes(byte_span_t bytes);

    std::vector<unsigned char> base64_to_bytes(const std::string& base64);

    //
    // Signing/Encryption
    //
    void aes(byte_span_t key, byte_span_t data, uint32_t flags, std::vector<unsigned char>& out);

    void aes_cbc(byte_span_t key, byte_span_t iv, byte_span_t data, uint32_t flags, std::vector<unsigned char>& out);

    ecdsa_sig_t ec_sig_from_bytes(
        byte_span_t private_key, byte_span_t hash, uint32_t flags = EC_FLAG_ECDSA | EC_FLAG_GRIND_R);

    std::vector<unsigned char> ec_sig_to_der(byte_span_t sig, bool sighash = false);
    ecdsa_sig_t ec_sig_from_der(byte_span_t der, bool sighash = false);

    bool ec_sig_verify(
        byte_span_t public_key, byte_span_t message_hash, byte_span_t sig, uint32_t flags = EC_FLAG_ECDSA);

    inline auto sig_to_der_hex(const ecdsa_sig_t& signature) { return b2h(ec_sig_to_der(signature)); }

    std::vector<unsigned char> ec_public_key_from_private_key(byte_span_t private_key);

    std::vector<unsigned char> ec_public_key_decompress(byte_span_t public_key);

    std::pair<std::vector<unsigned char>, bool> to_private_key_bytes(
        const std::string& priv_key, const std::string& passphrase, bool mainnet);

    bool ec_private_key_verify(byte_span_t bytes);

    std::pair<priv_key_t, std::vector<unsigned char>> get_ephemeral_keypair();

    std::vector<unsigned char> ecdh(byte_span_t public_key, byte_span_t private_key);

    std::vector<unsigned char> ae_host_commit_from_bytes(byte_span_t entropy, uint32_t flags = EC_FLAG_ECDSA);

    bool ae_verify(byte_span_t public_key, byte_span_t message_hash, byte_span_t host_entropy,
        byte_span_t signer_commitment, byte_span_t sig, uint32_t flags = EC_FLAG_ECDSA);

    //
    // Elements
    //
    std::array<unsigned char, ASSET_GENERATOR_LEN> asset_generator_from_bytes(byte_span_t asset, byte_span_t abf);

    std::array<unsigned char, ASSET_TAG_LEN> asset_final_vbf(
        uint64_span_t values, size_t num_inputs, byte_span_t abf, byte_span_t vbf);

    std::array<unsigned char, ASSET_COMMITMENT_LEN> asset_value_commitment(
        uint64_t value, byte_span_t vbf, byte_span_t generator);

    std::vector<unsigned char> asset_rangeproof(uint64_t value, byte_span_t public_key, byte_span_t private_key,
        byte_span_t asset, byte_span_t abf, byte_span_t vbf, byte_span_t commitment, byte_span_t extra,
        byte_span_t generator, uint64_t min_value, int exp, int min_bits);

    size_t asset_surjectionproof_size(size_t num_inputs);

    std::vector<unsigned char> asset_surjectionproof(byte_span_t output_asset, byte_span_t output_abf,
        byte_span_t output_generator, byte_span_t bytes, byte_span_t asset, byte_span_t abf, byte_span_t generator);

    unblind_t asset_unblind(byte_span_t private_key, byte_span_t rangeproof, byte_span_t commitment,
        byte_span_t nonce_commitment, byte_span_t extra_commitment, byte_span_t generator);

    unblind_t asset_unblind_with_nonce(byte_span_t blinding_nonce, byte_span_t rangeproof, byte_span_t commitment,
        byte_span_t extra_commitment, byte_span_t generator);

    std::string confidential_addr_to_addr(const std::string& address, uint32_t prefix);
    std::string confidential_addr_to_addr_segwit(
        const std::string& address, const std::string& confidential_prefix, const std::string& prefix);

    pub_key_t confidential_addr_to_ec_public_key(const std::string& address, uint32_t prefix);
    pub_key_t confidential_addr_segwit_to_ec_public_key(
        const std::string& address, const std::string& confidential_prefix);

    std::string confidential_addr_from_addr(const std::string& address, uint32_t prefix, byte_span_t public_key);

    blinding_key_t asset_blinding_key_from_seed(byte_span_t seed);

    priv_key_t asset_blinding_key_to_ec_private_key(byte_span_t blinding_key, byte_span_t script);

    //
    // Transactions
    //
    GA_USE_RESULT uint32_t tx_flags(bool is_liquid);

    GA_USE_RESULT bool tx_is_elements(const wally_tx_ptr& tx);

    GA_USE_RESULT size_t tx_get_length(const wally_tx_ptr& tx, uint32_t flags = WALLY_TX_FLAG_USE_WITNESS);

    std::vector<unsigned char> tx_to_bytes(const wally_tx_ptr& tx, uint32_t flags = WALLY_TX_FLAG_USE_WITNESS);

    void tx_add_raw_output(const wally_tx_ptr& tx, uint64_t satoshi, byte_span_t script);

    void tx_add_elements_raw_output(const wally_tx_ptr& tx, byte_span_t script, byte_span_t asset, byte_span_t value,
        byte_span_t nonce, byte_span_t surjectionproof, byte_span_t rangeproof);

    void tx_elements_output_commitment_set(const wally_tx_ptr& tx, size_t index, byte_span_t asset, byte_span_t value,
        byte_span_t nonce, byte_span_t surjectionproof, byte_span_t rangeproof);

    std::array<unsigned char, SHA256_LEN> tx_get_btc_signature_hash(const wally_tx_ptr& tx, size_t index,
        byte_span_t script, uint64_t satoshi, uint32_t sighash = WALLY_SIGHASH_ALL,
        uint32_t flags = WALLY_TX_FLAG_USE_WITNESS);

    std::array<unsigned char, SHA256_LEN> tx_get_elements_signature_hash(const wally_tx_ptr& tx, size_t index,
        byte_span_t script, byte_span_t value, uint32_t sighash = WALLY_SIGHASH_ALL,
        uint32_t flags = WALLY_TX_FLAG_USE_WITNESS);

    wally_tx_ptr tx_init(uint32_t locktime, size_t inputs_allocation_len, size_t outputs_allocation_len = 2,
        uint32_t version = WALLY_TX_VERSION_2);

    wally_tx_ptr tx_from_bin(byte_span_t tx_bin, uint32_t flags = WALLY_TX_FLAG_USE_WITNESS);
    wally_tx_ptr tx_from_hex(const std::string& tx_hex, uint32_t flags = WALLY_TX_FLAG_USE_WITNESS);

    void tx_add_raw_input(const wally_tx_ptr& tx, byte_span_t txhash, uint32_t index, uint32_t sequence,
        byte_span_t script, const wally_tx_witness_stack_ptr& witness = {});

    GA_USE_RESULT size_t tx_get_vsize(const wally_tx_ptr& tx);

    GA_USE_RESULT size_t tx_get_weight(const wally_tx_ptr& tx);

    void tx_set_input_script(const wally_tx_ptr& tx, size_t index, byte_span_t script);

    void tx_set_input_witness(const wally_tx_ptr& tx, size_t index, const wally_tx_witness_stack_ptr& witness);

    GA_USE_RESULT size_t tx_vsize_from_weight(size_t weight);

    wally_tx_witness_stack_ptr tx_witness_stack_init(size_t allocation_len);

    void tx_witness_stack_add(const wally_tx_witness_stack_ptr& stack, byte_span_t witness);

    void tx_witness_stack_add_dummy(const wally_tx_witness_stack_ptr& stack, uint32_t flags);

    cvalue_t tx_confidential_value_from_satoshi(uint64_t satoshi);

    uint64_t tx_confidential_value_to_satoshi(byte_span_t ct_value);

    xpub_t make_xpub(const ext_key* hdkey);
    xpub_t make_xpub(const std::string& chain_code_hex, const std::string& public_key_hex);
    xpub_t make_xpub(const std::string& bip32_xpub);
    std::string bip32_key_to_base58(const struct ext_key* hdkey, uint32_t flags);

    constexpr uint32_t harden(uint32_t pointer) { return pointer | 0x80000000; }
    constexpr uint32_t unharden(uint32_t pointer) { return pointer & 0x7fffffff; }

#undef GA_USE_RESULT

} /* namespace sdk */
} /* namespace ga */

#endif /* GDK_CORE_WALLY_HPP */
