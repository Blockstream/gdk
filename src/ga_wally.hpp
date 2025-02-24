#ifndef GDK_CORE_WALLY_HPP
#define GDK_CORE_WALLY_HPP
#pragma once

#include <array>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "gsl_wrapper.hpp"
#include "wally_wrapper.h"

#include "assertion.hpp"

#define SIGHASH_SINGLE_ANYONECANPAY (WALLY_SIGHASH_SINGLE | WALLY_SIGHASH_ANYONECANPAY)

namespace std {
    template <> struct default_delete<struct ext_key> {
        void operator()(struct ext_key* ptr) const { ::bip32_key_free(ptr); }
    };

    template <> struct default_delete<struct wally_tx_input> {
        void operator()(struct wally_tx_input* ptr) const { wally_tx_input_free(ptr); }
    };

    template <> struct default_delete<struct wally_tx_output> {
        void operator()(struct wally_tx_output* ptr) const { wally_tx_output_free(ptr); }
    };
} // namespace std

namespace green {

    using wally_ext_key_ptr = std::unique_ptr<struct ext_key>;

    using byte_span_t = gsl::span<const unsigned char>;
    using uint16_span_t = gsl::span<const uint16_t>;
    using uint32_span_t = gsl::span<const uint32_t>;
    using uint64_span_t = gsl::span<const uint64_t>;

    using ec_sig_t = std::array<unsigned char, EC_SIGNATURE_LEN>;
    using ecdsa_sig_rec_t = std::array<unsigned char, EC_SIGNATURE_RECOVERABLE_LEN>;
    using chain_code_t = std::array<unsigned char, WALLY_BIP32_CHAIN_CODE_LEN>;
    using pbkdf2_hmac256_t = std::array<unsigned char, PBKDF2_HMAC_SHA256_LEN>;
    using pbkdf2_hmac512_t = std::array<unsigned char, PBKDF2_HMAC_SHA512_LEN>;
    using pub_key_t = std::array<unsigned char, EC_PUBLIC_KEY_LEN>;
    using priv_key_t = std::array<unsigned char, EC_PRIVATE_KEY_LEN>;

    using asset_id_t = std::array<unsigned char, ASSET_TAG_LEN>;
    using vbf_t = std::array<unsigned char, 32>;
    using abf_t = std::array<unsigned char, 32>;
    using abf_vbf_t = std::array<unsigned char, WALLY_ABF_VBF_LEN>;
    using unblind_t = std::tuple<asset_id_t, vbf_t, abf_t, uint64_t>;
    using cvalue_t = std::array<unsigned char, WALLY_TX_ASSET_CT_VALUE_UNBLIND_LEN>;
    using blinding_key_t = std::array<unsigned char, HMAC_SHA512_LEN>;

    struct wally_string_dtor {
        void operator()(char* p) { wally_free_string(p); }
    };
    using wally_string_ptr = std::unique_ptr<char, wally_string_dtor>;
    inline std::string make_string(char* p) { return std::string(wally_string_ptr(p).get()); }

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
    pbkdf2_hmac256_t pbkdf2_hmac_sha512_256(byte_span_t password, byte_span_t salt, uint32_t cost = 2048);

    //
    // BIP 32
    //

    //
    // A bip32 extended key for public key derivation.
    //
    class xpub_hdkey final {
    public:
        explicit xpub_hdkey(const std::string& bip32_xpub);

        explicit xpub_hdkey(const ext_key& src);

        xpub_hdkey(bool is_main_net, byte_span_t public_key, byte_span_t chain_code = {});

        xpub_hdkey(const xpub_hdkey&) = default;
        xpub_hdkey& operator=(const xpub_hdkey&) = default;
        xpub_hdkey(xpub_hdkey&&) = default;
        xpub_hdkey& operator=(xpub_hdkey&&) = default;

        ~xpub_hdkey();

        bool operator==(const xpub_hdkey& rhs) const;
        inline bool operator!=(const xpub_hdkey& rhs) const { return !(*this == rhs); }

        xpub_hdkey derive(uint32_span_t path) const;

        chain_code_t get_chain_code() const;
        pub_key_t get_public_key() const;
        std::vector<unsigned char> get_xonly_key() const;
        std::vector<unsigned char> get_tweaked_xonly_key(bool is_liquid) const;
        std::vector<unsigned char> get_fingerprint() const;
        std::vector<unsigned char> get_parent_fingerprint() const;
        void set_parent_fingerprint(byte_span_t fingerprint);

        std::string to_base58() const;
        std::string to_hashed_identifier(const std::string& network) const;

    private:
        ext_key m_ext_key;
    };

    wally_ext_key_ptr bip32_key_from_parent_path_alloc(
        const wally_ext_key_ptr& parent, uint32_span_t path, uint32_t flags);

    wally_ext_key_ptr bip32_key_from_seed_alloc(
        byte_span_t seed, uint32_t version, uint32_t flags = BIP32_FLAG_SKIP_HASH);

    constexpr uint32_t harden(uint32_t pointer) { return pointer | 0x80000000; }
    constexpr uint32_t unharden(uint32_t pointer) { return pointer & 0x7fffffff; }
    inline bool is_hardened(uint32_t pointer) { return pointer & 0x80000000; }

    //
    // Scripts
    //
    std::vector<unsigned char> scriptsig_p2pkh_from_der(byte_span_t public_key, byte_span_t sig);

    std::vector<unsigned char> scriptsig_p2sh_p2wpkh_from_bytes(byte_span_t public_key);

    void scriptpubkey_csv_2of2_then_1_from_bytes(
        byte_span_t keys, uint32_t csv_blocks, bool optimize, std::vector<unsigned char>& out);

    uint32_t get_csv_blocks_from_csv_script(byte_span_t script);

    void scriptpubkey_multisig_from_bytes(byte_span_t keys, uint32_t threshold, std::vector<unsigned char>& out);

    size_t varbuff_get_length(size_t script_len);

    std::vector<unsigned char> script_push_from_bytes(byte_span_t data);

    std::vector<unsigned char> scriptpubkey_p2pkh_from_hash160(byte_span_t hash);
    std::vector<unsigned char> scriptpubkey_p2pkh_from_public_key(byte_span_t public_key);
    std::vector<unsigned char> scriptpubkey_p2wpkh_from_public_key(byte_span_t public_key);
    std::vector<unsigned char> scriptpubkey_p2sh_p2wpkh_from_public_key(byte_span_t public_key);
    std::vector<unsigned char> scriptpubkey_p2sh_from_hash160(byte_span_t hash);
    std::vector<unsigned char> scriptpubkey_p2sh_p2wsh_from_bytes(byte_span_t script);
    std::vector<unsigned char> scriptpubkey_p2tr_from_public_key(byte_span_t public_key, bool is_liquid);

    uint32_t scriptpubkey_get_type(byte_span_t scriptpubkey);

    // Create a v0 segwit witness program
    std::vector<unsigned char> witness_script(byte_span_t script, uint32_t flags);

    std::array<unsigned char, SHA256_LEN> format_bitcoin_message_hash(byte_span_t message);

    std::string electrum_script_hash_hex(byte_span_t script_bytes);

    std::vector<unsigned char> scrypt(byte_span_t password, byte_span_t salt, uint32_t cost = 16384,
        uint32_t block_size = 8, uint32_t parallelism = 8);

    std::string bip39_mnemonic_from_bytes(byte_span_t data);

    void bip39_mnemonic_validate(const std::string& mnemonic);

    std::vector<unsigned char> bip39_mnemonic_to_seed(
        const std::string& mnemonic, const std::string& passphrase = std::string());

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

    std::string base58check_from_bytes(byte_span_t data);

    bool validate_base58check(const std::string& base58);

    std::vector<unsigned char> base58check_to_bytes(const std::string& base58);

    std::string base64_from_bytes(byte_span_t bytes);

    std::vector<unsigned char> base64_to_bytes(const std::string& base64);

    //
    // Signing/Encryption
    //
    void aes(byte_span_t key, byte_span_t data, uint32_t flags, std::vector<unsigned char>& out);

    void aes_cbc(byte_span_t key, byte_span_t iv, byte_span_t data, uint32_t flags, std::vector<unsigned char>& out);

    ec_sig_t ec_sig_from_bytes(
        byte_span_t private_key, byte_span_t hash, uint32_t flags = EC_FLAG_ECDSA | EC_FLAG_GRIND_R);

    ecdsa_sig_rec_t ec_sig_rec_from_compact(byte_span_t compact_sig, byte_span_t hash, byte_span_t public_key);

    std::vector<unsigned char> ec_sig_to_der(byte_span_t sig, uint32_t sighash_flags = WALLY_SIGHASH_ALL);
    ec_sig_t ec_sig_from_der(byte_span_t der, bool has_sighash_byte);

    bool ec_sig_verify(
        byte_span_t public_key, byte_span_t message_hash, byte_span_t sig, uint32_t flags = EC_FLAG_ECDSA);

    std::string sig_only_to_der_hex(const ec_sig_t& signature);

    std::vector<unsigned char> ec_public_key_from_private_key(byte_span_t private_key, bool do_decompress = false);

    // convert a WIF/BIP38/BIP32 encoded private key to a raw private key
    std::pair<std::vector<unsigned char>, bool> to_private_key_bytes(
        const std::string& encoded, const std::string& passphrase, bool is_mainnet);

    bool ec_private_key_verify(byte_span_t bytes);

    std::pair<priv_key_t, std::vector<unsigned char>> get_ephemeral_keypair();

    std::array<unsigned char, SHA256_LEN> ecdh(byte_span_t public_key, byte_span_t private_key);

    std::array<unsigned char, WALLY_HOST_COMMITMENT_LEN> ae_host_commit_from_bytes(
        byte_span_t entropy, uint32_t flags = EC_FLAG_ECDSA);

    bool ec_scalar_verify(byte_span_t scalar);

    std::array<unsigned char, EC_SCALAR_LEN> ec_scalar_add(byte_span_t a, byte_span_t b);

    std::array<unsigned char, EC_SCALAR_LEN> ec_scalar_subtract(byte_span_t a, byte_span_t b);

    //
    // Elements
    //
    std::array<unsigned char, ASSET_GENERATOR_LEN> asset_generator_from_bytes(byte_span_t asset, byte_span_t abf);

    std::array<unsigned char, ASSET_TAG_LEN> asset_final_vbf(
        uint64_span_t values, size_t num_inputs, byte_span_t abf, byte_span_t vbf);

    std::array<unsigned char, EC_SCALAR_LEN> asset_scalar_offset(uint64_t value, byte_span_t abf, byte_span_t vbf);

    std::vector<unsigned char> asset_value_commitment(uint64_t value, byte_span_t vbf, byte_span_t generator);

    std::vector<unsigned char> asset_rangeproof(uint64_t value, byte_span_t public_key, byte_span_t private_key,
        byte_span_t asset, byte_span_t abf, byte_span_t vbf, byte_span_t commitment, byte_span_t extra,
        byte_span_t generator, uint64_t min_value = 1, int exp = 0, int min_bits = 52);

    size_t asset_rangeproof_max_size(uint64_t value, int min_bits = 52);

    std::vector<unsigned char> explicit_rangeproof(
        uint64_t value, byte_span_t nonce, byte_span_t vbf, byte_span_t commitment, byte_span_t generator);

    bool explicit_rangeproof_verify(
        byte_span_t rangeproof, uint64_t value, byte_span_t commitment, byte_span_t generator);

    std::vector<unsigned char> asset_surjectionproof(byte_span_t output_asset, byte_span_t output_abf,
        byte_span_t output_generator, byte_span_t bytes, byte_span_t asset, byte_span_t abf, byte_span_t generator);

    unblind_t asset_unblind(byte_span_t private_key, byte_span_t rangeproof, byte_span_t commitment,
        byte_span_t nonce_commitment, byte_span_t extra_commitment, byte_span_t generator);

    unblind_t asset_unblind_with_nonce(byte_span_t blinding_nonce, byte_span_t rangeproof, byte_span_t commitment,
        byte_span_t extra_commitment, byte_span_t generator);

    bool is_possible_confidential_addr(const std::string& address);
    std::string confidential_addr_to_addr(const std::string& address, uint32_t prefix);
    std::string confidential_addr_to_addr_segwit(
        const std::string& address, const std::string& confidential_prefix, const std::string& family);

    pub_key_t confidential_addr_to_ec_public_key(const std::string& address, uint32_t prefix);
    pub_key_t confidential_addr_segwit_to_ec_public_key(
        const std::string& address, const std::string& confidential_prefix);

    std::string confidential_addr_from_addr(
        const std::string& address, uint32_t prefix, const std::string& blinding_pubkey_hex);
    std::string confidential_addr_from_addr_segwit(const std::string& address, const std::string& family,
        const std::string& confidential_prefix, const std::string& blinding_pubkey_hex);

    blinding_key_t asset_blinding_key_from_seed(byte_span_t seed);

    priv_key_t asset_blinding_key_to_ec_private_key(byte_span_t blinding_key, byte_span_t script);

    abf_vbf_t asset_blinding_key_to_abf_vbf(byte_span_t blinding_key, byte_span_t hash_prevouts, uint32_t output_index);

    std::array<unsigned char, SHA256_LEN> get_hash_prevouts(byte_span_t txids, uint32_span_t output_indices);

    cvalue_t tx_confidential_value_from_satoshi(uint64_t satoshi);

    uint64_t tx_confidential_value_to_satoshi(byte_span_t ct_value);

} // namespace green

#endif /* GDK_CORE_WALLY_HPP */
