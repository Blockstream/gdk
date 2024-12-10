#ifndef GDK_SIGNER_HPP
#define GDK_SIGNER_HPP
#pragma once

#include "ga_wally.hpp"
#include <mutex>
#include <nlohmann/json.hpp>
#include <optional>
#include <utility>

namespace green {

    class network_parameters;

    // Enum to represent the "level" of support for Liquid on an HW
    enum class liquid_support_level : uint32_t {
        none = 0, // Liquid is not supported
        lite = 1 // Liquid is supported, unblinding is done on the host
    };

    // Enum to indicate whether AE-protocol signatures are supported/mandatory
    enum class ae_protocol_support_level : uint32_t {
        none = 0, // AE signing protocol is not supported, only vanilla EC sigs
        optional = 1, // Both AE and vanilla EC sigs are supported
        mandatory = 2 // AE protocol mandatory, vanilla EC sigs not supported
    };

    //
    // Interface to signing and deriving privately derived xpub keys
    //
    class signer final {
    public:
        static const std::array<uint32_t, 1> REGISTER_PATH;
        static const std::array<uint32_t, 1> LOGIN_PATH;
        static const std::array<uint32_t, 1> CLIENT_SECRET_PATH;
        static const std::array<unsigned char, 8> PASSWORD_SALT;
        static const std::array<unsigned char, 8> BLOB_SALT;
        static const std::array<unsigned char, 8> WATCH_ONLY_SALT;
        static const std::array<unsigned char, 8> WO_SEED_U;
        static const std::array<unsigned char, 8> WO_SEED_P;
        static const std::array<unsigned char, 8> WO_SEED_K;

        using cache_t = std::map<std::vector<uint32_t>, std::string>;

        signer(
            const network_parameters& net_params, const nlohmann::json& hw_device, const nlohmann::json& credentials);

        signer(const signer&) = delete;
        signer& operator=(const signer&) = delete;
        signer(signer&&) = delete;
        signer& operator=(signer&&) = delete;
        virtual ~signer();

        // Returns true if this signers credentials and HW device match 'other'
        bool is_compatible_with(const std::shared_ptr<signer>& other) const;

        // Return the mnemonic associated with this signer (empty if none available)
        std::string get_mnemonic(const std::string& password);

        // Normalize watch only credentials (encrypts/decrypts any rich watch only data)
        static nlohmann::json normalize_watch_only_credentials(const nlohmann::json& credentials);

        // Returns true if this signer produces only low-r signatures
        bool supports_low_r() const;

        // Returns true if this signer can sign arbitrary scripts
        bool supports_arbitrary_scripts() const;

        // Returns the level of liquid support
        liquid_support_level get_liquid_support() const;

        // Returns true if this signer can export the master blinding key
        bool supports_host_unblinding() const;

        // Returns true if this signer can sign txs with externally blinded outputs
        bool supports_external_blinding() const;

        // Returns true if this signer supports signing pay-to-taproot inputs
        bool supports_p2tr() const;

        // Returns how this signer supports the Anti-Exfil protocol
        ae_protocol_support_level get_ae_protocol_support() const;

        // Returns true if this signer should use the Anti-Exfil protocol.
        // Currently always true if the signer supports it.
        bool use_ae_protocol() const;

        // Returns true if this signer is for a remote service
        bool is_remote() const;

        // Returns true if this signer is for a Liquid session
        bool is_liquid() const;

        // Returns true if this signer is watch-only (cannot sign)
        bool is_watch_only() const;

        // Returns true if this signer is a watch-only descriptor wallet
        // (cannot sign, fixed list of subaccounts)
        bool is_descriptor_watch_only() const;

        // Returns true if this signer is hardware (i.e. externally implemented)
        bool is_hardware() const;

        // Get the device description for this signer
        const nlohmann::json& get_device() const;

        // Get the login credentials for this signer (empty for hardware signers)
        nlohmann::json get_credentials() const;

        // Get the master xpub. Equivalent to calling `get_bip32_xpub` with an
        // empty path.
        std::string get_master_bip32_xpub();

        // Returns true if we have the master xpub
        bool has_master_bip32_xpub();

        // Get the xpub for 'm/<path>'. This should only be used to derive
        // the master xpub for privately derived keys such as subaccounts.
        // Use xpub_hdkeys to quickly derive from the resulting key.
        std::string get_bip32_xpub(uint32_span_t path);

        // Whether this signer has a pre-computed cached xpub for the given path
        bool has_bip32_xpub(uint32_span_t path);

        // Cache an xpub for a given path.
        // Returns the xpub and whether or not it was inserted.
        std::pair<std::string, bool> cache_bip32_xpub(uint32_span_t path, const std::string& bip32_xpub);

        // Get cached xpubs and paths from a signer as a cacheable json format
        nlohmann::json get_cached_bip32_xpubs_json();

        // Return the ECDSA signature for a message using the bip32 key 'm/<path>'
        ec_sig_t ecdsa_sign(uint32_span_t path, byte_span_t message);

        // Return the Schnorr signature for a hash using the taptweak bip32 key 'm/<path>'
        ec_sig_t schnorr_sign(uint32_span_t path, byte_span_t message);

        priv_key_t get_blinding_key_from_script(byte_span_t script);

        std::vector<unsigned char> get_blinding_pubkey_from_script(byte_span_t script);

        bool has_master_blinding_key() const;
        blinding_key_t get_master_blinding_key() const;
        void set_master_blinding_key(const std::string& blinding_key_hex);

        std::vector<unsigned char> get_master_fingerprint();
        void set_master_fingerprint(const std::string& fingerprint_hex);

    private:
        // Get all cached xpubs and their paths
        cache_t get_cached_bip32_xpubs();

        // Immutable
        const bool m_is_main_net;
        const bool m_is_liquid;
        const unsigned char m_btc_version;
        const nlohmann::json m_credentials;
        const nlohmann::json m_device;
        wally_ext_key_ptr m_master_key;
        // Mutable post construction
        mutable std::mutex m_mutex;
        std::optional<blinding_key_t> m_master_blinding_key;
        std::optional<std::vector<unsigned char>> m_master_fingerprint;
        cache_t m_cached_bip32_xpubs;
    };

} // namespace green

#endif
