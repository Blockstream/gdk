#ifndef GDK_SIGNER_HPP
#define GDK_SIGNER_HPP
#pragma once

#include "boost_wrapper.hpp"
#include "ga_wally.hpp"
#include <nlohmann/json.hpp>

namespace ga {
namespace sdk {
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
    class signer {
    public:
        static const std::array<uint32_t, 1> LOGIN_PATH;
        static const std::array<uint32_t, 1> CLIENT_SECRET_PATH;
        static const std::array<unsigned char, 8> PASSWORD_SALT;
        static const std::array<unsigned char, 8> BLOB_SALT;

        signer(const network_parameters& net_params, const nlohmann::json& hw_device);

        signer(const signer&) = delete;
        signer& operator=(const signer&) = delete;
        signer(signer&&) = delete;
        signer& operator=(signer&&) = delete;
        virtual ~signer();

        // Return the mnemonic associated with this signer (empty if none available)
        virtual std::string get_mnemonic(const std::string& password);

        // Get the challenge to sign for GA authentication
        virtual std::string get_challenge();

        // Returns true if if this signer produces only low-r signatures
        bool supports_low_r() const;

        // Returns true if if this signer can sign arbitrary scripts
        bool supports_arbitrary_scripts() const;

        // Returns the level of liquid support
        liquid_support_level get_liquid_support() const;

        // Returns true if if this signer can export the master blinding key
        bool supports_host_unblinding() const;

        // Returns how this signer supports the Anti-Exfil protocol
        ae_protocol_support_level get_ae_protocol_support() const;

        // Returns true if this signer can sign (i.e. its not watch-only)
        bool can_sign() const;

        // Get the HW device description for this signer (empty if not HW)
        nlohmann::json get_hw_device() const;

        // Get the xpub for 'm/<path>'. This should only be used to derive the master
        // xpub for privately derived master keys, since it may involve talking to
        // hardware. Use xpub_hdkeys_base to quickly derive from the resulting key.
        virtual xpub_t get_xpub(uint32_span_t path);
        virtual std::string get_bip32_xpub(uint32_span_t path);

        // Return the ECDSA signature for a hash using the bip32 key 'm/<path>'
        virtual ecdsa_sig_t sign_hash(uint32_span_t path, byte_span_t hash);

        priv_key_t get_blinding_key_from_script(byte_span_t script);

        std::vector<unsigned char> get_blinding_pubkey_from_script(byte_span_t script);

        bool has_master_blinding_key() const;
        void set_master_blinding_key(const blinding_key_t& blinding_key);

    protected:
        const bool m_is_main_net;
        const bool m_is_liquid;
        const unsigned char m_btc_version;
        const nlohmann::json m_hw_device;
        boost::optional<blinding_key_t> m_master_blinding_key;
    };

    //
    // Watch-only signer for watch-only sessions
    //
    class watch_only_signer final : public signer {
    public:
        explicit watch_only_signer(const network_parameters& net_params);
        ~watch_only_signer() override;
    };

    //
    // A proxy for a hardware signer controlled by the caller
    //
    class hardware_signer : public signer {
    public:
        hardware_signer(const network_parameters& net_params, const nlohmann::json& hw_device);
        ~hardware_signer() override;
    };

    //
    // A signer that signs using a private key held in memory
    //
    class software_signer final : public hardware_signer {
    public:
        // FIXME: Take mnemonic/xpub as a char* to avoid copying
        software_signer(const network_parameters& net_params, const std::string& mnemonic_or_xpub);
        ~software_signer() override;

        std::string get_mnemonic(const std::string& password) override;

        std::string get_challenge() override;

        xpub_t get_xpub(uint32_span_t path) override;
        std::string get_bip32_xpub(uint32_span_t path) override;

        ecdsa_sig_t sign_hash(uint32_span_t path, byte_span_t hash) override;

    private:
        std::string m_mnemonic;
        wally_ext_key_ptr m_master_key;
    };

} // namespace sdk
} // namespace ga

#endif
