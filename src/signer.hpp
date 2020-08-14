#ifndef GDK_SIGNER_HPP
#define GDK_SIGNER_HPP
#pragma once

#include "boost_wrapper.hpp"
#include "ga_wally.hpp"
#include "gsl_wrapper.hpp"
#include "memory.hpp"
#include <nlohmann/json.hpp>

namespace ga {
namespace sdk {
    inline const std::array<uint32_t, 1> LOGIN_PATH{ { 0x4741b11e } };
    inline const std::array<uint32_t, 1> PASSWORD_PATH{ { harden(0x70617373) } }; // 'pass'
    inline const std::array<unsigned char, 8> PASSWORD_SALT = {
        { 0x70, 0x61, 0x73, 0x73, 0x73, 0x61, 0x6c, 0x74 } // 'passsalt'
    };
    class network_parameters;

    // Enum to represent the "level" of support for Liquid on an HW
    enum class liquid_support_level : uint32_t {
        none, // Liquid is not supported
        lite, // Liquid is supported, but the unblinding is done on the host
        full // Everything is done on the HW
    };

    //
    // Interface to signing and deriving privately derived xpub keys
    //
    class signer {
    public:
        explicit signer(const network_parameters& net_params);

        signer(const signer&) = delete;
        signer& operator=(const signer&) = delete;
        signer(signer&&) = delete;
        signer& operator=(signer&&) = delete;
        virtual ~signer();

        // Get the challenge to sign for GA authentication
        virtual std::string get_challenge() = 0;

        // Returns true if if this signer produces only low-r signatures
        virtual bool supports_low_r() const;

        // Returns true if if this signer can sign arbitrary scripts
        virtual bool supports_arbitrary_scripts() const;

        // Returns the level of liquid support
        virtual liquid_support_level supports_liquid() const;

        virtual nlohmann::json get_hw_device() const;

        // Get the xpub for 'm/<path>'. This should only be used to derive the master
        // xpub for privately derived master keys, since it may involve talking to
        // hardware. Use xpub_hdkeys_base to quickly derive from the resulting key.
        virtual xpub_t get_xpub(gsl::span<const uint32_t> path = empty_span<uint32_t>()) = 0;
        virtual std::string get_bip32_xpub(gsl::span<const uint32_t> path) = 0;

        // Return the ECDSA signature for a hash using the bip32 key 'm/<path>'
        virtual ecdsa_sig_t sign_hash(gsl::span<const uint32_t> path, gsl::span<const unsigned char> hash) = 0;

        virtual priv_key_t get_blinding_key_from_script(byte_span_t script);

        virtual std::vector<unsigned char> get_public_key_from_blinding_key(byte_span_t script);

    protected:
        const network_parameters& m_net_params;
    };

    //
    // Watch-only signer for watch-only sessions
    //
    class watch_only_signer final : public signer {
    public:
        explicit watch_only_signer(const network_parameters& net_params);

        watch_only_signer(const watch_only_signer&) = delete;
        watch_only_signer& operator=(const watch_only_signer&) = delete;
        watch_only_signer(watch_only_signer&&) = delete;
        watch_only_signer& operator=(watch_only_signer&&) = delete;
        ~watch_only_signer() override;

        bool supports_low_r() const override;
        bool supports_arbitrary_scripts() const override;
        liquid_support_level supports_liquid() const override;

        std::string get_challenge() override;

        xpub_t get_xpub(gsl::span<const uint32_t> path = empty_span<uint32_t>()) override;
        std::string get_bip32_xpub(gsl::span<const uint32_t> path) override;

        ecdsa_sig_t sign_hash(gsl::span<const uint32_t> path, gsl::span<const unsigned char> hash) override;
    };

    //
    // A signer that signs using a private key held in memory
    //
    class software_signer final : public signer {
    public:
        // FIXME: Take mnemonic/xpub as a char* to avoid copying
        software_signer(const network_parameters& net_params, const std::string& mnemonic_or_xpub);

        software_signer(const software_signer&) = delete;
        software_signer& operator=(const software_signer&) = delete;
        software_signer(software_signer&&) = delete;
        software_signer& operator=(software_signer&&) = delete;
        ~software_signer() override;

        bool supports_low_r() const override;
        bool supports_arbitrary_scripts() const override;
        liquid_support_level supports_liquid() const override;

        std::string get_challenge() override;

        xpub_t get_xpub(gsl::span<const uint32_t> path = empty_span<uint32_t>()) override;
        std::string get_bip32_xpub(gsl::span<const uint32_t> path) override;

        ecdsa_sig_t sign_hash(gsl::span<const uint32_t> path, gsl::span<const unsigned char> hash) override;
        priv_key_t get_blinding_key_from_script(byte_span_t script) override;

    private:
        wally_ext_key_ptr m_master_key;
        boost::optional<blinding_key_t> m_master_blinding_key;
    };

    //
    // A proxy for a hardware signer controlled by the caller
    //
    class hardware_signer final : public signer {
    public:
        // FIXME: Take mnemonic/xpub as a char* to avoid copying
        hardware_signer(const network_parameters& net_params, const nlohmann::json& hw_device);

        hardware_signer(const hardware_signer&) = delete;
        hardware_signer& operator=(const hardware_signer&) = delete;
        hardware_signer(hardware_signer&&) = delete;
        hardware_signer& operator=(hardware_signer&&) = delete;
        ~hardware_signer() override;

        bool supports_low_r() const override;
        bool supports_arbitrary_scripts() const override;
        liquid_support_level supports_liquid() const override;

        nlohmann::json get_hw_device() const override;

        std::string get_challenge() override;

        xpub_t get_xpub(gsl::span<const uint32_t> path = empty_span<uint32_t>()) override;
        std::string get_bip32_xpub(gsl::span<const uint32_t> path) override;

        ecdsa_sig_t sign_hash(gsl::span<const uint32_t> path, gsl::span<const unsigned char> hash) override;
        priv_key_t get_blinding_key_from_script(byte_span_t script) override;

    private:
        const nlohmann::json m_hw_device;
    };

} // namespace sdk
} // namespace ga

#endif
