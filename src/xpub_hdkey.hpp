#ifndef GDK_XPUB_HDKEY_HPP
#define GDK_XPUB_HDKEY_HPP
#pragma once

#include <map>
#include <optional>

#include "ga_wally.hpp"

namespace green {

    class network_parameters;

    //
    // Derives public keys from an xpub
    //
    class xpub_hdkey final {
    public:
        xpub_hdkey(bool is_main_net, const xpub_t& xpub, uint32_span_t path = {});

        static xpub_hdkey from_public_key(bool is_main_net, byte_span_t public_key);

        xpub_hdkey(const xpub_hdkey&) = default;
        xpub_hdkey& operator=(const xpub_hdkey&) = default;
        xpub_hdkey(xpub_hdkey&&) = default;
        xpub_hdkey& operator=(xpub_hdkey&&) = default;

        explicit xpub_hdkey(const ext_key& ext_key) { m_ext_key = ext_key; }

        ~xpub_hdkey();

        xpub_hdkey derive(uint32_span_t path);

        xpub_t to_xpub_t() const;
        pub_key_t get_public_key() const;
        std::vector<unsigned char> get_fingerprint() const;

        std::string to_base58() const;
        std::string to_hashed_identifier(const std::string& network) const;

    private:
        ext_key m_ext_key;
    };

    //
    // Base class for collections of xpubs
    //
    class xpub_hdkeys {
    public:
        explicit xpub_hdkeys(const network_parameters& net_params);
        xpub_hdkeys(const network_parameters& net_params, const xpub_t& xpub);

        xpub_hdkeys(const xpub_hdkeys&) = default;
        xpub_hdkeys& operator=(const xpub_hdkeys&) = default;
        xpub_hdkeys(xpub_hdkeys&&) = default;
        xpub_hdkeys& operator=(xpub_hdkeys&&) = default;
        virtual ~xpub_hdkeys() = default;

        // If is_internal is empty, derives a Green key for a subaccount and pointer.
        // Otherwise, derives a BIP44 key for a subaccount and pointer, internal or not.
        xpub_hdkey derive(uint32_t subaccount, uint32_t pointer, std::optional<bool> is_internal = {});

        // Get the path to a subaccount parent
        virtual std::vector<uint32_t> get_subaccount_root_path(uint32_t subaccount) const = 0;

        // Get the full path to a key in a subaccount
        virtual std::vector<uint32_t> get_subaccount_full_path(
            uint32_t subaccount, uint32_t pointer, bool is_internal) const = 0;

        virtual xpub_hdkey get_subaccount(uint32_t subaccount) = 0;

    protected:
        bool m_is_main_net;
        bool m_is_liquid;
        xpub_t m_xpub;
        std::map<uint32_t, xpub_hdkey> m_subaccounts;
    };

    //
    // Derives Green public keys for the given network:
    // Main account
    //     m/1/gait_path/pointer
    // Subaccounts:
    //     m/3/gait_path/subaccount/pointer
    //
    // NOTE: This class cannot be used for v0 addresses, which must be handled
    // separately.
    //
    class green_pubkeys final : public xpub_hdkeys {
    public:
        green_pubkeys(const network_parameters& net_params, uint32_span_t gait_path);

        green_pubkeys(const green_pubkeys&) = default;
        green_pubkeys& operator=(const green_pubkeys&) = default;
        green_pubkeys(green_pubkeys&&) = default;
        green_pubkeys& operator=(green_pubkeys&&) = default;
        ~green_pubkeys() override = default;

        // Return the path that must be used to deriving the gait_path xpub
        static std::array<uint32_t, 1> get_gait_generation_path();

        // Return a gait path for registration. xpub must be the users m/0x4741' path.
        static std::array<unsigned char, HMAC_SHA512_LEN> get_gait_path_bytes(const xpub_t& xpub);

        // Get the path to the subaccount parent, i.e. m/1/gait_path or m/3/gait_path/subaccount
        virtual std::vector<uint32_t> get_subaccount_root_path(uint32_t subaccount) const override;

        // Get the full path to a key in a subaccount
        virtual std::vector<uint32_t> get_subaccount_full_path(
            uint32_t subaccount, uint32_t pointer, bool is_internal) const override;

        xpub_hdkey get_subaccount(uint32_t subaccount) override;

    private:
        std::array<uint32_t, 32> m_gait_path;
    };

    //
    // Base class for a users pubkeys.
    //
    // Adds the ability to register (privately derived) subaccount xpubs,
    // and so derive user pubkeys from registered subaccounts.
    //
    class user_pubkeys : public xpub_hdkeys {
    public:
        using xpub_hdkeys::xpub_hdkeys;

        virtual bool have_subaccount(uint32_t subaccount) = 0;

        virtual void add_subaccount(uint32_t subaccount, const xpub_t& xpub) = 0;
        virtual void remove_subaccount(uint32_t subaccount) = 0;
    };

    //
    // Derives Green user public keys for the given network:
    // Main account:
    //     m/1/pointer
    // Subaccounts:
    //     m/3'/subaccount'/1/pointer
    // Because subaccount keys are privately derived, you must call add_subaccount
    // passing the xpub of the m/3'/subaccount' key before calling derive()
    // on a subaccount.
    //
    class green_user_pubkeys final : public user_pubkeys {
    public:
        explicit green_user_pubkeys(const network_parameters& net_params);
        green_user_pubkeys(const network_parameters& net_params, const xpub_t& xpub);

        green_user_pubkeys(const green_user_pubkeys&) = default;
        green_user_pubkeys& operator=(const green_user_pubkeys&) = default;
        green_user_pubkeys(green_user_pubkeys&&) = default;
        green_user_pubkeys& operator=(green_user_pubkeys&&) = default;
        ~green_user_pubkeys() override = default;

        // Note: The static implementations below are used for old-style
        // Green watch only logins (i.e. those without a client blob).
        // For those sessions, the users subaccount xpubs aren't available.

        // Get the path to the subaccount parent, i.e. m or m/3'/subaccount'
        static std::vector<uint32_t> get_green_subaccount_root_path(uint32_t subaccount);
        // Get the full path to a key in a subaccount
        static std::vector<uint32_t> get_green_subaccount_full_path(
            uint32_t subaccount, uint32_t pointer, bool is_internal);

        // Get the path to the subaccount parent, i.e. m or m/3'/subaccount'
        virtual std::vector<uint32_t> get_subaccount_root_path(uint32_t subaccount) const override;

        // Get the full path to a key in a subaccount
        virtual std::vector<uint32_t> get_subaccount_full_path(
            uint32_t subaccount, uint32_t pointer, bool is_internal) const override;

        virtual bool have_subaccount(uint32_t subaccount) override;

        virtual void add_subaccount(uint32_t subaccount, const xpub_t& xpub) override;
        virtual void remove_subaccount(uint32_t subaccount) override;

        virtual xpub_hdkey get_subaccount(uint32_t subaccount) override;
    };

    //
    // User recovery keys for the given network:
    // Subaccounts:
    //     m/1/pointer
    // Recovery keys are not privately derived because the server must derive
    // keys for address generation, and it only ever has the xpub
    // representing "m". Where a recovery mnemonic is generated on the client
    // side, it encodes "m" directly.
    //

    //
    // Derives BIP44/BIP49/BIP84 public keys for the given network:
    // Subaccounts:
    //     m/[44|49|84]'/[0|1|1776]'/mapped subaccount'/is_internal/pointer
    // 0 = Mainnet, 1 = Testnet/Liquid testnet, 1776 = Liquid mainnet.
    // Green subaccount numbers are mapped to BIP44 accounts as follows:
    // purpose: subaccount % 16 -> 0=49, 1=84, 2=44.
    // mapped subaccount: subaccount / 16.
    // Because subaccount keys are privately derived, you must call
    // add_subaccount passing the xpub up to mapped subaccount' before calling
    // derive() on a subaccount.
    //
    class bip44_pubkeys final : public user_pubkeys {
    public:
        explicit bip44_pubkeys(const network_parameters& net_params);

        bip44_pubkeys(const bip44_pubkeys&) = default;
        bip44_pubkeys& operator=(const bip44_pubkeys&) = default;
        bip44_pubkeys(bip44_pubkeys&&) = default;
        bip44_pubkeys& operator=(bip44_pubkeys&&) = default;
        ~bip44_pubkeys() override = default;

        static std::vector<uint32_t> get_bip44_subaccount_root_path(
            bool is_main_net, bool is_liquid, uint32_t subaccount);
        static std::vector<uint32_t> get_bip44_subaccount_full_path(
            bool is_main_net, bool is_liquid, uint32_t subaccount, uint32_t pointer, bool is_internal);

        // Get the path to the subaccount parent, i.e. m/[44|49|84]'/[0|1|1776]'/mapped subaccount'
        virtual std::vector<uint32_t> get_subaccount_root_path(uint32_t subaccount) const override;

        // Get the full path to a key in a subaccount
        virtual std::vector<uint32_t> get_subaccount_full_path(
            uint32_t subaccount, uint32_t pointer, bool is_internal) const override;

        virtual bool have_subaccount(uint32_t subaccount) override;

        virtual void add_subaccount(uint32_t subaccount, const xpub_t& xpub) override;
        virtual void remove_subaccount(uint32_t subaccount) override;

        virtual xpub_hdkey get_subaccount(uint32_t subaccount) override;
    };

} // namespace green

#endif
