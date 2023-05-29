#ifndef GDK_XPUB_HDKEY_HPP
#define GDK_XPUB_HDKEY_HPP
#pragma once

#include <map>

#include "ga_wally.hpp"
#include "network_parameters.hpp"

namespace ga {
namespace sdk {

    //
    // Derives public keys from an xpub
    //
    class xpub_hdkey final {
    public:
        xpub_hdkey(bool is_main_net, const xpub_t& xpub, uint32_span_t path);
        xpub_hdkey(bool is_main_net, const xpub_t& xpub);

        xpub_hdkey(const xpub_hdkey&) = default;
        xpub_hdkey& operator=(const xpub_hdkey&) = default;
        xpub_hdkey(xpub_hdkey&&) = default;
        xpub_hdkey& operator=(xpub_hdkey&&) = default;
        ~xpub_hdkey();

        pub_key_t derive(uint32_span_t path);

        xpub_t to_xpub_t() const;
        std::string to_base58() const;
        std::string to_hashed_identifier(const std::string& network) const;

    private:
        ext_key m_ext_key;
    };

    namespace detail {

        //
        // Base class for collections of xpubs
        //
        class xpub_hdkeys_base {
        public:
            explicit xpub_hdkeys_base(const network_parameters& net_params);
            xpub_hdkeys_base(const network_parameters& net_params, const xpub_t& xpub);

            xpub_hdkeys_base(const xpub_hdkeys_base&) = default;
            xpub_hdkeys_base& operator=(const xpub_hdkeys_base&) = default;
            xpub_hdkeys_base(xpub_hdkeys_base&&) = default;
            xpub_hdkeys_base& operator=(xpub_hdkeys_base&&) = default;
            virtual ~xpub_hdkeys_base() = default;

            // Derive a Green pubkey for a subaccount and pointer
            pub_key_t derive(uint32_t subaccount, uint32_t pointer);
            // Derive a BIP44 pubkey for a subaccount and pointer, internal or not
            pub_key_t derive(uint32_t subaccount, uint32_t pointer, bool is_internal);

            virtual xpub_hdkey get_subaccount(uint32_t subaccount) = 0;

        protected:
            bool m_is_main_net;
            bool m_is_liquid;
            xpub_t m_xpub;
            std::map<uint32_t, xpub_hdkey> m_subaccounts;
        };
    } // namespace detail

    //
    // Derives GA public keys for the given network:
    // Main account
    //     m/1/gait_path/pointer
    // Subaccounts:
    //     m/3/gait_path/subaccount/pointer
    //
    class ga_pubkeys final : public detail::xpub_hdkeys_base {
    public:
        ga_pubkeys(const network_parameters& net_params, uint32_span_t gait_path);

        ga_pubkeys(const ga_pubkeys&) = default;
        ga_pubkeys& operator=(const ga_pubkeys&) = default;
        ga_pubkeys(ga_pubkeys&&) = default;
        ga_pubkeys& operator=(ga_pubkeys&&) = default;
        ~ga_pubkeys() override = default;

        // Return the path that must be used to deriving the gait_path xpub
        static std::array<uint32_t, 1> get_gait_generation_path();

        // Return a gait path for registration. xpub must be the users m/0x4741' path.
        static std::array<unsigned char, HMAC_SHA512_LEN> get_gait_path_bytes(const xpub_t& xpub);

        xpub_hdkey get_subaccount(uint32_t subaccount) override;

    private:
        std::array<uint32_t, 32> m_gait_path;
    };

    //
    // Base class for a users pubkeys
    //
    class user_pubkeys : public detail::xpub_hdkeys_base {
    public:
        using detail::xpub_hdkeys_base::xpub_hdkeys_base;

        // Get the path to a subaccount parent
        virtual std::vector<uint32_t> get_subaccount_root_path(uint32_t subaccount) const = 0;

        // Get the full path to a key in a subaccount
        virtual std::vector<uint32_t> get_subaccount_full_path(
            uint32_t subaccount, uint32_t pointer, bool is_internal) const = 0;

        virtual bool have_subaccount(uint32_t subaccount) = 0;

        virtual void add_subaccount(uint32_t subaccount, const xpub_t& xpub) = 0;
        virtual void remove_subaccount(uint32_t subaccount) = 0;

        virtual xpub_hdkey get_subaccount(uint32_t subaccount) override = 0;
    };

    //
    // Derives GA user public keys for the given network:
    // Main account:
    //     m/1/pointer
    // Subaccounts:
    //     m/3'/subaccount'/1/pointer
    // Because subaccount keys are privately derived, you must call add_subaccount
    // passing the xpub of the m/3'/subaccount' key before calling derive()
    // on a subaccount.
    //
    class ga_user_pubkeys final : public user_pubkeys {
    public:
        explicit ga_user_pubkeys(const network_parameters& net_params);
        ga_user_pubkeys(const network_parameters& net_params, const xpub_t& xpub);

        ga_user_pubkeys(const ga_user_pubkeys&) = default;
        ga_user_pubkeys& operator=(const ga_user_pubkeys&) = default;
        ga_user_pubkeys(ga_user_pubkeys&&) = default;
        ga_user_pubkeys& operator=(ga_user_pubkeys&&) = default;
        ~ga_user_pubkeys() override = default;

        // Note: The 2 static implementations below are used for GA watch only
        // logins where the users xpubs aren't (yet) available.

        // Get the path to the subaccount parent, i.e. m or m/3'/subaccount'
        static std::vector<uint32_t> get_ga_subaccount_root_path(uint32_t subaccount);
        // Get the full path to a key in a subaccount
        static std::vector<uint32_t> get_ga_subaccount_full_path(
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

} // namespace sdk
} // namespace ga

#endif
