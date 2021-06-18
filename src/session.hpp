#ifndef GDK_SESSION_HPP
#define GDK_SESSION_HPP
#pragma once

#include <memory>
#include <nlohmann/json.hpp>

#include "include/gdk.h"

#include "amount.hpp"
#include "boost_wrapper.hpp"
#include "ga_wally.hpp"

namespace ga {
namespace sdk {
    class network_parameters;
    class session_impl;

    int init(const nlohmann::json& config);
    const nlohmann::json& gdk_config();

    class session {
    public:
        session();
        ~session();

        session(const session&) = delete;
        session(session&&) = delete;

        session& operator=(const session&) = delete;
        session& operator=(session&&) = delete;

        void connect(const nlohmann::json& net_params);
        void disconnect();
        void reconnect_hint(const nlohmann::json& hint);
        std::string get_tor_socks5();

        nlohmann::json http_request(const nlohmann::json& params);
        nlohmann::json refresh_assets(const nlohmann::json& params);
        nlohmann::json validate_asset_domain_name(const nlohmann::json& params);

        void register_user(const std::string& mnemonic, bool supports_csv);
        void register_user(const std::string& master_pub_key_hex, const std::string& master_chain_code_hex,
            const std::string& gait_path_hex, bool supports_csv);

        std::string get_challenge(const std::string& address);
        nlohmann::json authenticate(const std::string& sig_der_hex, const std::string& path_hex,
            const std::string& root_xpub_bip32, const std::string& device_id, const nlohmann::json& hw_device);
        void register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs);
        nlohmann::json login(const std::string& mnemonic, const std::string& password);
        nlohmann::json login_with_pin(const std::string& pin, const nlohmann::json& pin_data);
        nlohmann::json login_watch_only(const std::string& username, const std::string& password);
        bool set_watch_only(const std::string& username, const std::string& password);
        std::string get_watch_only_username();
        bool remove_account(const nlohmann::json& twofactor_data);

        uint32_t get_next_subaccount(const std::string& type);
        nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount);
        nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount, const std::string& xpub);
        std::vector<uint32_t> get_subaccount_root_path(uint32_t subaccount);
        std::vector<uint32_t> get_subaccount_full_path(uint32_t subaccount, uint32_t pointer);

        void change_settings_limits(const nlohmann::json& limit_details, const nlohmann::json& twofactor_data);

        nlohmann::json get_transactions(const nlohmann::json& details);

        void set_notification_handler(GA_notification_handler handler, void* context);

        nlohmann::json get_receive_address(const nlohmann::json& details);
        nlohmann::json get_previous_addresses(uint32_t subaccount, uint32_t last_pointer);
        void set_local_encryption_keys(const pub_key_t& public_key, bool is_hw_wallet);

        nlohmann::json get_subaccounts();

        nlohmann::json get_subaccount(uint32_t subaccount);

        void rename_subaccount(uint32_t subaccount, const std::string& new_name);
        void set_subaccount_hidden(uint32_t subaccount, bool is_hidden);

        nlohmann::json get_balance(const nlohmann::json& details);

        nlohmann::json get_available_currencies();

        bool is_rbf_enabled();
        bool is_watch_only();
        bool is_liquid();
        nlohmann::json get_settings();
        nlohmann::json get_post_login_data();
        void change_settings(const nlohmann::json& settings);

        nlohmann::json get_twofactor_config(bool reset_cached = false);
        std::vector<std::string> get_all_twofactor_methods();
        std::vector<std::string> get_enabled_twofactor_methods();

        void set_email(const std::string& email, const nlohmann::json& twofactor_data);
        void activate_email(const std::string& code);
        nlohmann::json init_enable_twofactor(
            const std::string& method, const std::string& data, const nlohmann::json& twofactor_data);
        void enable_gauth(const std::string& code, const nlohmann::json& twofactor_data);
        void enable_twofactor(const std::string& method, const std::string& code);
        void disable_twofactor(const std::string& method, const nlohmann::json& twofactor_data);
        nlohmann::json auth_handler_request_code(
            const std::string& method, const std::string& action, const nlohmann::json& twofactor_data);
        std::string auth_handler_request_proxy_code(const std::string& action, const nlohmann::json& twofactor_data);

        nlohmann::json request_twofactor_reset(const std::string& email);
        nlohmann::json confirm_twofactor_reset(
            const std::string& email, bool is_dispute, const nlohmann::json& twofactor_data);

        nlohmann::json request_undo_twofactor_reset(const std::string& email);
        nlohmann::json confirm_undo_twofactor_reset(const std::string& email, const nlohmann::json& twofactor_data);

        nlohmann::json cancel_twofactor_reset(const nlohmann::json& twofactor_data);

        nlohmann::json set_pin(const std::string& mnemonic, const std::string& pin, const std::string& device_id);
        void disable_all_pin_logins();

        nlohmann::json get_blinded_scripts(const nlohmann::json& details);
        nlohmann::json get_unspent_outputs(const nlohmann::json& details);
        nlohmann::json get_unspent_outputs_for_private_key(
            const std::string& private_key, const std::string& password, uint32_t unused);
        nlohmann::json set_unspent_outputs_status(const nlohmann::json& details, const nlohmann::json& twofactor_data);
        nlohmann::json get_transaction_details(const std::string& txhash_hex);

        bool has_blinding_nonce(const std::string& pubkey, const std::string& script);
        void set_blinding_nonce(const std::string& pubkey, const std::string& script, const std::string& nonce);

        nlohmann::json create_transaction(const nlohmann::json& details);
        nlohmann::json sign_transaction(const nlohmann::json& details);
        nlohmann::json send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data);
        std::string broadcast_transaction(const std::string& tx_hex);

        void send_nlocktimes();
        nlohmann::json get_expired_deposits(const nlohmann::json& deposit_details);
        void set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data);
        void set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data);

        void set_transaction_memo(const std::string& txhash_hex, const std::string& memo);

        void upload_confidential_addresses(uint32_t subaccount, const std::vector<std::string>& confidential_addresses);

        nlohmann::json get_fee_estimates();

        std::string get_mnemonic_passphrase(const std::string& password);

        std::string get_system_message();
        std::pair<std::string, std::vector<uint32_t>> get_system_message_info(const std::string& system_message);
        void ack_system_message(const std::string& system_message);
        void ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex);

        nlohmann::json convert_amount(const nlohmann::json& amount_json);

        amount get_min_fee_rate() const;
        amount get_default_fee_rate() const;
        uint32_t get_block_height() const;
        amount get_dust_threshold() const;
        nlohmann::json get_spending_limits() const;
        bool is_spending_limits_decrease(const nlohmann::json& limit_details);

        const network_parameters& get_network_parameters() const;

        auto get_nonnull_impl()
        {
            auto p = m_impl.load();
            GDK_RUNTIME_ASSERT(p != nullptr);
            return p;
        }

        auto get_nonnull_impl() const
        {
            auto p = m_impl.load();
            GDK_RUNTIME_ASSERT(p != nullptr);
            return p;
        }

    private:
        template <typename F, typename... Args> auto exception_wrapper(F&& f, Args&&... args);

        void reconnect();

        auto get_impl() { return m_impl.load(); }
        auto get_impl() const { return m_impl.load(); }

        using session_ptr = boost::shared_ptr<session_impl>;
        using session_atomic_ptr = boost::atomic_shared_ptr<session_impl>;

        session_atomic_ptr m_impl;

        GA_notification_handler m_notification_handler{ nullptr };
        void* m_notification_context{ nullptr };
    };
} // namespace sdk
} // namespace ga

#endif
