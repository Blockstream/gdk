#ifndef GDK_SESSION_HPP
#define GDK_SESSION_HPP
#pragma once

#include <memory>
#include <nlohmann/json.hpp>

#include "include/gdk.h"

#include "amount.hpp"
#include "ga_wally.hpp"
#include "network_parameters.hpp"

namespace ga {
namespace sdk {
    class ga_session;
    class signer;
    class ga_pubkeys;
    class ga_user_pubkeys;

    class session {
    public:
        session();
        ~session();

        session(const session&) = delete;
        session(session&&) = delete;

        session& operator=(const session&) = delete;
        session& operator=(session&&) = delete;

        void connect(const std::string& name, const std::string& proxy = std::string(), bool use_tor = false,
            bool debug = false);
        void disconnect();

        void register_user(const std::string& mnemonic, bool supports_csv);
        void register_user(const std::string& master_pub_key_hex, const std::string& master_chain_code_hex,
            const std::string& gait_path_hex, bool supports_csv);

        std::string get_challenge(const std::string& address);
        void authenticate(const std::string& sig_der_hex, const std::string& path_hex, const std::string& device_id,
            const nlohmann::json& hw_device);
        void register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs);
        void login(const std::string& mnemonic, const std::string& password);
        void login_with_pin(const std::string& pin, const nlohmann::json& pin_data);
        void login_watch_only(const std::string& username, const std::string& password);
        bool set_watch_only(const std::string& username, const std::string& password);
        bool remove_account(const nlohmann::json& twofactor_data);

        uint32_t get_next_subaccount();
        nlohmann::json create_subaccount(const nlohmann::json& details);
        nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount, const xpub_t& xpub);

        void change_settings_limits(const nlohmann::json& limit_details, const nlohmann::json& twofactor_data);

        nlohmann::json get_transactions(uint32_t subaccount, uint32_t page_id);

        void set_notification_handler(GA_notification_handler handler, void* context);

        nlohmann::json get_receive_address(uint32_t subaccount, const std::string& addr_type = std::string());

        nlohmann::json get_subaccounts();

        nlohmann::json get_balance(uint32_t subaccount, uint32_t num_confs);

        nlohmann::json get_available_currencies();

        nlohmann::json get_hw_device();

        bool is_rbf_enabled();
        bool is_watch_only();
        uint32_t get_current_subaccount();
        void set_current_subaccount(uint32_t subaccount);
        nlohmann::json get_settings();
        void change_settings(const nlohmann::json& settings);

        nlohmann::json get_twofactor_config(bool reset_cached = false);
        std::vector<std::string> get_all_twofactor_methods();
        std::vector<std::string> get_enabled_twofactor_methods();

        void set_email(const std::string& email, const nlohmann::json& twofactor_data);
        void activate_email(const std::string& code);
        void init_enable_twofactor(
            const std::string& method, const std::string& data, const nlohmann::json& twofactor_data);
        void enable_gauth(const std::string& code, const nlohmann::json& twofactor_data);
        void enable_twofactor(const std::string& method, const std::string& code);
        void disable_twofactor(const std::string& method, const nlohmann::json& twofactor_data);
        void auth_handler_request_code(
            const std::string& method, const std::string& action, const nlohmann::json& twofactor_data);
        nlohmann::json reset_twofactor(const std::string& email);
        nlohmann::json confirm_twofactor_reset(
            const std::string& email, bool is_dispute, const nlohmann::json& twofactor_data);
        nlohmann::json cancel_twofactor_reset(const nlohmann::json& twofactor_data);

        nlohmann::json set_pin(const std::string& mnemonic, const std::string& pin, const std::string& device_id);

        nlohmann::json get_unspent_outputs(uint32_t subaccount, uint32_t num_confs);
        nlohmann::json get_unspent_outputs_for_private_key(
            const std::string& private_key, const std::string& password, uint32_t unused);
        nlohmann::json get_transaction_details(const std::string& txhash_hex);

        nlohmann::json create_transaction(const nlohmann::json& details);
        nlohmann::json sign_transaction(const nlohmann::json& details);
        nlohmann::json send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data);
        std::string broadcast_transaction(const std::string& tx_hex);

        void send_nlocktimes();

        void set_transaction_memo(const std::string& txhash_hex, const std::string& memo, const std::string& memo_type);

        nlohmann::json get_fee_estimates();

        std::string get_mnemonic_passphrase(const std::string& password);

        std::string get_system_message();
        std::pair<std::string, std::vector<uint32_t>> get_system_message_info(const std::string& system_message);
        void ack_system_message(const std::string& system_message);
        void ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex);

        nlohmann::json convert_amount(const nlohmann::json& amount_json);
        nlohmann::json convert_amount_nocatch(const nlohmann::json& amount_json);
        nlohmann::json encrypt(const nlohmann::json& input_json);
        nlohmann::json decrypt(const nlohmann::json& input_json);

        amount get_min_fee_rate() const;
        amount get_default_fee_rate() const;
        bool have_subaccounts() const;
        uint32_t get_block_height() const;
        amount get_dust_threshold() const;
        nlohmann::json get_spending_limits() const;
        bool is_spending_limits_decrease(const nlohmann::json& limit_details);

        const network_parameters& get_network_parameters() const;
        signer& get_signer();
        ga_pubkeys& get_ga_pubkeys();
        ga_user_pubkeys& get_user_pubkeys();
        ga_user_pubkeys& get_recovery_pubkeys();

    private:
        template <typename F, typename... Args> auto exception_wrapper(F&& f, Args&&... args);

        GA_notification_handler m_notification_handler;
        void* m_notification_context;

        std::unique_ptr<ga_session> m_impl;
    };
} // namespace sdk
} // namespace ga

#endif
