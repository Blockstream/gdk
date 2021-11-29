#pragma once

#include "session_impl.hpp"

namespace ga {
namespace sdk {
    struct tor_controller;

    class ga_rust final : public session_impl {
    public:
        explicit ga_rust(network_parameters&& net_params);
        ~ga_rust();

        bool is_connected() const;
        void set_ping_fail_handler(ping_fail_t handler);
        void set_heartbeat_timeout_handler(websocketpp::pong_timeout_handler);
        bool reconnect();
        void try_reconnect();
        void reconnect_hint(bool, bool);

        // TODO: remove me when tor MR extract lands
        void tor_sleep_hint(const std::string& hint);
        std::string get_tor_socks5();

        void connect();
        void disconnect();

        nlohmann::json http_request(nlohmann::json params);
        nlohmann::json refresh_assets(const nlohmann::json& params);
        nlohmann::json validate_asset_domain_name(const nlohmann::json& params);

        std::string get_challenge(const pub_key_t& public_key);
        nlohmann::json authenticate(const std::string& sig_der_hex, const std::string& path_hex,
            const std::string& root_bip32_xpub, std::shared_ptr<signer> signer);
        void register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs);
        nlohmann::json login(std::shared_ptr<signer> signer);
        std::string mnemonic_from_pin_data(const nlohmann::json& pin_data);
        nlohmann::json login_watch_only(std::shared_ptr<signer> signer);
        bool set_watch_only(const std::string& username, const std::string& password);
        std::string get_watch_only_username();
        bool remove_account(const nlohmann::json& twofactor_data);

        uint32_t get_next_subaccount(const std::string& type);
        nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount, const std::string& xpub);

        void change_settings_limits(const nlohmann::json& limit_details, const nlohmann::json& twofactor_data);
        nlohmann::json get_transactions(const nlohmann::json& details);

        nlohmann::json get_receive_address(const nlohmann::json& details);
        nlohmann::json get_previous_addresses(uint32_t subaccount, uint32_t last_pointer);
        nlohmann::json get_subaccounts();
        nlohmann::json get_subaccount(uint32_t subaccount);
        void rename_subaccount(uint32_t subaccount, const std::string& new_name);
        void set_subaccount_hidden(uint32_t subaccount, bool is_hidden);
        std::vector<uint32_t> get_subaccount_root_path(uint32_t subaccount);
        std::vector<uint32_t> get_subaccount_full_path(uint32_t subaccount, uint32_t pointer);

        nlohmann::json get_available_currencies() const;

        bool is_rbf_enabled() const;
        bool is_watch_only() const;
        nlohmann::json get_settings();
        nlohmann::json get_post_login_data();
        void change_settings(const nlohmann::json& settings);

        nlohmann::json get_twofactor_config(bool reset_cached = false);
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

        nlohmann::json get_unspent_outputs(const nlohmann::json& details, unique_pubkeys_and_scripts_t& missing);
        nlohmann::json get_unspent_outputs_for_private_key(
            const std::string& private_key, const std::string& password, uint32_t unused);
        nlohmann::json set_unspent_outputs_status(const nlohmann::json& details, const nlohmann::json& twofactor_data);
        wally_tx_ptr get_raw_transaction_details(const std::string& txhash_hex) const;

        nlohmann::json create_transaction(const nlohmann::json& details);
        nlohmann::json sign_transaction(const nlohmann::json& details);
        nlohmann::json psbt_sign(const nlohmann::json& details);
        nlohmann::json send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data);
        std::string broadcast_transaction(const std::string& tx_hex);

        void send_nlocktimes();
        void set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data);
        void set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data);

        void set_transaction_memo(const std::string& txhash_hex, const std::string& memo);

        nlohmann::json get_fee_estimates();

        std::string get_system_message();
        std::pair<std::string, std::vector<uint32_t>> get_system_message_info(const std::string& system_message);
        void ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex);

        nlohmann::json convert_amount(const nlohmann::json& amount_json) const;

        void upload_confidential_addresses(uint32_t subaccount, const std::vector<std::string>& confidential_addresses);

        amount get_min_fee_rate() const;
        amount get_default_fee_rate() const;
        uint32_t get_block_height() const;
        amount get_dust_threshold() const;
        nlohmann::json get_spending_limits() const;
        bool is_spending_limits_decrease(const nlohmann::json& limit_details);

        ga_pubkeys& get_ga_pubkeys();
        user_pubkeys& get_user_pubkeys();
        ga_user_pubkeys& get_recovery_pubkeys();

        void disable_all_pin_logins();

        static int32_t spv_verify_tx(const nlohmann::json& details);

        static std::string psbt_extract_tx(const std::string& psbt_hex);
        static std::string psbt_merge_tx(const std::string& psbt_hex, const std::string& tx_hex);

    private:
        nlohmann::json call_session(const std::string& method, const nlohmann::json& input) const;

        static void GDKRUST_notif_handler(void* self_context, char* json);
        void set_notification_handler(GA_notification_handler handler, void* context);

        std::shared_ptr<tor_controller> m_tor_ctrl;
        bool m_reconnect_restart;

        void* m_session;
    };

} // namespace sdk
} // namespace ga
