#ifndef GDK_SESSION_IMPL_HPP
#define GDK_SESSION_IMPL_HPP

#pragma once

#include "amount.hpp"
#include "autobahn_wrapper.hpp"
#include "network_parameters.hpp"
#include "signer.hpp"

namespace ga {
namespace sdk {
    using ping_fail_t = std::function<void()>;

    class ga_pubkeys;
    class ga_user_pubkeys;
    class user_pubkeys;

    class session_impl {
    public:
        explicit session_impl(const nlohmann::json& net_params, nlohmann::json& defaults);
        session_impl(const session_impl& other) = delete;
        session_impl(session_impl&& other) noexcept = delete;
        session_impl& operator=(const session_impl& other) = delete;
        session_impl& operator=(session_impl&& other) noexcept = delete;

        virtual ~session_impl();

        // Factory method
        static boost::shared_ptr<session_impl> create(const nlohmann::json& net_params);

        virtual void on_failed_login() = 0;
        virtual bool is_connected() const = 0;
        virtual void set_ping_fail_handler(ping_fail_t handler) = 0;
        virtual void set_heartbeat_timeout_handler(websocketpp::pong_timeout_handler) = 0;
        virtual void emit_notification(std::string event, nlohmann::json details) = 0;
        virtual bool reconnect() = 0;
        virtual void reconnect_hint(bool enable, bool restart) = 0;
        virtual void try_reconnect() = 0;

        // TODO: remove me when tor MR extract lands
        virtual void tor_sleep_hint(const std::string& hint) = 0;
        virtual std::string get_tor_socks5() = 0;

        virtual void connect() = 0;
        virtual void disconnect() = 0;

        virtual nlohmann::json http_request(nlohmann::json params) = 0;
        virtual nlohmann::json refresh_assets(const nlohmann::json& params) = 0;
        virtual nlohmann::json validate_asset_domain_name(const nlohmann::json& params) = 0;

        virtual void register_user(const std::string& mnemonic, bool supports_csv) = 0;
        virtual void register_user(const std::string& master_pub_key_hex, const std::string& master_chain_code_hex,
            const std::string& gait_path_hex, bool supports_csv)
            = 0;

        virtual std::string get_challenge(const std::string& address) = 0;
        virtual nlohmann::json authenticate(const std::string& sig_der_hex, const std::string& path_hex,
            const std::string& root_xpub_bip32, const std::string& device_id, const nlohmann::json& hw_device)
            = 0;
        virtual void register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs) = 0;
        virtual nlohmann::json login(const std::string& mnemonic, const std::string& password) = 0;
        virtual nlohmann::json login_with_pin(const std::string& pin, const nlohmann::json& pin_data) = 0;
        virtual nlohmann::json login_watch_only(const std::string& username, const std::string& password) = 0;
        virtual bool set_watch_only(const std::string& username, const std::string& password) = 0;
        virtual std::string get_watch_only_username() = 0;
        virtual bool remove_account(const nlohmann::json& twofactor_data) = 0;

        virtual uint32_t get_next_subaccount(const std::string& type) = 0;
        virtual nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount) = 0;
        virtual nlohmann::json create_subaccount(
            const nlohmann::json& details, uint32_t subaccount, const std::string& xpub)
            = 0;

        virtual void change_settings_limits(const nlohmann::json& limit_details, const nlohmann::json& twofactor_data)
            = 0;
        virtual nlohmann::json get_transactions(const nlohmann::json& details) = 0;

        virtual void set_notification_handler(GA_notification_handler handler, void* context) = 0;

        virtual nlohmann::json get_receive_address(const nlohmann::json& details) = 0;
        virtual nlohmann::json get_previous_addresses(uint32_t subaccount, uint32_t last_pointer) = 0;
        virtual nlohmann::json get_subaccounts() = 0;
        virtual nlohmann::json get_subaccount(uint32_t subaccount) = 0;
        virtual void rename_subaccount(uint32_t subaccount, const std::string& new_name) = 0;
        virtual void set_subaccount_hidden(uint32_t subaccount, bool is_hidden) = 0;
        virtual std::vector<uint32_t> get_subaccount_root_path(uint32_t subaccount) = 0;
        virtual std::vector<uint32_t> get_subaccount_full_path(uint32_t subaccount, uint32_t pointer) = 0;

        virtual nlohmann::json get_balance(const nlohmann::json& details) = 0;
        virtual nlohmann::json get_available_currencies() const = 0;

        virtual bool is_rbf_enabled() const = 0;
        virtual bool is_watch_only() const = 0;
        virtual nlohmann::json get_settings() = 0;
        virtual nlohmann::json get_post_login_data() = 0;
        virtual void change_settings(const nlohmann::json& settings) = 0;

        virtual nlohmann::json get_twofactor_config(bool reset_cached = false) = 0;
        virtual std::vector<std::string> get_all_twofactor_methods() = 0;
        virtual std::vector<std::string> get_enabled_twofactor_methods() = 0;

        virtual void set_email(const std::string& email, const nlohmann::json& twofactor_data) = 0;
        virtual void activate_email(const std::string& code) = 0;
        virtual nlohmann::json init_enable_twofactor(
            const std::string& method, const std::string& data, const nlohmann::json& twofactor_data)
            = 0;
        virtual void enable_gauth(const std::string& code, const nlohmann::json& twofactor_data) = 0;
        virtual void enable_twofactor(const std::string& method, const std::string& code) = 0;
        virtual void disable_twofactor(const std::string& method, const nlohmann::json& twofactor_data) = 0;
        virtual nlohmann::json auth_handler_request_code(
            const std::string& method, const std::string& action, const nlohmann::json& twofactor_data)
            = 0;
        virtual std::string auth_handler_request_proxy_code(
            const std::string& action, const nlohmann::json& twofactor_data)
            = 0;
        virtual nlohmann::json request_twofactor_reset(const std::string& email) = 0;
        virtual nlohmann::json confirm_twofactor_reset(
            const std::string& email, bool is_dispute, const nlohmann::json& twofactor_data)
            = 0;

        virtual nlohmann::json request_undo_twofactor_reset(const std::string& email) = 0;
        virtual nlohmann::json confirm_undo_twofactor_reset(
            const std::string& email, const nlohmann::json& twofactor_data)
            = 0;

        virtual nlohmann::json cancel_twofactor_reset(const nlohmann::json& twofactor_data) = 0;

        virtual nlohmann::json set_pin(
            const std::string& mnemonic, const std::string& pin, const std::string& device_id)
            = 0;

        virtual void set_blinding_nonce(const std::string& pubkey, const std::string& script, const std::string& nonce)
            = 0;
        virtual bool has_blinding_nonce(const std::string& pubkey, const std::string& script) = 0;
        virtual nlohmann::json get_blinded_scripts(const nlohmann::json& details) = 0;
        virtual void upload_confidential_addresses(
            uint32_t subaccount, const std::vector<std::string>& confidential_addresses)
            = 0;

        virtual nlohmann::json get_unspent_outputs(const nlohmann::json& details) = 0;
        virtual nlohmann::json get_unspent_outputs_for_private_key(
            const std::string& private_key, const std::string& password, uint32_t unused)
            = 0;
        virtual nlohmann::json set_unspent_outputs_status(
            const nlohmann::json& details, const nlohmann::json& twofactor_data)
            = 0;
        virtual nlohmann::json get_transaction_details(const std::string& txhash_hex) const = 0;

        virtual nlohmann::json create_transaction(const nlohmann::json& details) = 0;
        virtual nlohmann::json sign_transaction(const nlohmann::json& details) = 0;
        virtual nlohmann::json send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data)
            = 0;
        virtual std::string broadcast_transaction(const std::string& tx_hex) = 0;

        virtual void send_nlocktimes() = 0;
        virtual nlohmann::json get_expired_deposits(const nlohmann::json& deposit_details) = 0;
        virtual void set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data) = 0;
        virtual void set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data) = 0;

        virtual void set_transaction_memo(const std::string& txhash_hex, const std::string& memo) = 0;

        virtual nlohmann::json get_fee_estimates() = 0;

        virtual std::string get_mnemonic_passphrase(const std::string& password) = 0;

        virtual std::string get_system_message() = 0;
        virtual std::pair<std::string, std::vector<uint32_t>> get_system_message_info(const std::string& system_message)
            = 0;
        virtual void ack_system_message(const std::string& system_message) = 0;
        virtual void ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex) = 0;

        virtual nlohmann::json convert_amount(const nlohmann::json& amount_json) const = 0;

        virtual amount get_min_fee_rate() const = 0;
        virtual amount get_default_fee_rate() const = 0;
        virtual uint32_t get_block_height() const = 0;
        virtual amount get_dust_threshold() const = 0;
        virtual nlohmann::json get_spending_limits() const = 0;
        virtual bool is_spending_limits_decrease(const nlohmann::json& limit_details) = 0;

        virtual void set_local_encryption_keys(const pub_key_t& public_key, bool is_hw_wallet) = 0;
        virtual void disable_all_pin_logins() = 0;

        const network_parameters& get_network_parameters() const { return m_net_params; }
        virtual std::shared_ptr<signer> get_signer() = 0;
        virtual ga_pubkeys& get_ga_pubkeys() = 0;
        virtual user_pubkeys& get_user_pubkeys() = 0;
        virtual ga_user_pubkeys& get_recovery_pubkeys() = 0;

    protected:
        // Immutable upon construction
        const network_parameters m_net_params;
        const bool m_debug_logging;

        // Immutable post-login
        std::shared_ptr<signer> m_signer;
    };

} // namespace sdk
} // namespace ga

#endif // #ifndef GDK_SESSION_IMPL_HPP
