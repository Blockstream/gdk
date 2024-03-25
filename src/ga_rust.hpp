#pragma once

#include "session_impl.hpp"

namespace ga {
namespace sdk {
    class ga_rust final : public session_impl {
    public:
        explicit ga_rust(network_parameters&& net_params);
        ~ga_rust();

        void reconnect();
        void reconnect_hint(const nlohmann::json& hint);

        void connect();
        void disconnect();

        std::string get_challenge(const pub_key_t& public_key);
        nlohmann::json authenticate(const std::string& sig_der_hex, std::shared_ptr<signer> signer);
        void register_subaccount_xpubs(
            const std::vector<uint32_t>& pointers, const std::vector<std::string>& bip32_xpubs);
        nlohmann::json credentials_from_pin_data(const nlohmann::json& pin_data);
        nlohmann::json login_wo(std::shared_ptr<signer> signer);
        bool set_wo_credentials(const std::string& username, const std::string& password);
        std::string get_wo_username();
        bool remove_account(const nlohmann::json& twofactor_data);

        bool discover_subaccount(const std::string& xpub, const std::string& type);
        uint32_t get_next_subaccount(const std::string& type);
        uint32_t get_last_empty_subaccount(const std::string& type);
        nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount, const std::string& xpub);

        // Get the master blinding key from the rust cache if available.
        // If the master blinding key is missing,
        // The caller should obtain it from the signer and set it with
        // set_cached_master_blinding_key
        std::pair<std::string, bool> get_cached_master_blinding_key();

        // Set the master blinding key in the rust cache.
        // If the cache has already a master blinding key,
        // attempting to set a different key results in an error.
        void set_cached_master_blinding_key(const std::string& master_blinding_key_hex);

        // Start the rust sync threads.
        // This must be done once the store is loaded
        // and for liquid after the master blinding key is set.
        void start_sync_threads();

        // Get the subaccount pointers for the subaccount that belongs to the wallet.
        // For each of these subaccounts, the caller should set the xpub with
        // create_subaccount if the xpub missing from the store.
        std::vector<uint32_t> get_subaccount_pointers();

        void change_settings_limits(const nlohmann::json& limit_details, const nlohmann::json& twofactor_data);
        nlohmann::json get_transactions(const nlohmann::json& details);

        nlohmann::json get_receive_address(const nlohmann::json& details);
        nlohmann::json get_previous_addresses(const nlohmann::json& details);
        nlohmann::json get_subaccounts();
        void rename_subaccount(uint32_t subaccount, const std::string& new_name);
        void set_subaccount_hidden(uint32_t subaccount, bool is_hidden);
        std::vector<uint32_t> get_subaccount_root_path(uint32_t subaccount);
        std::vector<uint32_t> get_subaccount_full_path(uint32_t subaccount, uint32_t pointer, bool is_internal);

        nlohmann::json get_available_currencies() const;

        bool is_rbf_enabled() const;
        nlohmann::json get_settings() const;
        void change_settings(const nlohmann::json& settings);

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

        nlohmann::json encrypt_with_pin(const nlohmann::json& details);
        nlohmann::json decrypt_with_pin(const nlohmann::json& details);

        nlohmann::json get_unspent_outputs(const nlohmann::json& details, unique_pubkeys_and_scripts_t& missing);
        nlohmann::json set_unspent_outputs_status(const nlohmann::json& details, const nlohmann::json& twofactor_data);
        Tx get_raw_transaction_details(const std::string& txhash_hex) const;

        nlohmann::json get_scriptpubkey_data(byte_span_t scriptpubkey);
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
        bool is_spending_limits_decrease(const nlohmann::json& limit_details);
        void set_local_encryption_keys(const pub_key_t& public_key, std::shared_ptr<signer> signer);

        ga_pubkeys& get_ga_pubkeys();
        user_pubkeys& get_recovery_pubkeys();

        void disable_all_pin_logins();

        nlohmann::json get_address_data(const nlohmann::json& details);

    private:
        static void GDKRUST_notif_handler(void* self_context, char* json);
        void set_notification_handler(GA_notification_handler handler, void* context);

        void* m_session;
    };

} // namespace sdk
} // namespace ga
