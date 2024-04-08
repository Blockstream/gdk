#ifndef GDK_GA_SESSION_HPP
#define GDK_GA_SESSION_HPP
#pragma once

#include <array>
#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "amount.hpp"
#include "client_blob.hpp"
#include "ga_wally.hpp"
#include "session_impl.hpp"

namespace ga {
namespace sdk {
    struct cache;
    class ga_user_pubkeys;
    class wamp_transport;

    class ga_session final : public session_impl {
    public:
        using nlocktime_t = std::map<std::string, nlohmann::json>; // txhash:pt_idx -> lock info

        explicit ga_session(network_parameters&& net_params);
        ~ga_session();

        void connect();
        void reconnect();
        void reconnect_hint(const nlohmann::json& hint);
        void disconnect();

        void emit_notification(nlohmann::json details, bool async);

        nlohmann::json register_user(const std::string& master_pub_key_hex, const std::string& master_chain_code_hex,
            const std::string& gait_path_hex, bool supports_csv);

        std::string get_challenge(const pub_key_t& public_key);
        nlohmann::json authenticate(const std::string& sig_der_hex, std::shared_ptr<signer> signer);

        void register_subaccount_xpubs(
            const std::vector<uint32_t>& pointers, const std::vector<std::string>& bip32_xpubs);

        nlohmann::json credentials_from_pin_data(const nlohmann::json& pin_data);
        nlohmann::json login_wo(std::shared_ptr<signer> signer);

        bool set_wo_credentials(const std::string& username, const std::string& password);
        std::string get_wo_username();
        bool remove_account(const nlohmann::json& twofactor_data);

        void change_settings_limits(const nlohmann::json& details, const nlohmann::json& twofactor_data);

        nlohmann::json get_subaccounts();
        std::vector<uint32_t> get_subaccount_pointers();
        void rename_subaccount(uint32_t subaccount, const std::string& new_name);
        void set_subaccount_hidden(uint32_t subaccount, bool is_hidden);
        uint32_t get_next_subaccount(const std::string& type);
        nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount);
        nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount, const std::string& xpub);
        nlohmann::json get_receive_address(const nlohmann::json& details);
        nlohmann::json get_previous_addresses(const nlohmann::json& details);
        void set_local_encryption_keys(const pub_key_t& public_key, std::shared_ptr<signer> signer);
        nlohmann::json get_available_currencies() const;
        bool is_rbf_enabled() const;

        nlohmann::json get_twofactor_config(bool reset_cached);
        nlohmann::json get_twofactor_config(locker_t& locker, bool reset_cached = false);
        std::vector<std::string> get_enabled_twofactor_methods();

        nlohmann::json get_settings() const;
        void change_settings(const nlohmann::json& settings);

        void set_email(const std::string& email, const nlohmann::json& twofactor_data);
        void activate_email(const std::string& code);
        nlohmann::json init_enable_twofactor(
            const std::string& method, const std::string& data, const nlohmann::json& twofactor_data);
        void enable_twofactor(const std::string& method, const std::string& code);
        void enable_gauth(const std::string& code, const nlohmann::json& twofactor_data);
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
        void disable_all_pin_logins();

        nlohmann::json get_unspent_outputs(const nlohmann::json& details, unique_pubkeys_and_scripts_t& missing);
        void process_unspent_outputs(nlohmann::json& utxos);
        nlohmann::json set_unspent_outputs_status(const nlohmann::json& details, const nlohmann::json& twofactor_data);
        Tx get_raw_transaction_details(const std::string& txhash_hex) const;

        nlohmann::json service_sign_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data,
            std::vector<std::vector<unsigned char>>& old_scripts);
        nlohmann::json send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data);
        std::string broadcast_transaction(const std::string& tx_hex);

        void send_nlocktimes();
        void set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data);
        void set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data);

        void set_transaction_memo(const std::string& txhash_hex, const std::string& memo);

        void upload_confidential_addresses(uint32_t subaccount, const std::vector<std::string>& addresses);

        nlohmann::json get_fee_estimates();

        std::string get_system_message();
        std::pair<std::string, std::vector<uint32_t>> get_system_message_info(const std::string& message);
        void ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex);

        nlohmann::json convert_amount(const nlohmann::json& amount_json) const;

        bool encache_blinding_data(const std::string& pubkey_hex, const std::string& script_hex,
            const std::string& nonce_hex, const std::string& blinding_pubkey_hex);
        void encache_new_scriptpubkeys(uint32_t subaccount);
        nlohmann::json get_scriptpubkey_data(byte_span_t scriptpubkey);

        amount get_min_fee_rate() const;
        amount get_default_fee_rate() const;
        uint32_t get_block_height() const;
        nlohmann::json get_spending_limits() const;
        bool is_spending_limits_decrease(const nlohmann::json& details);

        ga_pubkeys& get_ga_pubkeys();
        user_pubkeys& get_recovery_pubkeys();
        bool has_recovery_pubkeys_subaccount(uint32_t subaccount);
        std::vector<uint32_t> get_subaccount_root_path(uint32_t subaccount);
        std::vector<uint32_t> get_subaccount_full_path(uint32_t subaccount, uint32_t pointer, bool is_internal);
        std::string get_service_xpub(uint32_t subaccount);
        std::string get_recovery_xpub(uint32_t subaccount);

        std::pair<std::string, bool> get_cached_master_blinding_key();
        void set_cached_master_blinding_key(const std::string& master_blinding_key_hex);

        void encache_signer_xpubs(std::shared_ptr<signer> signer);

        nlohmann::json sync_transactions(uint32_t subaccount, unique_pubkeys_and_scripts_t& missing);
        void store_transactions(uint32_t subaccount, nlohmann::json& txs);
        void postprocess_transactions(nlohmann::json& tx_list);
        nlohmann::json get_transactions(const nlohmann::json& details);

    private:
        void reset_cached_session_data(locker_t& locker);
        void delete_reorg_block_txs(locker_t& locker, bool from_latest_cached);
        void reset_all_session_data(bool in_dtor);
        void set_local_encryption_keys_impl(
            locker_t& locker, const pub_key_t& public_key, std::shared_ptr<signer> signer);

        void derive_wallet_identifiers(locker_t& locker, nlohmann::json& login_data, bool is_relogin);
        void get_cached_client_blob(const std::string& server_hmac);
        bool load_client_blob(locker_t& locker, const std::string& client_id, bool encache);
        void update_client_blob(locker_t& locker, nlohmann::json& server_data, bool encache);
        bool save_client_blob(locker_t& locker, const std::string& client_id, const std::string& old_hmac);
        void encache_client_blob(locker_t& locker, const std::vector<unsigned char>& data, const std::string& hmac);
        void update_blob(locker_t& locker, std::function<bool()> update_fn);

        void load_signer_xpubs(locker_t& locker, std::shared_ptr<signer> signer);

        void ack_system_message(locker_t& locker, const std::string& message_hash_hex, const std::string& sig_der_hex);

        nlohmann::json sign_or_send_tx(const nlohmann::json& details, const nlohmann::json& twofactor_data,
            bool is_send, std::vector<std::vector<unsigned char>>& old_scripts);
        nlohmann::json get_appearance() const;
        bool subaccount_allows_csv(uint32_t subaccount) const;
        const std::string& get_default_address_type(uint32_t) const;
        void set_twofactor_config(locker_t& locker, const nlohmann::json& config);
        nlohmann::json set_twofactor_reset_config(const nlohmann::json& config);
        void set_enabled_twofactor_methods(locker_t& locker);
        nlohmann::json authenticate_wo(locker_t& locker, const std::string& username, const std::string& password,
            const std::string& user_agent, bool with_blob);
        nlohmann::json on_post_login(locker_t& locker, nlohmann::json& login_data, const std::string& root_bip32_xpub,
            bool watch_only, bool is_relogin);
        void update_fiat_rate(locker_t& locker, const std::string& rate_str);
        void update_spending_limits(locker_t& locker, const nlohmann::json& limits);
        nlohmann::json get_spending_limits(locker_t& locker) const;
        nlohmann::json convert_amount(locker_t& locker, const nlohmann::json& amount_json) const;
        nlohmann::json convert_fiat_cents(locker_t& locker, amount::value_type fiat_cents) const;
        nlohmann::json get_settings(locker_t& locker) const;
        bool unblind_utxo(locker_t& locker, nlohmann::json& utxo, const std::string& for_txhash,
            unique_pubkeys_and_scripts_t& missing);
        std::vector<unsigned char> get_alternate_blinding_nonce(
            locker_t& locker, nlohmann::json& utxo, const std::vector<unsigned char>& nonce_commitment);
        bool cleanup_utxos(session_impl::locker_t& locker, nlohmann::json& utxos, const std::string& for_txhash,
            unique_pubkeys_and_scripts_t& missing);

        std::unique_ptr<locker_t> get_multi_call_locker(uint32_t category_flags, bool wait_for_lock);
        void on_new_transaction(const std::vector<uint32_t>& subaccounts, nlohmann::json details);
        void purge_tx_notification(const std::string& txhash_hex);
        void on_new_block(nlohmann::json details, bool is_relogin);
        void on_new_block(locker_t& locker, nlohmann::json details, bool is_relogin);
        void on_new_tickers(nlohmann::json details);
        void set_pricing_source(
            locker_t& locker, const std::string& currency, const std::string& exchange, bool is_login);

        void remap_appearance_settings(session_impl::locker_t& locker, const nlohmann::json& src_json,
            nlohmann::json& dst_json, bool from_settings) const;

        nlohmann::json insert_subaccount(locker_t& locker, uint32_t subaccount, const std::string& name,
            const std::string& receiving_id, const std::string& recovery_pub_key,
            const std::string& recovery_chain_code, const std::string& recovery_xpub, const std::string& type,
            uint32_t required_ca);

        std::pair<std::string, std::string> sign_challenge(locker_t& locker, const std::string& challenge);

        void set_fee_estimates(locker_t& locker, const nlohmann::json& fee_estimates);

        nlohmann::json refresh_http_data(const std::string& page, const std::string& key, bool refresh);

        void update_address_info(nlohmann::json& address, bool is_historic);
        std::shared_ptr<nlocktime_t> update_nlocktime_info(session_impl::locker_t& locker);

        void save_cache();

        void subscribe_all(locker_t& locker);

        std::vector<unsigned char> get_pin_password(const std::string& pin, const std::string& pin_identifier);
        nlohmann::json decrypt_with_pin_impl(const nlohmann::json& details, bool is_login);

        // Start/stop background header downloads
        void download_headers_ctl(locker_t& locker, bool do_start);
        void download_headers_thread_fn();

        const bool m_spv_enabled;
        std::optional<pbkdf2_hmac512_t> m_local_encryption_key;
        // Current client blob (if any)
        client_blob m_blob;
        // HMAC of the current blobs contents
        std::string m_blob_hmac;
        // Key for encrypting the client blob contents
        std::optional<pbkdf2_hmac256_t> m_blob_aes_key;
        // Key for generating blob HMAC. Only set if the
        // client blob is writable.
        std::optional<pbkdf2_hmac256_t> m_blob_hmac_key;
        bool m_blob_outdated;
        std::array<uint32_t, 32> m_gait_path;
        nlohmann::json m_limits_data;
        nlohmann::json m_twofactor_config;
        amount::value_type m_min_fee_rate;
        std::string m_fiat_source;
        std::string m_fiat_rate;
        std::string m_fiat_currency;
        uint64_t m_earliest_block_time;
        uint64_t m_nlocktime;
        uint32_t m_csv_blocks;

        nlohmann::json m_assets;

        std::map<uint32_t, nlohmann::json> m_subaccounts; // Includes 0 for main
        std::unique_ptr<ga_pubkeys> m_ga_pubkeys;
        std::unique_ptr<ga_user_pubkeys> m_recovery_pubkeys;
        uint32_t m_next_subaccount;
        std::vector<uint32_t> m_fee_estimates;
        std::chrono::system_clock::time_point m_fee_estimates_ts;

        uint32_t m_system_message_id; // Next system message
        uint32_t m_system_message_ack_id; // Currently returned message id to ack
        std::string m_system_message_ack; // Currently returned message to ack
        std::vector<std::string> m_tx_notifications;
        std::chrono::system_clock::time_point m_tx_last_notification;
        nlohmann::json m_last_block_notification;

        uint32_t m_multi_call_category;
        std::shared_ptr<nlocktime_t> m_nlocktimes;

        std::shared_ptr<cache> m_cache;
        std::set<uint32_t> m_synced_subaccounts;
        const std::string m_user_agent;
        std::unique_ptr<wamp_transport> m_wamp;
        std::unique_ptr<wamp_transport> m_blobserver;

        // SPV header downloading
        std::shared_ptr<std::thread> m_spv_thread; // Header download thread
        std::atomic_bool m_spv_thread_done; // True when m_spv_thread has exited
        std::atomic_bool m_spv_thread_stop; // True when we want m_spv_thread to stop
        // Txs that are SPV verified but not yet confirmed beyond the reorg limit
        std::set<std::string> m_spv_verified_txs;
    };

} // namespace sdk
} // namespace ga

#endif
