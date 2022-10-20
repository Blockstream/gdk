#ifndef GDK_SESSION_IMPL_HPP
#define GDK_SESSION_IMPL_HPP

#pragma once
#include <mutex>
#include <set>
#include <thread>

#include "amount.hpp"
#include "boost_wrapper.hpp"
#include "ga_wally.hpp"
#include "network_parameters.hpp"

namespace ga {
namespace sdk {
    using pubkey_and_script_t = std::pair<std::vector<unsigned char>, std::vector<unsigned char>>;
    using unique_pubkeys_and_scripts_t = std::set<pubkey_and_script_t>;

    class ga_pubkeys;
    class user_pubkeys;
    class signer;
    struct tor_controller;

    class session_impl {
    public:
        using locker_t = std::unique_lock<std::mutex>;

        explicit session_impl(network_parameters&& net_params);
        session_impl(const session_impl& other) = delete;
        session_impl(session_impl&& other) noexcept = delete;
        session_impl& operator=(const session_impl& other) = delete;
        session_impl& operator=(session_impl&& other) noexcept = delete;

        virtual ~session_impl();

        // Factory method
        static std::shared_ptr<session_impl> create(const nlohmann::json& net_params);

        // UTXOs
        using utxo_cache_value_t = std::shared_ptr<const nlohmann::json>;

        // Lookup cached UTXOs
        utxo_cache_value_t get_cached_utxos(uint32_t subaccount, uint32_t num_confs) const;
        // Encache UTXOs. Takes ownership of utxos, returns the encached value
        utxo_cache_value_t set_cached_utxos(uint32_t subaccount, uint32_t num_confs, nlohmann::json& utxos);
        // Un-encache UTXOs
        void remove_cached_utxos(const std::vector<uint32_t>& subaccounts);

        virtual nlohmann::json get_unspent_outputs(const nlohmann::json& details, unique_pubkeys_and_scripts_t& missing)
            = 0;
        virtual void process_unspent_outputs(nlohmann::json& utxos);
        virtual nlohmann::json get_unspent_outputs_for_private_key(
            const std::string& private_key, const std::string& password, uint32_t unused)
            = 0;
        virtual nlohmann::json set_unspent_outputs_status(
            const nlohmann::json& details, const nlohmann::json& twofactor_data)
            = 0;

        virtual nlohmann::json register_user(const std::string& master_pub_key_hex,
            const std::string& master_chain_code_hex, const std::string& gait_path_hex, bool supports_csv);

        // Disable notifications from being delivered
        void disable_notifications();
        // Call the users registered notification handler. Must be called without any locks held.
        virtual void emit_notification(nlohmann::json details, bool async);
        std::string connect_tor();
        virtual void reconnect() = 0;
        virtual void reconnect_hint(const nlohmann::json& hint);
        // Get the tor or user connection proxy address
        nlohmann::json get_proxy_settings() const;
        nlohmann::json get_registry_config() const;

        virtual void connect() = 0;
        virtual void disconnect() = 0;

        // Make an http request to an arbitrary host governed by 'params'.
        virtual nlohmann::json http_request(nlohmann::json params);
        virtual void refresh_assets(const nlohmann::json& params);
        nlohmann::json get_assets(const nlohmann::json& params);
        virtual nlohmann::json validate_asset_domain_name(const nlohmann::json& params) = 0;

        virtual void load_store(std::shared_ptr<signer> signer);
        virtual void start_sync_threads();
        virtual std::vector<uint32_t> get_subaccount_pointers() = 0;
        virtual std::string get_challenge(const pub_key_t& public_key) = 0;
        virtual nlohmann::json authenticate(const std::string& sig_der_hex, const std::string& path_hex,
            const std::string& root_bip32_xpub, std::shared_ptr<signer> signer)
            = 0;
        virtual void register_subaccount_xpubs(
            const std::vector<uint32_t>& pointers, const std::vector<std::string>& bip32_xpubs)
            = 0;
        virtual nlohmann::json login(std::shared_ptr<signer> signer);
        virtual nlohmann::json credentials_from_pin_data(const nlohmann::json& pin_data) = 0;
        virtual nlohmann::json login_wo(std::shared_ptr<signer> signer) = 0;
        virtual bool set_wo_credentials(const std::string& username, const std::string& password) = 0;
        virtual std::string get_wo_username() = 0;
        virtual bool remove_account(const nlohmann::json& twofactor_data) = 0;

        // Returns true if the subaccount was discovered
        virtual bool discover_subaccount(const std::string& xpub, const std::string& type);
        virtual uint32_t get_next_subaccount(const std::string& type) = 0;
        virtual nlohmann::json create_subaccount(
            const nlohmann::json& details, uint32_t subaccount, const std::string& xpub)
            = 0;

        virtual void change_settings_limits(const nlohmann::json& limit_details, const nlohmann::json& twofactor_data)
            = 0;
        virtual nlohmann::json get_transactions(const nlohmann::json& details) = 0;
        virtual nlohmann::json sync_transactions(uint32_t subaccount, unique_pubkeys_and_scripts_t& missing);
        virtual void store_transactions(uint32_t subaccount, nlohmann::json& txs);
        virtual void postprocess_transactions(nlohmann::json& tx_list);

        virtual void set_notification_handler(GA_notification_handler handler, void* context);
        bool set_signer(std::shared_ptr<signer> signer);

        virtual nlohmann::json get_receive_address(const nlohmann::json& details) = 0;
        virtual nlohmann::json get_previous_addresses(const nlohmann::json& details) = 0;
        virtual nlohmann::json get_subaccounts() = 0;
        virtual nlohmann::json get_subaccount(uint32_t subaccount) = 0;
        virtual void rename_subaccount(uint32_t subaccount, const std::string& new_name) = 0;
        virtual void set_subaccount_hidden(uint32_t subaccount, bool is_hidden) = 0;
        virtual std::vector<uint32_t> get_subaccount_root_path(uint32_t subaccount) = 0;
        virtual std::vector<uint32_t> get_subaccount_full_path(uint32_t subaccount, uint32_t pointer, bool is_internal)
            = 0;
        virtual std::string get_subaccount_type(uint32_t subaccount);

        virtual nlohmann::json get_available_currencies() const = 0;

        virtual bool is_rbf_enabled() const = 0;
        virtual bool is_watch_only() const = 0;
        virtual void ensure_full_session() = 0;
        virtual nlohmann::json get_settings() = 0;
        virtual nlohmann::json get_post_login_data() = 0;
        virtual void change_settings(const nlohmann::json& settings) = 0;

        virtual nlohmann::json get_twofactor_config(bool reset_cached = false) = 0;
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

        virtual nlohmann::json encrypt_with_pin(const nlohmann::json& details) = 0;
        virtual nlohmann::json decrypt_with_pin(const nlohmann::json& details);

        virtual bool encache_blinding_data(const std::string& pubkey_hex, const std::string& script_hex,
            const std::string& nonce_hex, const std::string& blinding_pubkey_hex);
        virtual void encache_scriptpubkey_data(byte_span_t scriptpubkey, const uint32_t subaccount,
            const uint32_t branch, const uint32_t pointer, const uint32_t subtype, const uint32_t script_type);
        virtual void encache_new_scriptpubkeys(const uint32_t subaccount);
        virtual nlohmann::json get_scriptpubkey_data(byte_span_t scriptpubkey);
        virtual nlohmann::json psbt_get_details(const nlohmann::json& details);
        virtual void upload_confidential_addresses(
            uint32_t subaccount, const std::vector<std::string>& confidential_addresses)
            = 0;

        virtual wally_tx_ptr get_raw_transaction_details(const std::string& txhash_hex) const = 0;
        virtual nlohmann::json get_transaction_details(const std::string& txhash_hex) const = 0;

        virtual nlohmann::json create_transaction(const nlohmann::json& details) = 0;
        virtual nlohmann::json user_sign_transaction(const nlohmann::json& details) = 0;
        virtual nlohmann::json service_sign_transaction(
            const nlohmann::json& details, const nlohmann::json& twofactor_data)
            = 0;
        virtual nlohmann::json psbt_sign(const nlohmann::json& details) = 0;
        virtual nlohmann::json send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data)
            = 0;
        virtual std::string broadcast_transaction(const std::string& tx_hex) = 0;

        virtual void send_nlocktimes() = 0;
        virtual void set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data) = 0;
        virtual void set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data) = 0;

        virtual void set_transaction_memo(const std::string& txhash_hex, const std::string& memo) = 0;

        virtual nlohmann::json get_fee_estimates() = 0;

        virtual std::string get_system_message() = 0;
        virtual std::pair<std::string, std::vector<uint32_t>> get_system_message_info(const std::string& system_message)
            = 0;
        virtual void ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex) = 0;

        virtual nlohmann::json convert_amount(const nlohmann::json& amount_json) const = 0;

        virtual amount get_min_fee_rate() const = 0;
        virtual amount get_default_fee_rate() const = 0;
        virtual uint32_t get_block_height() const = 0;
        virtual amount get_dust_threshold() const = 0;
        virtual nlohmann::json get_spending_limits() const = 0;
        virtual bool is_spending_limits_decrease(const nlohmann::json& limit_details) = 0;

        virtual void set_local_encryption_keys(const pub_key_t& public_key, std::shared_ptr<signer> signer) = 0;
        virtual void save_cache();
        virtual void disable_all_pin_logins() = 0;

        const network_parameters& get_network_parameters() const { return m_net_params; }
        std::shared_ptr<signer> get_nonnull_signer();
        std::shared_ptr<signer> get_signer();
        virtual void encache_signer_xpubs(std::shared_ptr<signer> signer);

        virtual ga_pubkeys& get_ga_pubkeys() = 0;
        virtual user_pubkeys& get_user_pubkeys();
        virtual user_pubkeys& get_recovery_pubkeys() = 0;

        // Cached data
        virtual std::pair<std::string, bool> get_cached_master_blinding_key() = 0;
        virtual void set_cached_master_blinding_key(const std::string& master_blinding_key_hex);

        virtual bool has_recovery_pubkeys_subaccount(uint32_t subaccount);
        virtual std::string get_service_xpub(uint32_t subaccount);
        virtual std::string get_recovery_xpub(uint32_t subaccount);
        virtual std::vector<unsigned char> output_script_from_utxo(const nlohmann::json& utxo);
        virtual std::vector<pub_key_t> pubkeys_from_utxo(const nlohmann::json& utxo);

        virtual nlohmann::json gl_call(const char* method, const nlohmann::json& params);

    protected:
        // Locking per-session assumes the following thread safety model:
        // 1) Implementations noted "idempotent" can be called from multiple
        //    threads at once
        // 2) Implementations noted "post-login idempotent" can be called
        //    from multiple threads after login has completed.
        // 3) Implementations that take a locker_t as the first parameter
        //    assume that the caller holds the lock and will leave it
        //    locked upon return.
        //
        // The safest way to strictly adhere to the above is to serialize all
        // access to the session. Everything up to login should be serialized
        // otherwise. Logical wallet operations that span more than one api call
        // (such as those handled by two factor call objects) do not lock the
        // session for the entire operation. In general we must assume that
        // local state can be out of sync with the server, whether this is due
        // to multiple threads in a single process or actions in another
        // process (e.g. the user is logged in twice in different apps)
        //
        // ** Under no circumstances must this mutex ever be made recursive **
        mutable std::mutex m_mutex;

        // Immutable upon construction
        const network_parameters m_net_params;
        boost::asio::io_context m_io;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_work_guard;
        std::thread m_run_thread; // Runs the asio context
        const std::string m_user_proxy;
        std::shared_ptr<tor_controller> m_tor_ctrl;

        // Immutable once set by the caller (prior to connect)
        GA_notification_handler m_notification_handler;
        void* m_notification_context;

        // Immutable post-login
        std::shared_ptr<signer> m_signer;
        std::unique_ptr<user_pubkeys> m_user_pubkeys;

        // Mutable
        std::string m_tor_proxy; // Updated on connect(), protected by m_mutex
        std::atomic_bool m_notify; // Whether to emit notifications

        // UTXOs
        // Cached UTXOs are unfiltered; if using the cached values you
        // may need to filter them first (e.g. to removed expired or frozen UTXOS)
        using utxo_cache_key_t = std::pair<uint32_t, uint32_t>; // subaccount, num_confs
        using utxo_cache_t = std::map<utxo_cache_key_t, utxo_cache_value_t>;
        mutable std::mutex m_utxo_cache_mutex;
        utxo_cache_t m_utxo_cache;
    };

} // namespace sdk
} // namespace ga

#endif // #ifndef GDK_SESSION_IMPL_HPP
