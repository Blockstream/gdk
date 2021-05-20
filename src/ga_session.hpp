#ifndef GDK_GA_SESSION_HPP
#define GDK_GA_SESSION_HPP
#pragma once

#include <array>
#include <chrono>
#include <map>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include "amount.hpp"
#include "client_blob.hpp"
#include "ga_cache.hpp"
#include "ga_wally.hpp"
#include "network_parameters.hpp"
#include "session_common.hpp"
#include "signer.hpp"
#include "threading.hpp"
#include "tx_list_cache.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ga {
namespace sdk {
    enum class logging_levels : uint32_t;

    struct websocketpp_gdk_config;
    struct websocketpp_gdk_tls_config;
    struct tor_controller;
    struct network_control_context;
    struct event_loop_controller;

    using client = websocketpp::client<websocketpp_gdk_config>;
    using client_tls = websocketpp::client<websocketpp_gdk_tls_config>;
    using context_ptr = websocketpp::lib::shared_ptr<boost::asio::ssl::context>;
    using wamp_session_ptr = std::shared_ptr<autobahn::wamp_session>;

    class ga_session final : public session_common {
    public:
        using transport_t = std::shared_ptr<autobahn::wamp_websocket_transport>;
        using locker_t = std::unique_lock<std::mutex>;
        using heartbeat_t = websocketpp::pong_timeout_handler;
        using ping_fail_t = std::function<void()>;
        using nlocktime_t = std::map<std::string, nlohmann::json>; // txhash:pt_idx -> lock info

        explicit ga_session(const nlohmann::json& net_params);
        ga_session(const ga_session& other) = delete;
        ga_session(ga_session&& other) noexcept = delete;
        ga_session& operator=(const ga_session& other) = delete;
        ga_session& operator=(ga_session&& other) noexcept = delete;

        ~ga_session();

        void connect();
        void try_reconnect();
        void reconnect_hint(bool enabled, bool restarted);
        std::string get_tor_socks5();
        void tor_sleep_hint(const std::string& hint);

        void set_heartbeat_timeout_handler(heartbeat_t handler);
        void set_ping_fail_handler(ping_fail_t handler);

        nlohmann::json http_request(nlohmann::json params);
        nlohmann::json refresh_assets(const nlohmann::json& params);
        nlohmann::json validate_asset_domain_name(const nlohmann::json& params);

        void register_user(const std::string& mnemonic, bool supports_csv);
        void register_user(const std::string& master_pub_key_hex, const std::string& master_chain_code_hex,
            const std::string& gait_path_hex, bool supports_csv);

        std::string get_challenge(const std::string& address);
        nlohmann::json authenticate(const std::string& sig_der_hex, const std::string& path_hex,
            const std::string& root_xpub_bip32, const std::string& device_id,
            const nlohmann::json& hw_device = nlohmann::json::object());

        void register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs);

        nlohmann::json login(const std::string& mnemonic, const std::string& password);
        bool login_from_cached(const std::string& mnemonic);
        nlohmann::json login_with_pin(const std::string& pin, const nlohmann::json& pin_data);
        nlohmann::json login_watch_only(const std::string& username, const std::string& password);
        void on_failed_login();

        bool set_watch_only(const std::string& username, const std::string& password);
        std::string get_watch_only_username();
        bool remove_account(const nlohmann::json& twofactor_data);

        template <typename T>
        void change_settings(const std::string& key, const T& value, const nlohmann::json& twofactor_data);
        void change_settings_limits(const nlohmann::json& details, const nlohmann::json& twofactor_data);

        nlohmann::json get_transactions(const nlohmann::json& details);

        void set_notification_handler(GA_notification_handler handler, void* context);

        nlohmann::json get_subaccounts();
        nlohmann::json get_subaccount(uint32_t subaccount);
        nlohmann::json get_cached_subaccount(uint32_t subaccount) const;
        void rename_subaccount(uint32_t subaccount, const std::string& new_name);
        void set_subaccount_hidden(uint32_t subaccount, bool is_hidden);
        uint32_t get_next_subaccount(const std::string& type);
        nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount);
        nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount, const std::string& xpub);
        nlohmann::json get_receive_address(const nlohmann::json& details);
        nlohmann::json get_previous_addresses(uint32_t subaccount, uint32_t last_pointer);
        void set_local_encryption_keys(const pub_key_t& public_key, bool is_hw_wallet);
        nlohmann::json get_balance(const nlohmann::json& details);
        nlohmann::json get_available_currencies() const;
        bool is_rbf_enabled() const;
        bool is_watch_only() const;

        nlohmann::json get_twofactor_config(bool reset_cached);
        nlohmann::json get_twofactor_config(locker_t& locker, bool reset_cached = false);
        std::vector<std::string> get_all_twofactor_methods();
        std::vector<std::string> get_enabled_twofactor_methods();

        nlohmann::json get_settings();
        nlohmann::json get_post_login_data();
        void change_settings(const nlohmann::json& settings);

        void set_email(const std::string& email, const nlohmann::json& twofactor_data);
        void activate_email(const std::string& code);
        void init_enable_twofactor(
            const std::string& method, const std::string& data, const nlohmann::json& twofactor_data);
        void enable_twofactor(const std::string& method, const std::string& code);
        void enable_gauth(const std::string& code, const nlohmann::json& twofactor_data);
        void disable_twofactor(const std::string& method, const nlohmann::json& twofactor_data);
        void auth_handler_request_code(
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
        nlohmann::json get_transaction_details(const std::string& txhash) const;
        tx_list_cache::container_type get_raw_transactions(uint32_t subaccount, uint32_t first, uint32_t count);

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

        void change_settings_pricing_source(const std::string& currency, const std::string& exchange);

        nlohmann::json get_fee_estimates();

        std::string get_mnemonic_passphrase(const std::string& password);

        std::string get_system_message();
        std::pair<std::string, std::vector<uint32_t>> get_system_message_info(const std::string& message);
        void ack_system_message(const std::string& message);
        void ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex);

        nlohmann::json convert_amount(const nlohmann::json& amount_json) const;

        bool has_blinding_nonce(const std::string& pubkey, const std::string& script);
        void set_blinding_nonce(const std::string& pubkey, const std::string& script, const std::string& nonce);
        std::vector<unsigned char> get_blinding_nonce(const std::string& pubkey, const std::string& script);

        amount get_min_fee_rate() const;
        amount get_default_fee_rate() const;
        uint32_t get_block_height() const;
        amount get_dust_threshold() const;
        nlohmann::json get_spending_limits() const;
        bool is_spending_limits_decrease(const nlohmann::json& details);
        const network_parameters& get_network_parameters() const { return m_net_params; }

        void emit_notification(std::string event, nlohmann::json details);

        std::shared_ptr<signer> get_signer();
        ga_pubkeys& get_ga_pubkeys();
        user_pubkeys& get_user_pubkeys();
        ga_user_pubkeys& get_recovery_pubkeys();
        bool has_recovery_pubkeys_subaccount(uint32_t subaccount);
        std::vector<uint32_t> get_subaccount_root_path(uint32_t subaccount);
        std::vector<uint32_t> get_subaccount_full_path(uint32_t subaccount, uint32_t pointer);
        std::string get_service_xpub(uint32_t subaccount);
        std::string get_recovery_xpub(uint32_t subaccount);
        ae_protocol_support_level ae_protocol_support() const;

        std::vector<unsigned char> output_script_from_utxo(const nlohmann::json& utxo);
        std::vector<pub_key_t> pubkeys_from_utxo(const nlohmann::json& utxo);

    private:
        void reset();

        bool is_connected() const;
        bool reconnect();
        void stop_reconnect();

        void register_user(locker_t& locker, const std::string& mnemonic, bool supports_csv);
        void register_user(locker_t& locker, const std::string& master_pub_key_hex,
            const std::string& master_chain_code_hex, const std::string& gait_path_hex, bool supports_csv);

        nlohmann::json authenticate(locker_t& locker, const std::string& sig_der_hex, const std::string& path_hex,
            const std::string& root_xpub_bip32, const std::string& device_id, const nlohmann::json& hw_device);
        nlohmann::json login(locker_t& locker, const std::string& mnemonic);
        void set_notification_handler(locker_t& locker, GA_notification_handler handler, void* context);

        void load_client_blob(locker_t& locker, bool encache);
        bool save_client_blob(locker_t& locker, const std::string& old_hmac);
        void encache_client_blob(locker_t& locker, const std::vector<unsigned char>& data);
        void update_blob(locker_t& locker, std::function<bool()> update_fn);
        void ack_system_message(locker_t& locker, const std::string& message_hash_hex, const std::string& sig_der_hex);

        nlohmann::json get_appearance() const;
        bool subaccount_allows_csv(uint32_t subaccount) const;
        const std::string& get_default_address_type(uint32_t) const;
        void push_appearance_to_server(locker_t& locker) const;
        void set_twofactor_config(locker_t& locker, const nlohmann::json& config);
        void set_enabled_twofactor_methods(locker_t& locker);
        void update_login_data(
            locker_t& locker, nlohmann::json& login_data, const std::string& root_xpub_bip32, bool watch_only);
        void update_fiat_rate(locker_t& locker, const std::string& rate_str);
        void update_spending_limits(locker_t& locker, const nlohmann::json& limits);
        nlohmann::json get_spending_limits(locker_t& locker) const;
        nlohmann::json get_subaccount(locker_t& locker, uint32_t subaccount);
        nlohmann::json get_subaccount_balance_from_server(uint32_t subaccount, uint32_t num_confs, bool confidential);
        nlohmann::json convert_amount(locker_t& locker, const nlohmann::json& amount_json) const;
        nlohmann::json convert_fiat_cents(locker_t& locker, amount::value_type fiat_cents) const;
        nlohmann::json get_settings(locker_t& locker);
        virtual nlohmann::json get_all_unspent_outputs(uint32_t subaccount, uint32_t num_confs, bool all_coins);
        bool unblind_utxo(nlohmann::json& utxo, const std::string& policy_asset);
        nlohmann::json cleanup_utxos(nlohmann::json& utxos, const std::string& policy_asset);
        tx_list_cache::container_type get_tx_list(ga_session::locker_t& locker, uint32_t subaccount, uint32_t page_id,
            const std::string& start_date, const std::string& end_date, nlohmann::json& state_info);

        autobahn::wamp_subscription subscribe(
            locker_t& locker, const std::string& topic, const autobahn::wamp_event_handler& callback);
        void call_notification_handler(locker_t& locker, nlohmann::json* details);

        std::unique_ptr<locker_t> get_multi_call_locker(uint32_t category_flags, bool wait_for_lock);
        void on_new_transaction(const std::vector<uint32_t>& subaccounts, nlohmann::json details);
        void on_new_block(nlohmann::json details);
        void on_new_fees(locker_t& locker, const nlohmann::json& details);
        void change_settings_pricing_source(locker_t& locker, const std::string& currency, const std::string& exchange);

        void remap_appearance_settings(
            ga_session::locker_t& locker, const nlohmann::json& src_json, nlohmann::json& dst_json, bool from_settings);

        nlohmann::json insert_subaccount(locker_t& locker, uint32_t subaccount, const std::string& name,
            const std::string& receiving_id, const std::string& recovery_pub_key,
            const std::string& recovery_chain_code, const std::string& recovery_xpub, const std::string& type,
            amount satoshi, bool has_txs, uint32_t required_ca, bool is_hidden);

        std::pair<std::string, std::string> sign_challenge(locker_t& locker, const std::string& challenge);

        nlohmann::json set_fee_estimates(locker_t& locker, const nlohmann::json& fee_estimates);

        nlohmann::json refresh_http_data(const std::string& type, bool refresh);

        void update_address_info(nlohmann::json& address, bool is_historic);
        std::shared_ptr<nlocktime_t> update_nlocktime_info();
        virtual nlohmann::json fetch_nlocktime_json();

        void set_local_encryption_keys(locker_t& locker, const pub_key_t& public_key, bool is_hw_wallet);

        context_ptr tls_init_handler_impl(
            const std::string& host_name, const std::vector<std::string>& roots, const std::vector<std::string>& pins);

        void make_client();
        void make_transport();

        void disconnect_transport() const;
        bool ping() const;

        void set_socket_options();
        void start_ping_timer();
        void disconnect();
        void unsubscribe();

        // Make a background WAMP call and return its result to the current thread.
        // The session mutex must not be held when calling this function.
        template <typename... Args>
        autobahn::wamp_call_result wamp_call(const std::string& method_name, Args&&... args) const
        {
            const std::string method{ m_wamp_call_prefix + method_name };
            auto fn = m_session->call(method, std::make_tuple(std::forward<Args>(args)...), m_wamp_call_options);
            return wamp_process_call(fn);
        }

        // Make a WAMP call on a currently locked session.
        template <typename... Args>
        autobahn::wamp_call_result wamp_call(locker_t& locker, const std::string& method_name, Args&&... args) const
        {
            unique_unlock unlocker(locker);
            return wamp_call(method_name, std::forward<Args>(args)...);
        }

        autobahn::wamp_call_result wamp_process_call(boost::future<autobahn::wamp_call_result>& fn) const;

        std::vector<unsigned char> get_pin_password(const std::string& pin, const std::string& pin_identifier);

        void ping_timer_handler(const boost::system::error_code& ec);

        // Locking per-session assumes the following thread safety model:
        // 1) wamp_call is assumed thread-safe
        // 2) Implementations noted "idempotent" can be called from multiple
        //    threads at once
        // 3) Implementations noted "post-login idempotent" can be called
        //    from multiple threads after login has completed.
        // 4) Implementations that take a locker_t as the first parameter
        //    assume that the caller holds the lock and will leave it
        //    locked upon return.
        //
        // The safest way to strictly adhere to the above is to serialize all
        // access to the session. Everything up to login should be serialized
        // otherwise. Logical wallet operation that span more than one api call
        // (such as those handled by two factor call objects) do not lock the
        // session for the entire operation. In general we must assume that
        // local state can be out of sync with the server, whether this is due
        // to multiple threads in a single process or actions in another
        // process (e.g. the user is logged in twice in different apps)
        //
        // ** Under no circumstances must this mutex ever be made recursive **
        mutable std::mutex m_mutex;
        const network_parameters m_net_params;
        std::string m_proxy;
        const bool m_use_tor;
        const bool m_has_network_proxy;
        const bool m_is_tls_connection;

        boost::asio::io_context m_io;
        boost::variant<std::unique_ptr<client>, std::unique_ptr<client_tls>> m_client;
        transport_t m_transport;
        wamp_session_ptr m_session;
        std::vector<autobahn::wamp_subscription> m_subscriptions;
        heartbeat_t m_heartbeat_handler;
        ping_fail_t m_ping_fail_handler;

        std::unique_ptr<event_loop_controller> m_controller;
        boost::asio::deadline_timer m_ping_timer;

        std::unique_ptr<network_control_context> m_network_control;
        boost::asio::thread_pool m_pool;

        GA_notification_handler m_notification_handler;
        void* m_notification_context;

        nlohmann::json m_login_data;
        boost::optional<pbkdf2_hmac512_t> m_local_encryption_key;
        client_blob m_blob;
        std::string m_blob_hmac;
        boost::optional<std::array<unsigned char, 32>> m_blob_aes_key;
        boost::optional<std::array<unsigned char, 32>> m_blob_hmac_key;
        bool m_blob_outdated;
        std::array<uint32_t, 32> m_gait_path;
        nlohmann::json m_limits_data;
        nlohmann::json m_twofactor_config;
        std::string m_mnemonic;
        amount::value_type m_min_fee_rate;
        std::string m_fiat_source;
        std::string m_fiat_rate;
        std::string m_fiat_currency;
        uint64_t m_earliest_block_time;
        uint64_t m_nlocktime;
        uint32_t m_csv_blocks;
        std::vector<uint32_t> m_csv_buckets;

        nlohmann::json m_assets;

        std::map<uint32_t, nlohmann::json> m_subaccounts; // Includes 0 for main
        std::unique_ptr<ga_pubkeys> m_ga_pubkeys;
        std::unique_ptr<user_pubkeys> m_user_pubkeys;
        std::unique_ptr<ga_user_pubkeys> m_recovery_pubkeys;
        uint32_t m_next_subaccount;
        std::vector<uint32_t> m_fee_estimates;
        uint32_t m_block_height;

        uint32_t m_system_message_id; // Next system message
        uint32_t m_system_message_ack_id; // Currently returned message id to ack
        std::string m_system_message_ack; // Currently returned message to ack
        bool m_watch_only;
        bool m_is_locked;
        logging_levels m_log_level;
        std::vector<std::string> m_tx_notifications;
        std::chrono::system_clock::time_point m_tx_last_notification;

        uint32_t m_multi_call_category;
        tx_list_caches m_tx_list_caches;
        std::shared_ptr<nlocktime_t> m_nlocktimes;

        std::shared_ptr<tor_controller> m_tor_ctrl;
        std::string m_last_tor_socks5;
        cache m_cache;
        const std::string m_user_agent;

        const std::string m_electrum_url;
        const bool m_electrum_tls;
        const bool m_spv_enabled;
        autobahn::wamp_call_options m_wamp_call_options;
        const std::string m_wamp_call_prefix;
    };

} // namespace sdk
} // namespace ga

#endif
