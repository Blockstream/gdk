#ifndef GDK_GA_SESSION_HPP
#define GDK_GA_SESSION_HPP
#pragma once

#include <array>
#include <chrono>
#include <map>
#include <string>
#include <vector>

#include "amount.hpp"
#include "client_blob.hpp"
#include "ga_wally.hpp"
#include "session_impl.hpp"
#include "threading.hpp"

using namespace std::literals;

namespace ga {
namespace sdk {
    struct cache;
    struct websocketpp_gdk_config;
    struct websocketpp_gdk_tls_config;
    struct tor_controller;
    struct network_control_context;
    struct event_loop_controller;

    using client = websocketpp::client<websocketpp_gdk_config>;
    using client_tls = websocketpp::client<websocketpp_gdk_tls_config>;
    using context_ptr = websocketpp::lib::shared_ptr<boost::asio::ssl::context>;
    using wamp_session_ptr = std::shared_ptr<autobahn::wamp_session>;

    class ga_session final : public session_impl {
    public:
        using transport_t = std::shared_ptr<autobahn::wamp_websocket_transport>;
        using heartbeat_t = websocketpp::pong_timeout_handler;
        using nlocktime_t = std::map<std::string, nlohmann::json>; // txhash:pt_idx -> lock info

        explicit ga_session(network_parameters&& net_params);
        ~ga_session();

        nlohmann::json register_user(const std::string& master_pub_key_hex, const std::string& master_chain_code_hex,
            const std::string& gait_path_hex, bool supports_csv);

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

        std::string get_challenge(const pub_key_t& public_key);
        nlohmann::json authenticate(const std::string& sig_der_hex, const std::string& path_hex,
            const std::string& root_bip32_xpub, std::shared_ptr<signer> signer);

        void register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs);

        std::string mnemonic_from_pin_data(const nlohmann::json& pin_data);
        nlohmann::json login_watch_only(std::shared_ptr<signer> signer);

        bool set_watch_only(const std::string& username, const std::string& password);
        std::string get_watch_only_username();
        bool remove_account(const nlohmann::json& twofactor_data);

        template <typename T>
        void change_settings(const std::string& key, const T& value, const nlohmann::json& twofactor_data);
        void change_settings_limits(const nlohmann::json& details, const nlohmann::json& twofactor_data);

        nlohmann::json get_subaccounts();
        nlohmann::json get_subaccount(uint32_t subaccount);
        void rename_subaccount(uint32_t subaccount, const std::string& new_name);
        void set_subaccount_hidden(uint32_t subaccount, bool is_hidden);
        uint32_t get_next_subaccount(const std::string& type);
        nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount);
        nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount, const std::string& xpub);
        nlohmann::json get_receive_address(const nlohmann::json& details);
        nlohmann::json get_previous_addresses(uint32_t subaccount, uint32_t last_pointer);
        void set_local_encryption_keys(const pub_key_t& public_key, std::shared_ptr<signer> signer);
        nlohmann::json get_available_currencies() const;
        bool is_rbf_enabled() const;
        bool is_watch_only() const;

        nlohmann::json get_twofactor_config(bool reset_cached);
        nlohmann::json get_twofactor_config(locker_t& locker, bool reset_cached = false);
        std::vector<std::string> get_enabled_twofactor_methods();

        nlohmann::json get_settings();
        nlohmann::json get_post_login_data();
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

        nlohmann::json set_pin(const std::string& mnemonic, const std::string& pin, const std::string& device_id);
        void disable_all_pin_logins();

        nlohmann::json get_unspent_outputs(const nlohmann::json& details, unique_pubkeys_and_scripts_t& missing);
        void process_unspent_outputs(nlohmann::json& utxos);
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

        void upload_confidential_addresses(uint32_t subaccount, const std::vector<std::string>& addresses);

        void change_settings_pricing_source(const std::string& currency, const std::string& exchange);

        nlohmann::json get_fee_estimates();

        std::string get_system_message();
        std::pair<std::string, std::vector<uint32_t>> get_system_message_info(const std::string& message);
        void ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex);

        nlohmann::json convert_amount(const nlohmann::json& amount_json) const;

        bool set_blinding_nonce(
            const std::string& pubkey_hex, const std::string& script_hex, const std::string& nonce_hex);

        amount get_min_fee_rate() const;
        amount get_default_fee_rate() const;
        uint32_t get_block_height() const;
        amount get_dust_threshold() const;
        nlohmann::json get_spending_limits() const;
        bool is_spending_limits_decrease(const nlohmann::json& details);

        void emit_notification(nlohmann::json details, bool async);

        ga_pubkeys& get_ga_pubkeys();
        user_pubkeys& get_user_pubkeys();
        ga_user_pubkeys& get_recovery_pubkeys();
        bool has_recovery_pubkeys_subaccount(uint32_t subaccount);
        std::vector<uint32_t> get_subaccount_root_path(uint32_t subaccount);
        std::vector<uint32_t> get_subaccount_full_path(uint32_t subaccount, uint32_t pointer);
        std::string get_service_xpub(uint32_t subaccount);
        std::string get_recovery_xpub(uint32_t subaccount);

        std::vector<unsigned char> output_script_from_utxo(const nlohmann::json& utxo);
        std::vector<pub_key_t> pubkeys_from_utxo(const nlohmann::json& utxo);

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

        bool is_connected() const;
        bool reconnect();
        void stop_reconnect();

        void load_client_blob(locker_t& locker, bool encache);
        bool save_client_blob(locker_t& locker, const std::string& old_hmac);
        void encache_client_blob(locker_t& locker, const std::vector<unsigned char>& data);
        void update_blob(locker_t& locker, std::function<bool()> update_fn);

        void load_signer_xpubs(locker_t& locker, std::shared_ptr<signer> signer);

        void ack_system_message(locker_t& locker, const std::string& message_hash_hex, const std::string& sig_der_hex);

        nlohmann::json get_appearance() const;
        bool subaccount_allows_csv(uint32_t subaccount) const;
        const std::string& get_default_address_type(uint32_t) const;
        void push_appearance_to_server(locker_t& locker) const;
        void set_twofactor_config(locker_t& locker, const nlohmann::json& config);
        bool is_twofactor_reset_active(session_impl::locker_t& locker);
        nlohmann::json set_twofactor_reset_config(const autobahn::wamp_call_result& server_result);
        void set_enabled_twofactor_methods(locker_t& locker);
        nlohmann::json on_post_login(locker_t& locker, nlohmann::json& login_data, const std::string& root_bip32_xpub,
            bool watch_only, bool is_initial_login);
        void update_fiat_rate(locker_t& locker, const std::string& rate_str);
        void update_spending_limits(locker_t& locker, const nlohmann::json& limits);
        nlohmann::json get_spending_limits(locker_t& locker) const;
        nlohmann::json convert_amount(locker_t& locker, const nlohmann::json& amount_json) const;
        nlohmann::json convert_fiat_cents(locker_t& locker, amount::value_type fiat_cents) const;
        nlohmann::json get_settings(locker_t& locker);
        bool unblind_utxo(locker_t& locker, nlohmann::json& utxo, const std::string& for_txhash,
            unique_pubkeys_and_scripts_t& missing);
        bool cleanup_utxos(session_impl::locker_t& locker, nlohmann::json& utxos, const std::string& for_txhash,
            unique_pubkeys_and_scripts_t& missing);

        std::unique_ptr<locker_t> get_multi_call_locker(uint32_t category_flags, bool wait_for_lock);
        void on_new_transaction(const std::vector<uint32_t>& subaccounts, nlohmann::json details);
        void on_new_block(nlohmann::json details, bool is_relogin);
        void on_new_block(locker_t& locker, nlohmann::json details, bool is_relogin);
        void on_new_tickers(nlohmann::json details);
        void change_settings_pricing_source(locker_t& locker, const std::string& currency, const std::string& exchange);

        void remap_appearance_settings(session_impl::locker_t& locker, const nlohmann::json& src_json,
            nlohmann::json& dst_json, bool from_settings);

        nlohmann::json insert_subaccount(locker_t& locker, uint32_t subaccount, const std::string& name,
            const std::string& receiving_id, const std::string& recovery_pub_key,
            const std::string& recovery_chain_code, const std::string& recovery_xpub, const std::string& type,
            uint32_t required_ca, bool is_hidden);

        std::pair<std::string, std::string> sign_challenge(locker_t& locker, const std::string& challenge);

        void set_fee_estimates(locker_t& locker, const nlohmann::json& fee_estimates);

        nlohmann::json refresh_http_data(const std::string& page, const std::string& key, bool refresh);

        void update_address_info(nlohmann::json& address, bool is_historic);
        std::shared_ptr<nlocktime_t> update_nlocktime_info(session_impl::locker_t& locker);

        void save_cache();

        context_ptr tls_init_handler_impl(
            const std::string& host_name, const std::vector<std::string>& roots, const std::vector<std::string>& pins);

        void make_client();
        void make_transport();

        bool ping() const;

        void set_socket_options();
        void start_ping_timer();
        void disconnect();

        autobahn::wamp_subscription subscribe(
            locker_t& locker, const std::string& topic, const autobahn::wamp_event_handler& callback);
        void subscribe_all(locker_t& locker);
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

        std::string m_proxy;
        const bool m_has_network_proxy;

        boost::asio::io_context m_io;
        boost::variant<std::unique_ptr<client>, std::unique_ptr<client_tls>> m_client;
        transport_t m_transport;
        wamp_session_ptr m_session;
        std::vector<autobahn::wamp_subscription> m_subscriptions;
        heartbeat_t m_heartbeat_handler;
        ping_fail_t m_ping_fail_handler;

        boost::asio::deadline_timer m_ping_timer;

        std::unique_ptr<network_control_context> m_network_control;
        boost::asio::thread_pool m_pool;

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
        std::chrono::system_clock::time_point m_fee_estimates_ts;

        uint32_t m_system_message_id; // Next system message
        uint32_t m_system_message_ack_id; // Currently returned message id to ack
        std::string m_system_message_ack; // Currently returned message to ack
        bool m_watch_only;
        std::vector<std::string> m_tx_notifications;
        std::chrono::system_clock::time_point m_tx_last_notification;
        nlohmann::json m_last_block_notification;

        uint32_t m_multi_call_category;
        std::shared_ptr<nlocktime_t> m_nlocktimes;

        std::shared_ptr<tor_controller> m_tor_ctrl;
        std::string m_last_tor_socks5;
        std::shared_ptr<cache> m_cache;
        std::set<uint32_t> m_synced_subaccounts;
        const std::string m_user_agent;

        autobahn::wamp_call_options m_wamp_call_options;
        const std::string m_wamp_call_prefix;
        std::unique_ptr<event_loop_controller> m_controller;
    };

} // namespace sdk
} // namespace ga

#endif
