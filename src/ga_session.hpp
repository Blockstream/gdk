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

    class ga_pubkeys;
    class ga_user_pubkeys;
    class signer;

    struct websocketpp_gdk_config;
    struct websocketpp_gdk_tls_config;
    struct tor_controller;

    using client = websocketpp::client<websocketpp_gdk_config>;
    using client_tls = websocketpp::client<websocketpp_gdk_tls_config>;
    using transport = autobahn::wamp_websocketpp_websocket_transport<websocketpp_gdk_config>;
    using transport_tls = autobahn::wamp_websocketpp_websocket_transport<websocketpp_gdk_tls_config>;
    using context_ptr = websocketpp::lib::shared_ptr<boost::asio::ssl::context>;
    using wamp_call_result = boost::future<autobahn::wamp_call_result>;
    using wamp_session_ptr = std::shared_ptr<autobahn::wamp_session>;

    class exponential_backoff {
    public:
        explicit exponential_backoff(std::chrono::seconds limit = 300s)
            : m_limit(limit)
        {
        }

        std::chrono::seconds backoff(uint32_t n)
        {
            m_elapsed += m_waiting;
            const auto v
                = std::min(static_cast<uint32_t>(m_limit.count()), uint32_t{ 1 } << std::min(n, uint32_t{ 31 }));
            std::random_device rd;
            std::uniform_int_distribution<uint32_t> d(v / 2, v);
            m_waiting = std::chrono::seconds(d(rd));
            return m_waiting;
        }

        bool limit_reached() const { return m_elapsed >= m_limit; }
        std::chrono::seconds elapsed() const { return m_elapsed; }
        std::chrono::seconds waiting() const { return m_waiting; }

    private:
        const std::chrono::seconds m_limit;
        std::chrono::seconds m_elapsed{ 0s };
        std::chrono::seconds m_waiting{ 0s };
    };

    template <class T> struct flag_type {

        flag_type() { flag.second = flag.first.get_future(); }

        template <bool is_void = std::is_void<T>::value> std::enable_if_t<is_void> set() { flag.first.set_value(); }

        template <bool is_void = std::is_void<T>::value> void set(std::enable_if_t<!is_void, T> v)
        {
            flag.first.set_value(v);
        }

        T get() { return flag.second.get(); }

        std::future_status wait(std::chrono::seconds secs = 0s) const { return flag.second.wait_for(secs); }

        std::pair<std::promise<T>, std::future<T>> flag;
    };

    class network_control_context final {
    public:
        using flag_t = flag_type<void>;

        network_control_context() = default;
        ~network_control_context() = default;

        network_control_context(const network_control_context& context) = delete;
        network_control_context& operator=(const network_control_context& context) = delete;
        network_control_context(network_control_context&& context) = delete;
        network_control_context& operator=(network_control_context&& context) = delete;

        bool set_reconnect(bool reconnect)
        {
            bool r = m_reconnect_flag;
            if (r && reconnect) {
                return false;
            }
            return m_reconnect_flag.compare_exchange_strong(r, reconnect);
        }

        bool reconnecting() const { return m_reconnect_flag; }

        void reset_exit() { m_exit_flag = flag_t{}; }
        void set_exit() { m_exit_flag.set(); }
        bool retrying(std::chrono::seconds secs) const { return m_exit_flag.wait(secs) != std::future_status::ready; }

        void set_enabled(bool v) { m_enabled = v; }
        bool is_enabled() const { return m_enabled; }

        void reset() { reset_exit(); }

    private:
        flag_t m_exit_flag;
        std::atomic_bool m_reconnect_flag{ false };
        std::atomic_bool m_enabled{ true };
    };

    struct event_loop_controller {
        explicit event_loop_controller(boost::asio::io_service& io);

        void reset();

        std::thread m_run_thread;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_work_guard;
    };

    class ga_session final : public session_common {
    public:
        using transport_t = boost::variant<std::shared_ptr<transport>, std::shared_ptr<transport_tls>>;
        using locker_t = annotated_unique_lock<annotated_mutex>;
        using heartbeat_t = websocketpp::pong_timeout_handler;
        using ping_fail_t = std::function<void()>;
        using nlocktime_t = std::map<std::pair<std::string, uint32_t>, nlohmann::json>;

        explicit ga_session(const nlohmann::json& net_params);
        ga_session(const ga_session& other) = delete;
        ga_session(ga_session&& other) noexcept = delete;
        ga_session& operator=(const ga_session& other) = delete;
        ga_session& operator=(ga_session&& other) noexcept = delete;

        ~ga_session();

        void connect();
        void try_reconnect();
        void stop_reconnect();
        void reconnect_hint(bool enabled, bool restarted);
        bool reconnect();
        std::string get_tor_socks5();
        void tor_sleep_hint(const std::string& hint);

        void set_heartbeat_timeout_handler(heartbeat_t handler);
        void set_ping_fail_handler(ping_fail_t handler);

        nlohmann::json http_get(const nlohmann::json& params);
        nlohmann::json refresh_assets(const nlohmann::json& params);
        nlohmann::json validate_asset_domain_name(const nlohmann::json& params);

        void register_user(const std::string& mnemonic, bool supports_csv);
        void register_user(const std::string& master_pub_key_hex, const std::string& master_chain_code_hex,
            const std::string& gait_path_hex, bool supports_csv);

        std::string get_challenge(const std::string& address);
        void authenticate(const std::string& sig_der_hex, const std::string& path_hex, const std::string& device_id,
            const nlohmann::json& hw_device = nlohmann::json::object());

        void register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs);

        void login(const std::string& mnemonic, const std::string& password);
        bool login_from_cached(const std::string& mnemonic);
        void login_with_pin(const std::string& pin, const nlohmann::json& pin_data);
        void login_watch_only(const std::string& username, const std::string& password);
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
        uint32_t get_next_subaccount();
        nlohmann::json create_subaccount(const nlohmann::json& details);
        nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount, const std::string& xpub);
        nlohmann::json get_receive_address(uint32_t subaccount, const std::string& addr_type_);
        nlohmann::json get_receive_address(const nlohmann::json& details);
        std::string get_blinding_key_for_script(const std::string& script_hex);
        void set_local_encryption_key(byte_span_t key);
        std::string blind_address(const std::string& unblinded_addr, const std::string& blinding_key_hex);
        std::string extract_confidential_address(const std::string& blinded_address);
        nlohmann::json get_balance(const nlohmann::json& details);
        nlohmann::json get_available_currencies() const;
        nlohmann::json get_hw_device() const;
        bool is_rbf_enabled() const;
        bool is_watch_only() const;

        nlohmann::json get_twofactor_config(bool reset_cached);
        nlohmann::json get_twofactor_config(locker_t& locker, bool reset_cached = false) GDK_REQUIRES(m_mutex);
        std::vector<std::string> get_all_twofactor_methods();
        std::vector<std::string> get_enabled_twofactor_methods();

        nlohmann::json get_settings();
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
        nlohmann::json reset_twofactor(const std::string& email);
        nlohmann::json confirm_twofactor_reset(
            const std::string& email, bool is_dispute, const nlohmann::json& twofactor_data);
        nlohmann::json cancel_twofactor_reset(const nlohmann::json& twofactor_data);

        nlohmann::json set_pin(const std::string& mnemonic, const std::string& pin, const std::string& device_id);
        void disable_all_pin_logins();

        nlohmann::json get_blinded_scripts(const nlohmann::json& details);
        nlohmann::json get_unspent_outputs(const nlohmann::json& details);
        nlohmann::json get_unspent_outputs_for_private_key(
            const std::string& private_key, const std::string& password, uint32_t unused);
        nlohmann::json get_transaction_details(const std::string& txhash) const;
        std::vector<nlohmann::json> get_transactions(uint32_t subaccount, uint32_t page_id);

        nlohmann::json create_transaction(const nlohmann::json& details);
        nlohmann::json sign_transaction(const nlohmann::json& details);
        nlohmann::json send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data);
        std::string broadcast_transaction(const std::string& tx_hex);

        void sign_input(const wally_tx_ptr& tx, uint32_t index, const nlohmann::json& u, const std::string& der_hex);
        void blind_output(const nlohmann::json& details, const wally_tx_ptr& tx, uint32_t index,
            const nlohmann::json& output, const std::string& asset_commitment_hex,
            const std::string& value_commitment_hex, const std::string& abf, const std::string& vbf);

        void send_nlocktimes();
        nlohmann::json get_expired_deposits(const nlohmann::json& deposit_details);
        void set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data);
        void set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data);

        void set_transaction_memo(const std::string& txhash_hex, const std::string& memo, const std::string& memo_type);

        void upload_confidential_addresses(uint32_t subaccount, std::vector<std::string> confidential_addresses);

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
        std::array<unsigned char, 32> get_blinding_nonce(const std::string& pubkey, const std::string& script);

        amount get_min_fee_rate() const;
        amount get_default_fee_rate() const;
        uint32_t get_block_height() const;
        bool have_subaccounts() const;
        amount get_dust_threshold() const;
        nlohmann::json get_spending_limits() const;
        bool is_spending_limits_decrease(const nlohmann::json& details);
        const network_parameters& get_network_parameters() const { return m_net_params; }

        void emit_notification(std::string event, nlohmann::json details);

        signer& get_signer() GDK_REQUIRES(m_mutex);
        const signer& get_signer() const GDK_REQUIRES(m_mutex);
        ga_pubkeys& get_ga_pubkeys() GDK_REQUIRES(m_mutex);
        ga_user_pubkeys& get_user_pubkeys() GDK_REQUIRES(m_mutex);
        ga_user_pubkeys& get_recovery_pubkeys() GDK_REQUIRES(m_mutex);
        bool has_recovery_pubkeys_subaccount(uint32_t subaccount);
        std::string get_service_xpub(uint32_t subaccount);
        std::string get_recovery_xpub(uint32_t subaccount);
        bool supports_low_r() const;
        liquid_support_level hw_liquid_support() const;

        std::vector<unsigned char> output_script_from_utxo(const nlohmann::json& utxo);

        ecdsa_sig_t sign_hash(gsl::span<const uint32_t> path, gsl::span<const unsigned char> hash);

        std::string asset_id_from_string(const std::string& tag)
        {
            return tag.empty() || tag == m_net_params.policy_asset() ? "btc" : tag;
        }

    private:
        void reset();

        bool is_connected() const;

        void register_user(locker_t& locker, const std::string& mnemonic, bool supports_csv);
        void register_user(locker_t& locker, const std::string& master_pub_key_hex,
            const std::string& master_chain_code_hex, const std::string& gait_path_hex, bool supports_csv);

        void authenticate(locker_t& locker, const std::string& sig_der_hex, const std::string& path_hex,
            const std::string& device_id, const nlohmann::json& hw_device) GDK_REQUIRES(m_mutex);
        void login(locker_t& locker, const std::string& mnemonic) GDK_REQUIRES(m_mutex);
        void set_notification_handler(locker_t& locker, GA_notification_handler handler, void* context)
            GDK_REQUIRES(m_mutex);

        void ack_system_message(locker_t& locker, const std::string& message_hash_hex, const std::string& sig_der_hex);

        nlohmann::json get_appearance() const;
        bool subaccount_allows_csv(uint32_t subaccount) const;
        const std::string& get_default_address_type(uint32_t) const;
        void push_appearance_to_server(locker_t& locker) const GDK_REQUIRES(m_mutex);
        void set_enabled_twofactor_methods(locker_t& locker, nlohmann::json& config) GDK_REQUIRES(m_mutex);
        void update_login_data(locker_t& locker, nlohmann::json& login_data, bool watch_only) GDK_REQUIRES(m_mutex);
        void update_fiat_rate(locker_t& locker, const std::string& rate_str) GDK_REQUIRES(m_mutex);
        void update_spending_limits(locker_t& locker, const nlohmann::json& limits) GDK_REQUIRES(m_mutex);
        nlohmann::json get_spending_limits(locker_t& locker) const GDK_REQUIRES(m_mutex);
        nlohmann::json get_subaccount(locker_t& locker, uint32_t subaccount) GDK_REQUIRES(m_mutex);
        nlohmann::json get_subaccount_balance_from_server(uint32_t subaccount, uint32_t num_confs);
        nlohmann::json convert_amount(locker_t& locker, const nlohmann::json& amount_json) const GDK_REQUIRES(m_mutex);
        nlohmann::json convert_fiat_cents(locker_t& locker, amount::value_type fiat_cents) const GDK_REQUIRES(m_mutex);
        nlohmann::json get_settings(locker_t& locker) GDK_REQUIRES(m_mutex);
        void unblind_utxo(nlohmann::json& utxo, const std::string& policy_asset);
        nlohmann::json cleanup_utxos(nlohmann::json& utxos, const std::string& policy_asset);

        autobahn::wamp_subscription subscribe(
            locker_t& locker, const std::string& topic, const autobahn::wamp_event_handler& callback);
        void call_notification_handler(locker_t& locker, nlohmann::json* details) GDK_REQUIRES(m_mutex);

        void on_new_transaction(locker_t& locker, nlohmann::json details) GDK_REQUIRES(m_mutex);
        void on_new_block(locker_t& locker, nlohmann::json details) GDK_REQUIRES(m_mutex);
        void on_new_fees(locker_t& locker, const nlohmann::json& details) GDK_REQUIRES(m_mutex);
        void change_settings_pricing_source(locker_t& locker, const std::string& currency, const std::string& exchange)
            GDK_REQUIRES(m_mutex);

        nlohmann::json insert_subaccount(locker_t& locker, uint32_t subaccount, const std::string& name,
            const std::string& receiving_id, const std::string& recovery_pub_key,
            const std::string& recovery_chain_code, const std::string& type, amount satoshi, bool has_txs,
            uint32_t required_ca) GDK_REQUIRES(m_mutex);

        void upload_confidential_addresses(locker_t& locker, uint32_t subaccount,
            std::vector<std::string> confidential_addresses) GDK_REQUIRES(m_mutex);

        std::pair<std::string, std::string> sign_challenge(locker_t& locker, const std::string& challenge)
            GDK_REQUIRES(m_mutex);

        nlohmann::json set_fee_estimates(locker_t& locker, const nlohmann::json& fee_estimates) GDK_REQUIRES(m_mutex);

        nlohmann::json refresh_http_data(const std::string& type, bool refresh);

        nlocktime_t get_upcoming_nlocktime();

        bool connect_with_tls() const;

        context_ptr tls_init_handler_impl(const std::string& host_name);

        template <typename T>
        std::enable_if_t<std::is_same<T, client>::value> set_tls_init_handler(const std::string& host_name);
        template <typename T>
        std::enable_if_t<std::is_same<T, client_tls>::value> set_tls_init_handler(const std::string& host_name);
        template <typename T> void make_client();
        template <typename T> void make_transport();

        template <typename T> bool is_transport_connected() const
        {
            const auto transport = boost::get<std::shared_ptr<T>>(m_transport);
            return transport != nullptr && transport->is_connected();
        }

        template <typename T> void disconnect_transport() const;

        template <typename T> bool ping() const
        {
            bool expect_pong = false;
            no_std_exception_escape([this, &expect_pong] {
                if (is_transport_connected<T>()) {
                    const auto transport = boost::get<std::shared_ptr<T>>(m_transport);
                    GDK_RUNTIME_ASSERT(transport != nullptr);
                    expect_pong = transport->ping(std::string{});
                }
            });
            return expect_pong;
        }

        template <typename T, typename U> bool set_socket_option(U option) const
        {
            bool ret = false;
            no_std_exception_escape(
                [this, &ret, option] { ret = boost::get<std::shared_ptr<T>>(m_transport)->set_socket_option(option); });
            return ret;
        }

        void set_socket_options();
        void start_ping_timer();
        void disconnect();
        void unsubscribe();

        template <typename F, typename... Args>
        void wamp_call(F&& body, const std::string& method_name, Args&&... args) const
        {
            constexpr uint8_t timeout = 10;
            autobahn::wamp_call_options call_options;
            call_options.set_timeout(std::chrono::seconds(timeout));
            auto fn = m_session->call(method_name, std::make_tuple(std::forward<Args>(args)...), call_options)
                          .then(boost::launch::async, std::forward<F>(body));
            for (;;) {
                const auto status = fn.wait_for(boost::chrono::seconds(timeout));
                if (status == boost::future_status::timeout && !is_connected()) {
                    throw timeout_error{};
                }
                if (status == boost::future_status::ready) {
                    break;
                }
            }
            fn.get();
        }

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
        mutable annotated_mutex m_mutex;
        const network_parameters m_net_params;
        std::string m_proxy;
        const bool m_use_tor;
        const bool m_has_network_proxy;

        boost::asio::io_context m_io;
        boost::variant<std::unique_ptr<client>, std::unique_ptr<client_tls>> m_client;
        transport_t m_transport;
        wamp_session_ptr m_session;
        std::vector<autobahn::wamp_subscription> m_subscriptions GDK_GUARDED_BY(m_mutex);
        heartbeat_t m_heartbeat_handler;
        ping_fail_t m_ping_fail_handler;

        event_loop_controller m_controller;
        boost::asio::deadline_timer m_ping_timer;

        network_control_context m_network_control;
        boost::asio::thread_pool m_pool{ 4 };

        GA_notification_handler m_notification_handler GDK_GUARDED_BY(m_mutex);
        void* m_notification_context GDK_PT_GUARDED_BY(m_mutex);

        nlohmann::json m_login_data GDK_GUARDED_BY(m_mutex);
        boost::optional<std::array<unsigned char, PBKDF2_HMAC_SHA512_LEN>> m_local_encryption_key GDK_GUARDED_BY(
            m_mutex);
        std::array<uint32_t, 32> m_gait_path GDK_GUARDED_BY(m_mutex);
        nlohmann::json m_limits_data GDK_GUARDED_BY(m_mutex);
        nlohmann::json m_twofactor_config GDK_GUARDED_BY(m_mutex);
        std::string m_mnemonic;
        amount::value_type m_min_fee_rate GDK_GUARDED_BY(m_mutex);
        std::string m_fiat_source GDK_GUARDED_BY(m_mutex);
        std::string m_fiat_rate GDK_GUARDED_BY(m_mutex);
        std::string m_fiat_currency GDK_GUARDED_BY(m_mutex);
        uint64_t m_earliest_block_time GDK_GUARDED_BY(m_mutex);

        nlohmann::json m_assets;

        std::map<uint32_t, nlohmann::json> m_subaccounts GDK_GUARDED_BY(m_mutex); // Includes 0 for main
        std::unique_ptr<ga_pubkeys> m_ga_pubkeys GDK_PT_GUARDED_BY(m_mutex);
        std::unique_ptr<ga_user_pubkeys> m_user_pubkeys GDK_PT_GUARDED_BY(m_mutex);
        std::unique_ptr<ga_user_pubkeys> m_recovery_pubkeys GDK_PT_GUARDED_BY(m_mutex);
        uint32_t m_next_subaccount GDK_GUARDED_BY(m_mutex);
        std::vector<uint32_t> m_fee_estimates GDK_GUARDED_BY(m_mutex);
        uint32_t m_block_height GDK_GUARDED_BY(m_mutex);
        std::unique_ptr<signer> m_signer GDK_PT_GUARDED_BY(m_mutex);

        uint32_t m_system_message_id; // Next system message
        uint32_t m_system_message_ack_id; // Currently returned message id to ack
        std::string m_system_message_ack; // Currently returned message to ack
        bool m_watch_only;
        bool m_is_locked;
        bool m_cert_pin_validated;
        logging_levels m_log_level;
        std::vector<std::string> m_tx_notifications;
        std::chrono::system_clock::time_point m_tx_last_notification;

        tx_list_caches m_tx_list_caches;

        std::shared_ptr<tor_controller> m_tor_ctrl;
        std::string m_last_tor_socks5;
        cache m_cache GDK_GUARDED_BY(m_mutex);
        const std::string m_user_agent;
    };

} // namespace sdk
} // namespace ga

#endif
