#ifndef GDK_GA_SESSION_HPP
#define GDK_GA_SESSION_HPP
#pragma once

#include <array>
#include <chrono>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

#include "amount.hpp"
#include "autobahn_wrapper.hpp"
#include "boost_wrapper.hpp"
#include "logging.hpp"
#include "signer.hpp"
#include "tx_list_cache.hpp"
#include "xpub_hdkey.hpp"

namespace ga {
namespace sdk {
    enum class logging_levels : uint32_t;

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

    struct event_loop_controller {
        explicit event_loop_controller(boost::asio::io_service& io);

        void reset();

        std::thread m_run_thread;
        std::unique_ptr<boost::asio::io_service::work> m_work_guard;
    };

    class ga_session final {
    public:
        using transport_t = boost::variant<std::shared_ptr<transport>, std::shared_ptr<transport_tls>>;
        using locker_t = std::unique_lock<std::mutex>;
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
        bool reconnect();
        bool is_connected(const nlohmann::json& net_params);

        void set_heartbeat_timeout_handler(heartbeat_t handler);
        void set_ping_fail_handler(ping_fail_t handler);

        nlohmann::json http_get(const nlohmann::json& params);
        nlohmann::json refresh_assets();
        nlohmann::json validate_asset_domain_name(const nlohmann::json& params);

        void register_user(const std::string& mnemonic, bool supports_csv);
        void register_user(const std::string& master_pub_key_hex, const std::string& master_chain_code_hex,
            const std::string& gait_path_hex, bool supports_csv);

        std::string get_challenge(const std::string& address);
        void authenticate(const std::string& sig_der_hex, const std::string& path_hex, const std::string& device_id,
            const nlohmann::json& hw_device = nlohmann::json());
        void register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs);

        void login(const std::string& mnemonic);
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
        void rename_subaccount(uint32_t subaccount, const std::string& new_name);
        uint32_t get_next_subaccount();
        nlohmann::json create_subaccount(const nlohmann::json& details);
        nlohmann::json create_subaccount(const nlohmann::json& details, uint32_t subaccount, const xpub_t& xpub);
        nlohmann::json get_receive_address(uint32_t subaccount, const std::string& addr_type_);
        nlohmann::json get_receive_address(const nlohmann::json& details);
        nlohmann::json get_balance(const nlohmann::json& details);
        nlohmann::json get_available_currencies() const;
        nlohmann::json get_hw_device() const;
        bool is_rbf_enabled() const;
        bool is_watch_only() const;

        nlohmann::json get_twofactor_config(bool reset_cached);
        nlohmann::json get_twofactor_config(locker_t& locker, bool reset_cached = false);
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

        nlohmann::json get_unspent_outputs(const nlohmann::json& details);
        nlohmann::json get_unspent_outputs_for_private_key(
            const std::string& private_key, const std::string& password, uint32_t unused);
        nlohmann::json get_transaction_details(const std::string& txhash) const;

        nlohmann::json create_transaction(const nlohmann::json& details);
        nlohmann::json sign_transaction(const nlohmann::json& details);
        nlohmann::json send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data);
        std::string broadcast_transaction(const std::string& tx_hex);

        void sign_input(const wally_tx_ptr& tx, uint32_t index, const nlohmann::json& u, const std::string& der_hex);

        void send_nlocktimes();
        nlohmann::json get_expired_deposits(const nlohmann::json& deposit_details);
        void set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data);
        void set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data);

        void set_transaction_memo(const std::string& txhash_hex, const std::string& memo, const std::string& memo_type);

        void change_settings_pricing_source(const std::string& currency, const std::string& exchange);

        nlohmann::json get_fee_estimates();

        std::string get_mnemonic_passphrase(const std::string& password);

        std::string get_system_message();
        std::pair<std::string, std::vector<uint32_t>> get_system_message_info(const std::string& message);
        void ack_system_message(const std::string& message);
        void ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex);

        nlohmann::json convert_amount(const nlohmann::json& amount_json) const;

        nlohmann::json encrypt(const nlohmann::json& input_json) const;
        nlohmann::json decrypt(const nlohmann::json& input_json) const;

        amount get_min_fee_rate() const;
        amount get_default_fee_rate() const;
        uint32_t get_block_height() const;
        bool have_subaccounts() const;
        amount get_dust_threshold() const;
        nlohmann::json get_spending_limits() const;
        bool is_spending_limits_decrease(const nlohmann::json& details);
        const network_parameters& get_network_parameters() const { return m_net_params; }

        void emit_notification(std::string event, nlohmann::json details);

        signer& get_signer();
        ga_pubkeys& get_ga_pubkeys();
        ga_user_pubkeys& get_user_pubkeys();
        ga_user_pubkeys& get_recovery_pubkeys();

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
            const std::string& device_id, const nlohmann::json& hw_device);
        void set_notification_handler(locker_t& locker, GA_notification_handler handler, void* context);

        void ack_system_message(locker_t& locker, const std::string& message_hash_hex, const std::string& sig_der_hex);

        nlohmann::json get_appearance() const;
        const std::string& get_default_address_type() const;
        void push_appearance_to_server(locker_t& locker) const;
        void set_enabled_twofactor_methods(locker_t& locker, nlohmann::json& config);
        void update_login_data(locker_t& locker, nlohmann::json& login_data, bool watch_only);
        void update_fiat_rate(locker_t& locker, const std::string& rate_str);
        void update_spending_limits(locker_t& locker, const nlohmann::json& limits);
        nlohmann::json get_spending_limits(locker_t& locker) const;
        nlohmann::json get_subaccount(locker_t& locker, uint32_t subaccount);
        nlohmann::json get_subaccount_balance_from_server(
            ga_session::locker_t& locker, uint32_t subaccount, uint32_t num_confs);
        nlohmann::json convert_amount(locker_t& locker, const nlohmann::json& amount_json) const;
        nlohmann::json convert_fiat_cents(locker_t& locker, amount::value_type fiat_cents) const;
        nlohmann::json get_settings(locker_t& locker);

        autobahn::wamp_subscription subscribe(
            locker_t& locker, const std::string& topic, const autobahn::wamp_event_handler& callback);
        void call_notification_handler(locker_t& locker, nlohmann::json* details);

        void on_new_transaction(locker_t& locker, nlohmann::json details);
        void on_new_block(locker_t& locker, nlohmann::json details);
        void on_new_fees(locker_t& locker, const nlohmann::json& details);
        void change_settings_pricing_source(locker_t& locker, const std::string& currency, const std::string& exchange);

        nlohmann::json insert_subaccount(locker_t& locker, uint32_t subaccount, const std::string& name,
            const std::string& receiving_id, const std::string& recovery_pub_key,
            const std::string& recovery_chain_code, const std::string& type, amount satoshi, bool has_txs);

        std::pair<std::string, std::string> sign_challenge(locker_t& locker, const std::string& challenge);

        nlohmann::json set_fee_estimates(locker_t& locker, const nlohmann::json& fee_estimates);

        nlohmann::json refresh_assets(locker_t& locker);

        nlocktime_t get_upcoming_nlocktime() const;

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

        void disconnect();
        void unsubscribe();

        template <typename F, typename... Args>
        void wamp_call(F&& body, const std::string& method_name, Args&&... args) const
        {
            constexpr uint8_t timeout = 10;
            autobahn::wamp_call_options call_options;
            call_options.set_timeout(std::chrono::seconds(timeout));
            auto fn = m_session->call(method_name, std::make_tuple(std::forward<Args>(args)...), call_options)
                          .then(std::forward<F>(body));
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

        template <typename F> void no_std_exception_escape(F&& fn) const
        {
            try {
                fn();
            } catch (const std::exception& e) {
                try {
                    const auto what = e.what();
                    GDK_LOG_SEV(log_level::debug) << "ignoring exception:" << what;
                } catch (const std::exception&) {
                }
            }
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
        mutable std::mutex m_mutex;
        const network_parameters m_net_params;
        std::string m_proxy;
        const bool m_use_tor;

        boost::asio::io_context m_io;
        boost::variant<std::unique_ptr<client>, std::unique_ptr<client_tls>> m_client;
        transport_t m_transport;
        wamp_session_ptr m_session;
        std::vector<autobahn::wamp_subscription> m_subscriptions;
        heartbeat_t m_heartbeat_handler;
        ping_fail_t m_ping_fail_handler;

        event_loop_controller m_controller;
        boost::asio::deadline_timer m_ping_timer;

        GA_notification_handler m_notification_handler;
        void* m_notification_context;

        nlohmann::json m_login_data;
        std::vector<unsigned char> m_local_encryption_password;
        std::array<uint32_t, 32> m_gait_path;
        nlohmann::json m_limits_data;
        nlohmann::json m_twofactor_config;
        std::string m_mnemonic;
        amount::value_type m_min_fee_rate;
        std::string m_fiat_source;
        std::string m_fiat_rate;
        std::string m_fiat_currency;
        uint64_t m_earliest_block_time;

        nlohmann::json m_assets;

        std::map<uint32_t, nlohmann::json> m_subaccounts; // Includes 0 for main
        std::unique_ptr<ga_pubkeys> m_ga_pubkeys;
        std::unique_ptr<ga_user_pubkeys> m_user_pubkeys;
        std::unique_ptr<ga_user_pubkeys> m_recovery_pubkeys;
        uint32_t m_next_subaccount;
        std::vector<uint32_t> m_fee_estimates;
        uint32_t m_block_height;
        std::unique_ptr<signer> m_signer;

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

        std::vector<nlohmann::json> get_transactions(uint32_t subaccount, uint32_t page_id);
        static std::weak_ptr<tor_controller> s_tor_ctrl;
        std::shared_ptr<tor_controller> m_tor_ctrl;
    };

} // namespace sdk
} // namespace ga

#endif
