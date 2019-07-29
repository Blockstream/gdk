#include <algorithm>
#include <chrono>
#include <future>
#include <mutex>
#include <random>
#include <string>
#include <vector>

#include "session.hpp"

#include "autobahn_wrapper.hpp"
#include "exception.hpp"
#include "ga_session.hpp"
#include "logging.hpp"
#include "network_parameters.hpp"
#include "socks_client.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ga {
namespace sdk {
    namespace {
        // We lock connection and disconnection, beyond that the caller is
        // expected to ensure that methods are only called on a connected
        // session/are serialised.
        static std::mutex session_impl_mutex;
        static std::mutex network_control_context_mutex;

        static bool init_done = false;
        static nlohmann::json global_config;

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

    } // namespace

    class network_control_context final {
    public:
        using flag_t = flag_type<void>;

        network_control_context() = default;
        network_control_context(const network_control_context& context) = delete;
        network_control_context& operator=(const network_control_context& context) = delete;
        network_control_context(network_control_context&& context) = delete;
        network_control_context& operator=(network_control_context&& context) = delete;
        ~network_control_context() { stop_reconnect(); }

        void reset_reconnect() { m_reconnect_flag = flag_t{}; }
        void set_reconnect() { m_reconnect_flag.set(); }
        bool reconnecting() const { return m_reconnect_flag.wait() != std::future_status::ready; }

        void reset_exit() { m_exit_flag = flag_t{}; }
        void set_exit() { m_exit_flag.set(); }
        bool retrying(std::chrono::seconds secs) const { return m_exit_flag.wait(secs) != std::future_status::ready; }

        void set_enabled(bool v) { m_enabled = v; }
        bool is_enabled() const { return m_enabled; }

        template <class F> void reconnect(F&& fn) { start_reconnect(fn); }

        void stop_reconnect()
        {
            stop_reconnect_thread();
            reset_reconnect();
            reset_exit();
        }

    private:
        template <class F> void start_reconnect(F&& fn)
        {
            stop_reconnect();
            m_reconnect_thread = std::thread(fn);
        }

        void stop_reconnect_thread()
        {
            set_exit();
            if (m_reconnect_thread.joinable()) {
                m_reconnect_thread.join();
            }
        }

        std::thread m_reconnect_thread;
        flag_t m_reconnect_flag;
        flag_t m_exit_flag;
        bool m_enabled{ true };
    };

    int init(const nlohmann::json& config)
    {
        GDK_RUNTIME_ASSERT(config.is_object());
        GDK_RUNTIME_ASSERT(!init_done);

        global_config = config;

        GDK_VERIFY(wally_init(0));
        auto entropy = get_random_bytes<WALLY_SECP_RANDOMIZE_LEN>();
        GDK_VERIFY(wally_secp_randomize(entropy.data(), entropy.size()));
        wally_bzero(entropy.data(), entropy.size());

#if defined(__ANDROID__) and not defined(NDEBUG)
        start_android_std_outerr_bridge();
#endif
        init_done = true;

        return GA_OK;
    }

    const nlohmann::json& gdk_config() { return global_config; }

    static void log_exception(const char* preamble, const std::exception& e)
    {
        try {
            const auto what = e.what();
            GDK_LOG_SEV(log_level::debug) << preamble << what;
        } catch (const std::exception&) {
        }
    }

    template <typename F, typename... Args> auto session::exception_wrapper(F&& f, Args&&... args)
    {
        try {
            return f(std::forward<Args>(args)...);
        } catch (const autobahn::abort_error& e) {
            reconnect();
            throw reconnect_error();
        } catch (const login_error& e) {
            if (m_impl) {
                m_impl->on_failed_login();
            }
            std::rethrow_exception(std::current_exception());
        } catch (const autobahn::network_error& e) {
            reconnect();
            throw reconnect_error();
        } catch (const autobahn::no_transport_error& e) {
            reconnect();
            throw reconnect_error();
        } catch (const autobahn::protocol_error& e) {
            reconnect();
            throw reconnect_error();
        } catch (const autobahn::call_error& e) {
            std::pair<std::string, std::string> details;
            try {
                details = get_error_details(e);
                GDK_LOG_SEV(log_level::debug) << "server exception (" << details.first << "):" << details.second;
            } catch (const std::exception&) {
                log_exception("call error:", e);
            }
            if (details.first == "password") {
                // Server sends this response if the PIN is incorrect
                throw login_error(details.second);
            }
            std::rethrow_exception(std::current_exception());
        } catch (const assertion_error& e) {
            // Already logged by the assertion that failed
            std::rethrow_exception(std::current_exception());
        } catch (const user_error& e) {
            log_exception("user error:", e);
            std::rethrow_exception(std::current_exception());
        } catch (const reconnect_error& e) {
            std::rethrow_exception(std::current_exception());
        } catch (const timeout_error& e) {
            reconnect();
            throw reconnect_error();
        } catch (const websocketpp::exception& e) {
            reconnect();
            throw reconnect_error();
        } catch (const std::exception& e) {
            log_exception("uncaught exception:", e);
            std::rethrow_exception(std::current_exception());
        }
        __builtin_unreachable();
    }

    void session::connect(const nlohmann::json& net_params)
    {
        exception_wrapper([&] {
            {
                std::unique_lock<std::mutex> l{ session_impl_mutex };
                GDK_RUNTIME_ASSERT_MSG(init_done, "You must call GA_init first");

                if (m_impl != nullptr) {
                    if (m_impl->is_connected(net_params)) {
                        return; // No-op
                    }
                    throw reconnect_error(); // Need to disconnect first
                }

                m_impl = std::make_unique<ga_session>(net_params);
                m_impl->set_ping_fail_handler([this] {
                    GDK_LOG_SEV(log_level::info) << "ping failure detected. reconnecting...";
                    reconnect();
                });
                m_impl->set_heartbeat_timeout_handler([this](websocketpp::connection_hdl, const std::string&) {
                    GDK_LOG_SEV(log_level::info) << "pong timeout detected. reconnecting...";
                    reconnect();
                });
                m_impl->set_notification_handler(m_notification_handler, m_notification_context);
                m_impl->connect();
            }

            {
                std::unique_lock<std::mutex> o{ network_control_context_mutex };
                m_network_control_context = std::make_unique<network_control_context>();
                m_network_control_context->set_reconnect();
            }
        });
    }

    session::session() = default;
    session::~session() = default;

    void session::reconnect()
    {
        std::unique_lock<std::mutex> l{ network_control_context_mutex };
        if (!m_network_control_context) {
            GDK_LOG_SEV(log_level::info) << "null session context. backing off...";
            return;
        }

        if (m_network_control_context->reconnecting()) {
            GDK_LOG_SEV(log_level::info) << "reconnect in progress. backing off...";
            return;
        }

        if (!m_network_control_context->is_enabled()) {
            GDK_LOG_SEV(log_level::info) << "reconnect is disabled. backing off...";
            return;
        }

        m_network_control_context->reconnect([this] {
            const auto thread_id = std::this_thread::get_id();

            GDK_LOG_SEV(log_level::info) << "reconnect thread " << std::hex << thread_id << " started.";
            exponential_backoff bo;
            uint32_t n = 0;
            for (;;) {
                const auto backoff_time = bo.backoff(n++);
                {
                    nlohmann::json network_status = { { "connected", false }, { "elapsed", bo.elapsed().count() },
                        { "waiting", bo.waiting().count() }, { "limit", bo.limit_reached() } };
                    std::unique_lock<std::mutex> l{ session_impl_mutex };
                    if (m_impl) {
                        m_impl->emit_notification("network", network_status);
                    }
                }

                if (m_network_control_context == nullptr || !m_network_control_context->retrying(backoff_time)) {
                    GDK_LOG_SEV(log_level::info)
                        << "reconnect thread " << std::hex << thread_id << " exiting on request.";
                    break;
                }

                bool result = false;
                {
                    std::unique_lock<std::mutex> l{ session_impl_mutex };
                    if (m_impl == nullptr) {
                        break;
                    }
                    result = m_impl->reconnect();
                }
                if (result) {
                    if (m_network_control_context != nullptr) {
                        m_network_control_context->set_reconnect();
                        GDK_LOG_SEV(log_level::info)
                            << "reconnect thread " << std::hex << thread_id << " exiting on reconnect.";
                    } else {
                        GDK_LOG_SEV(log_level::info)
                            << "reconnect thread " << std::hex << thread_id << " exiting on null context.";
                    }
                    break;
                }
            }
        });
    }

    void session::disconnect()
    {
        {
            std::unique_lock<std::mutex> l{ network_control_context_mutex };
            m_network_control_context.reset();
        }
        {
            std::unique_lock<std::mutex> l{ session_impl_mutex };
            m_impl.reset();
        }
    }

    void session::reconnect_hint(const nlohmann::json& hint)
    {
        exception_wrapper([&] {
            {
                // we have an hint for Tor
                if (hint.contains("tor_sleep_hint")) {
                    std::lock_guard<std::mutex> l{ session_impl_mutex };

                    if (m_impl != nullptr) {
                        m_impl->tor_sleep_hint(hint["tor_sleep_hint"]);
                    }
                }

                // no connection-level hint, exit here
                if (!hint.contains("hint")) {
                    return;
                }

                std::unique_lock<std::mutex> l{ network_control_context_mutex };
                if (!m_network_control_context) {
                    return;
                }

                const std::string option = hint["hint"];
                GDK_RUNTIME_ASSERT(option == "now" || option == "disable" || option == "start");

                if (option != "start" && !m_network_control_context->reconnecting()) {
                    GDK_LOG_SEV(log_level::info) << "no reconnect in progress. ignoring.";
                    return;
                }

                m_network_control_context->stop_reconnect();
                m_network_control_context->set_enabled(option != "disable");
                m_network_control_context->set_reconnect();
            }
            reconnect();
        });
    }

    bool session::check_proxy_connectivity(const nlohmann::json& params)
    {
        boost::asio::io_context io;
        boost::beast::tcp_stream stream{ boost::asio::make_strand(io) };
        stream.expires_after(5s);

        const auto net_params = network_parameters{ network_parameters::get(params.at("name")) };
        const bool use_tor = params.value("use_tor", false);
        const auto server = net_params.get_connection_string(use_tor);
        const std::string proxy = params.at("proxy");

        GDK_LOG_SEV(log_level::info) << "attempting connection to " << server;

        auto client = std::make_shared<socks_client>(io, stream);
        GDK_RUNTIME_ASSERT(client != nullptr);

        auto result = client->run(server, proxy);
        io.run();

        try {
            result.get();
            client->shutdown();
            return true;
        } catch (const std::exception&) {
            throw;
        }

        __builtin_unreachable();
    }

    std::string session::get_tor_socks5()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_tor_socks5(); });
    }

    nlohmann::json session::http_get(const nlohmann::json& params)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->http_get(params); });
    }

    nlohmann::json session::refresh_assets(const nlohmann::json& params)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->refresh_assets(params); });
    }

    nlohmann::json session::validate_asset_domain_name(const nlohmann::json& params)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->validate_asset_domain_name(params); });
    }

    void session::register_user(const std::string& mnemonic, bool supports_csv)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->register_user(mnemonic, supports_csv); });
    }

    void session::register_user(const std::string& master_pub_key_hex, const std::string& master_chain_code_hex,
        const std::string& gait_path_hex, bool supports_csv)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper(
            [&] { m_impl->register_user(master_pub_key_hex, master_chain_code_hex, gait_path_hex, supports_csv); });
    }

    std::string session::get_challenge(const std::string& address)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_challenge(address); });
    }

    void session::authenticate(const std::string& sig_der_hex, const std::string& path_hex,
        const std::string& device_id, const nlohmann::json& hw_device)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->authenticate(sig_der_hex, path_hex, device_id, hw_device); });
    }

    void session::register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->register_subaccount_xpubs(bip32_xpubs); });
    }

    void session::login(const std::string& mnemonic, const std::string& password)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        GDK_RUNTIME_ASSERT(m_network_control_context != nullptr);
        return exception_wrapper([&] { m_impl->login(mnemonic, password); });
    }

    void session::login_with_pin(const std::string& pin, const nlohmann::json& pin_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        GDK_RUNTIME_ASSERT(m_network_control_context != nullptr);
        return exception_wrapper([&] { m_impl->login_with_pin(pin, pin_data); });
    }

    void session::login_watch_only(const std::string& username, const std::string& password)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        GDK_RUNTIME_ASSERT(m_network_control_context != nullptr);
        return exception_wrapper([&] { m_impl->login_watch_only(username, password); });
    }

    bool session::set_watch_only(const std::string& username, const std::string& password)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->set_watch_only(username, password); });
    }

    std::string session::get_watch_only_username()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_watch_only_username(); });
    }

    bool session::remove_account(const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->remove_account(twofactor_data); });
    }

    nlohmann::json session::create_subaccount(const nlohmann::json& details)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->create_subaccount(details); });
    }

    nlohmann::json session::create_subaccount(
        const nlohmann::json& details, uint32_t subaccount, const std::string& xpub)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->create_subaccount(details, subaccount, xpub); });
    }

    uint32_t session::get_next_subaccount()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_next_subaccount(); });
    }

    nlohmann::json session::get_subaccounts()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_subaccounts(); });
    }

    nlohmann::json session::get_subaccount(uint32_t subaccount)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_subaccount(subaccount); });
    }

    void session::rename_subaccount(uint32_t subaccount, const std::string& new_name)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->rename_subaccount(subaccount, new_name); });
    }

    nlohmann::json session::get_settings()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_settings(); });
    }

    void session::change_settings(const nlohmann::json& settings)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { m_impl->change_settings(settings); });
    }

    void session::change_settings_limits(const nlohmann::json& limit_details, const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { m_impl->change_settings_limits(limit_details, twofactor_data); });
    }

    nlohmann::json session::get_transactions(const nlohmann::json& details)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_transactions(details); });
    }

    void session::set_notification_handler(GA_notification_handler handler, void* context)
    {
        GDK_RUNTIME_ASSERT(m_impl == nullptr);
        GDK_RUNTIME_ASSERT(m_network_control_context == nullptr);
        m_notification_handler = handler;
        m_notification_context = context;
    }

    nlohmann::json session::get_receive_address(const nlohmann::json& details)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_receive_address(details); });
    }

    std::string session::get_blinding_key_for_script(const std::string& script_hex)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_blinding_key_for_script(script_hex); });
    }

    std::string session::blind_address(const std::string& unblinded_addr, const std::string& blinding_key_hex)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->blind_address(unblinded_addr, blinding_key_hex); });
    }

    nlohmann::json session::get_balance(const nlohmann::json& details)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_balance(details); });
    }

    nlohmann::json session::get_available_currencies()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_available_currencies(); });
    }

    nlohmann::json session::get_hw_device()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_hw_device(); });
    }

    bool session::is_rbf_enabled()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->is_rbf_enabled(); });
    }

    bool session::is_watch_only()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->is_watch_only(); });
    }

    bool session::is_liquid()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_network_parameters().liquid(); });
    }

    nlohmann::json session::get_twofactor_config(bool reset_cached)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_twofactor_config(reset_cached); });
    }

    std::vector<std::string> session::get_all_twofactor_methods()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_all_twofactor_methods(); });
    }

    std::vector<std::string> session::get_enabled_twofactor_methods()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_enabled_twofactor_methods(); });
    }

    void session::set_email(const std::string& email, const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->set_email(email, twofactor_data); });
    }

    void session::activate_email(const std::string& code)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->activate_email(code); });
    }

    void session::init_enable_twofactor(
        const std::string& method, const std::string& data, const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->init_enable_twofactor(method, data, twofactor_data); });
    }

    void session::enable_twofactor(const std::string& method, const std::string& code)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->enable_twofactor(method, code); });
    }

    void session::enable_gauth(const std::string& code, const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->enable_gauth(code, twofactor_data); });
    }

    void session::disable_twofactor(const std::string& method, const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->disable_twofactor(method, twofactor_data); });
    }

    void session::auth_handler_request_code(
        const std::string& method, const std::string& action, const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->auth_handler_request_code(method, action, twofactor_data); });
    }

    nlohmann::json session::reset_twofactor(const std::string& email)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->reset_twofactor(email); });
    }

    nlohmann::json session::confirm_twofactor_reset(
        const std::string& email, bool is_dispute, const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->confirm_twofactor_reset(email, is_dispute, twofactor_data); });
    }

    nlohmann::json session::cancel_twofactor_reset(const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->cancel_twofactor_reset(twofactor_data); });
    }

    nlohmann::json session::set_pin(const std::string& mnemonic, const std::string& pin, const std::string& device_id)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->set_pin(mnemonic, pin, device_id); });
    }

    nlohmann::json session::get_unspent_outputs(const nlohmann::json& details)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_unspent_outputs(details); });
    }

    nlohmann::json session::get_blinded_scripts(const nlohmann::json& details)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_blinded_scripts(details); });
    }

    bool session::has_blinding_nonce(const std::string& pubkey, const std::string& script)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->has_blinding_nonce(pubkey, script); });
    }

    void session::set_blinding_nonce(const std::string& pubkey, const std::string& script, const std::string& nonce)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->set_blinding_nonce(pubkey, script, nonce); });
    }

    nlohmann::json session::get_unspent_outputs_for_private_key(
        const std::string& private_key, const std::string& password, uint32_t unused)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper(
            [&] { return m_impl->get_unspent_outputs_for_private_key(private_key, password, unused); });
    }

    nlohmann::json session::create_transaction(const nlohmann::json& details)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->create_transaction(details); });
    }

    nlohmann::json session::sign_transaction(const nlohmann::json& details)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->sign_transaction(details); });
    }

    nlohmann::json session::send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->send_transaction(details, twofactor_data); });
    }

    std::string session::broadcast_transaction(const std::string& tx_hex)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->broadcast_transaction(tx_hex); });
    }

    void session::sign_input(
        const wally_tx_ptr& tx, uint32_t index, const nlohmann::json& u, const std::string& der_hex)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->sign_input(tx, index, u, der_hex); });
    }

    void session::send_nlocktimes()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->send_nlocktimes(); });
    }

    nlohmann::json session::get_expired_deposits(const nlohmann::json& deposit_details)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_expired_deposits(deposit_details); });
    }

    void session::set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->set_csvtime(locktime_details, twofactor_data); });
    }

    void session::set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->set_nlocktime(locktime_details, twofactor_data); });
    }

    void session::set_transaction_memo(
        const std::string& txhash_hex, const std::string& memo, const std::string& memo_type)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->set_transaction_memo(txhash_hex, memo, memo_type); });
    }

    nlohmann::json session::get_transaction_details(const std::string& txhash_hex)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_transaction_details(txhash_hex); });
    }

    std::string session::get_system_message()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_system_message(); });
    }

    nlohmann::json session::get_fee_estimates()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_fee_estimates(); });
    }

    std::string session::get_mnemonic_passphrase(const std::string& password)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_mnemonic_passphrase(password); });
    }

    std::pair<std::string, std::vector<uint32_t>> session::get_system_message_info(const std::string& system_message)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->get_system_message_info(system_message); // Note no exception wrapper
    }

    void session::ack_system_message(const std::string& system_message)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->ack_system_message(system_message); });
    }

    void session::ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->ack_system_message(message_hash_hex, sig_der_hex); });
    }

    nlohmann::json session::convert_amount(const nlohmann::json& amount_json)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->convert_amount(amount_json); });
    }

    nlohmann::json session::encrypt(const nlohmann::json& input_json)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->encrypt(input_json); });
    }

    nlohmann::json session::decrypt(const nlohmann::json& input_json)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->decrypt(input_json); });
    }

    amount session::get_min_fee_rate() const
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->get_min_fee_rate(); // Note no exception_wrapper
    }

    amount session::get_default_fee_rate() const
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->get_default_fee_rate(); // Note no exception_wrapper
    }

    bool session::have_subaccounts() const
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->have_subaccounts(); // Note no exception_wrapper
    }
    uint32_t session::get_block_height() const
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->get_block_height(); // Note no exception_wrapper
    }

    amount session::get_dust_threshold() const
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->get_dust_threshold(); // Note no exception_wrapper
    }

    nlohmann::json session::get_spending_limits() const
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->get_spending_limits(); // Note no exception_wrapper
    }

    bool session::is_spending_limits_decrease(const nlohmann::json& limit_details)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->is_spending_limits_decrease(limit_details); // Note no exception_wrapper
    }

    const network_parameters& session::get_network_parameters() const
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->get_network_parameters(); // Note no exception_wrapper
    }

} // namespace sdk
} // namespace ga
