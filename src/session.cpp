#include <algorithm>
#include <chrono>
#include <mutex>
#include <random>
#include <string>
#include <vector>

#include "session.hpp"

#include "autobahn_wrapper.hpp"
#include "exception.hpp"
#include "ga_session.hpp"
#include "ga_tx.hpp"
#include "logging.hpp"

using namespace std::literals;

namespace ga {
namespace sdk {
    namespace {
        // We lock connection and disconnection, beyond that the caller is
        // expected to ensure that methods are only called on a connected
        // session/are serialised.
        static std::mutex session_impl_mutex;
        static std::mutex session_context_mutex;

        class exponential_backoff {
        public:
            exponential_backoff(std::chrono::seconds limit = 1200s)
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

            void set() { flag.first.set_value(); }
            std::future_status wait(std::chrono::seconds secs = 0s) const { return flag.second.wait_for(secs); }

            std::pair<std::promise<T>, std::future<T>> flag;
        };

    } // namespace

    struct session_context final {

        using flag_t = flag_type<void>;

        void reset_reconnect() { m_reconnect_flag = flag_t{}; }
        void set_reconnect() { m_reconnect_flag.set(); }
        bool reconnecting() const { return m_reconnect_flag.wait() != std::future_status::ready; }

        void reset_exit() { m_exit_flag = flag_t{}; }
        void set_exit() { m_exit_flag.set(); }
        bool retrying(std::chrono::seconds secs) const { return m_exit_flag.wait(secs) != std::future_status::ready; }

        void terminate_reconnect_thread()
        {
            set_exit();
            if (m_reconnect_thread.joinable()) {
                m_reconnect_thread.join();
            }
        }

        void destroy()
        {
            terminate_reconnect_thread();
            reset_reconnect();
            reset_exit();
        }

        std::thread m_reconnect_thread;
        flag_t m_reconnect_flag;
        flag_t m_exit_flag;
    };

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

    void session::connect(const std::string& name, const std::string& proxy, bool use_tor, bool debug)
    {
        exception_wrapper([&] {
            std::unique_lock<std::mutex> l{ session_impl_mutex };

            if (m_impl != nullptr) {
                if (m_impl->is_connected(name, proxy, use_tor)) {
                    return; // No-op
                }
                throw reconnect_error(); // Need to disconnect first
            }

            network_parameters net_params{ *network_parameters::get(name) };
            m_impl = std::make_unique<ga_session>(net_params, proxy, use_tor, debug);
            std::unique_lock<std::mutex> o{ session_context_mutex };
            m_session_context = std::make_unique<session_context>();
            m_impl->set_ping_fail_handler([this] {
                GDK_LOG_SEV(log_level::info) << "ping failure detected. reconnecting...";
                reconnect();
            });
            m_impl->set_heartbeat_timeout_handler([this](websocketpp::connection_hdl, const std::string&) {
                GDK_LOG_SEV(log_level::info) << "pong timeout detected. reconnecting...";
                reconnect();
            });
            m_impl->connect();
            m_impl->set_notification_handler(m_notification_handler, m_notification_context);
            m_session_context->set_reconnect();
        });
    }

    session::session() = default;
    session::~session() = default;

    void session::reconnect()
    {
        std::unique_lock<std::mutex> l{ session_context_mutex };
        if (!m_session_context) {
            GDK_LOG_SEV(log_level::info) << "null session context. backing off...";
            return;
        }
        if (m_session_context->reconnecting()) {
            GDK_LOG_SEV(log_level::info) << "reconnect in progress. backing off...";
            return;
        }

        m_session_context->destroy();
        m_session_context->m_reconnect_thread = std::thread([this] {
            GDK_LOG_SEV(log_level::info) << "reconnect thread " << std::this_thread::get_id() << " started.";
            exponential_backoff bo;
            uint32_t n = 0;
            for (;;) {
                const auto backoff_time = bo.backoff(n++);
                {
                    std::unique_lock<std::mutex> l{ session_impl_mutex };
                    nlohmann::json network_status = { { "connected", false }, { "elapsed", bo.elapsed().count() },
                        { "waiting", bo.waiting().count() }, { "limit", bo.limit_reached() } };
                    GDK_RUNTIME_ASSERT(m_impl != nullptr);
                    m_impl->emit_notification("network", network_status);
                }
                GDK_RUNTIME_ASSERT(m_session_context != nullptr);
                if (!m_session_context->retrying(backoff_time)) {
                    GDK_LOG_SEV(log_level::info)
                        << "reconnect thread " << std::this_thread::get_id() << " exiting on request.";
                    break;
                }

                std::unique_lock<std::mutex> l{ session_impl_mutex };
                GDK_RUNTIME_ASSERT(m_impl != nullptr);
                const bool result = m_impl->reconnect();
                if (result) {
                    GDK_RUNTIME_ASSERT(m_session_context != nullptr);
                    m_session_context->set_reconnect();
                    GDK_LOG_SEV(log_level::info)
                        << "reconnect thread " << std::this_thread::get_id() << " exiting on reconnect.";
                    break;
                }
            }
        });
    }

    void session::disconnect()
    {
        {
            std::unique_lock<std::mutex> l{ session_context_mutex };
            if (m_session_context) {
                m_session_context->destroy();
            }
            m_session_context.reset();
        }
        {
            std::unique_lock<std::mutex> l{ session_impl_mutex };
            m_impl.reset();
        }
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
        GDK_RUNTIME_ASSERT(m_session_context != nullptr);
        return exception_wrapper([&] { m_impl->login(mnemonic, password); });
    }

    void session::login_with_pin(const std::string& pin, const nlohmann::json& pin_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        GDK_RUNTIME_ASSERT(m_session_context != nullptr);
        return exception_wrapper([&] { m_impl->login_with_pin(pin, pin_data); });
    }

    void session::login_watch_only(const std::string& username, const std::string& password)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        GDK_RUNTIME_ASSERT(m_session_context != nullptr);
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

    nlohmann::json session::create_subaccount(const nlohmann::json& details, uint32_t subaccount, const xpub_t& xpub)
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

    nlohmann::json session::get_transactions(uint32_t subaccount, uint32_t page_id)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_transactions(subaccount, page_id); });
    }

    void session::set_notification_handler(GA_notification_handler handler, void* context)
    {
        GDK_RUNTIME_ASSERT(m_impl == nullptr);
        GDK_RUNTIME_ASSERT(m_session_context == nullptr);
        m_notification_handler = handler;
        m_notification_context = context;
    }

    nlohmann::json session::get_receive_address(uint32_t subaccount, const std::string& addr_type)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_receive_address(subaccount, addr_type); });
    }

    nlohmann::json session::get_balance(uint32_t subaccount, uint32_t num_confs)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_balance(subaccount, num_confs); });
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

    nlohmann::json session::get_unspent_outputs(uint32_t subaccount, uint32_t num_confs)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->get_unspent_outputs(subaccount, num_confs); });
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
        return exception_wrapper([&] {
            try {
                return create_ga_transaction(*this, m_impl->get_network_parameters(), details);
            } catch (const user_error& e) {
                return nlohmann::json({ { "error", e.what() } });
            }
        });
    }

    nlohmann::json session::sign_transaction(const nlohmann::json& details)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return sign_ga_transaction(*this, details); });
    }

    nlohmann::json session::send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        GDK_RUNTIME_ASSERT(json_get_value(details, "error").empty());
        GDK_RUNTIME_ASSERT_MSG(json_get_value(details, "user_signed", false), "Tx must be signed before sending");

        return exception_wrapper([&] { return m_impl->send_transaction(details, twofactor_data); });
    }

    std::string session::broadcast_transaction(const std::string& tx_hex)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return exception_wrapper([&] { return m_impl->broadcast_transaction(tx_hex); });
    }

    void session::send_nlocktimes()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        exception_wrapper([&] { m_impl->send_nlocktimes(); });
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

    nlohmann::json session::convert_amount_nocatch(const nlohmann::json& amount_json)
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->convert_amount(amount_json);
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

    signer& session::get_signer()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->get_signer(); // Note no exception_wrapper
    }

    ga_pubkeys& session::get_ga_pubkeys()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->get_ga_pubkeys(); // Note no exception_wrapper
    }

    ga_user_pubkeys& session::get_user_pubkeys()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->get_user_pubkeys(); // Note no exception_wrapper
    }

    ga_user_pubkeys& session::get_recovery_pubkeys()
    {
        GDK_RUNTIME_ASSERT(m_impl != nullptr);
        return m_impl->get_recovery_pubkeys(); // Note no exception_wrapper
    }

} // namespace sdk
} // namespace ga
