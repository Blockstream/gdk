#include <algorithm>
#include <chrono>
#include <future>
#include <mutex>
#include <random>
#include <string>
#include <vector>

#include "session.hpp"

#include "amount.hpp"
#include "autobahn_wrapper.hpp"
#include "exception.hpp"
#include "ga_rust.hpp"
#include "ga_session.hpp"
#include "logging.hpp"
#include "network_parameters.hpp"
#include "signer.hpp"
#include "socks_client.hpp"
#include "utils.hpp"

using namespace std::literals;

namespace ga {
namespace sdk {
    namespace {

        static std::atomic_bool init_done{ false };
        static nlohmann::json global_config;
        static auto global_log_level = log_level::severity_level::fatal;

        static void log_exception(const char* preamble, const std::exception& e)
        {
            try {
                const auto what = e.what();
                GDK_LOG_SEV(log_level::debug) << preamble << what;
            } catch (const std::exception&) {
            }
        }
    } // namespace

    int init(const nlohmann::json& config)
    {
        GDK_RUNTIME_ASSERT(config.is_object());
        GDK_RUNTIME_ASSERT(!json_get_value(config, "datadir").empty());
        GDK_RUNTIME_ASSERT(!init_done);

        global_config = config;
        if (!global_config.contains("tordir")) {
            const std::string datadir = global_config["datadir"];
            global_config.emplace("tordir", datadir + "/tor");
        }
        if (!global_config.contains("log_level")) {
            global_config.emplace("log_level", "none");
        }
        if (!global_config.contains("registrydir")) {
            const std::string datadir = global_config["datadir"];
            global_config.emplace("registrydir", datadir + "/registry");
        }

        // Set up logging. Default to fatal logging, effectively 'none',
        // since we don't use fatal severity for logging.
        const std::string level = global_config["log_level"];
        if (level == "debug") {
            global_log_level = log_level::severity_level::debug;
        } else if (level == "info") {
            global_log_level = log_level::severity_level::info;
        } else if (level == "warn") {
            global_log_level = log_level::severity_level::warning;
        } else if (level == "error") {
            global_log_level = log_level::severity_level::error;
        }
        boost::log::core::get()->set_filter(log_level::severity >= global_log_level);

        GDK_VERIFY(wally_init(0));
        auto entropy = get_random_bytes<WALLY_SECP_RANDOMIZE_LEN>();
        GDK_VERIFY(wally_secp_randomize(entropy.data(), entropy.size()));
        wally_bzero(entropy.data(), entropy.size());

#if defined(__ANDROID__) and not defined(NDEBUG)
        start_android_std_outerr_bridge();
#endif

        init_rust(global_config);
        init_done = true;

        return GA_OK;
    }

    const nlohmann::json& gdk_config()
    {
        GDK_RUNTIME_ASSERT(init_done);
        return global_config;
    }

    void session::exception_handler(std::exception_ptr ex_p)
    {
        try {
            std::rethrow_exception(ex_p);
        } catch (const autobahn::abort_error& e) {
            signal_reconnect_and_throw();
        } catch (const login_error& e) {
            std::rethrow_exception(ex_p);
        } catch (const autobahn::network_error& e) {
            signal_reconnect_and_throw();
        } catch (const autobahn::no_transport_error& e) {
            signal_reconnect_and_throw();
        } catch (const autobahn::protocol_error& e) {
            signal_reconnect_and_throw();
        } catch (const autobahn::call_error& e) {
            std::pair<std::string, std::string> details;
            try {
                details = remap_ga_server_error(get_error_details(e));
                GDK_LOG_SEV(log_level::debug) << "server exception (" << details.first << "):" << details.second;
            } catch (const std::exception&) {
                log_exception("call error:", e);
            }
            if (details.first == "password") {
                // Server sends this response if the PIN is incorrect
                throw login_error(details.second);
            }
            if (!details.second.empty()) {
                throw user_error(details.second);
            }
            std::rethrow_exception(ex_p);
        } catch (const assertion_error& e) {
            // Already logged by the assertion that failed
            std::rethrow_exception(ex_p);
        } catch (const user_error& e) {
            log_exception("user error:", e);
            std::rethrow_exception(ex_p);
        } catch (const reconnect_error& e) {
            std::rethrow_exception(ex_p);
        } catch (const timeout_error& e) {
            signal_reconnect_and_throw();
        } catch (const websocketpp::exception& e) {
            signal_reconnect_and_throw();
        } catch (const std::exception& e) {
            log_exception("uncaught exception:", e);
            std::rethrow_exception(ex_p);
        }
    }

    template <typename F, typename... Args> auto session::exception_wrapper(F&& f, Args&&... args)
    {
        try {
            return f(std::forward<Args>(args)...);
        } catch (...) {
            exception_handler(std::current_exception());
        }
        __builtin_unreachable();
    }

    void session::connect(const nlohmann::json& net_params)
    {
        try {
            GDK_RUNTIME_ASSERT_MSG(init_done, "You must call GA_init first");

            locker_t locker(m_mutex);
            GDK_RUNTIME_ASSERT_MSG(!m_impl, "session already connected");

            auto impl = session_impl::create(net_params);
            impl->set_notification_handler(m_notification_handler, m_notification_context);
            impl->connect();
            m_impl = impl;
        } catch (const std::exception& ex) {
            log_exception("exception on connect:", ex);
            std::rethrow_exception(std::current_exception());
        }
    }

    session::session()
        : m_notification_handler(nullptr)
        , m_notification_context(nullptr)
    {
    }

    session::~session()
    {
        no_std_exception_escape([this]() {
            impl_ptr p;
            p.swap(m_impl); // Ensure the session_impl is deleted in this block
            if (p) {
                const bool is_electrum = p->get_network_parameters().is_electrum();
                GDK_LOG_SEV(log_level::info)
                    << "destroying " << (is_electrum ? "single" : "multi") << "sig session " << (void*)this;
                p->disconnect();
            }
        });
    }

    void session::signal_reconnect_and_throw()
    {
        auto p = get_impl();
        if (!p) {
            GDK_LOG_SEV(log_level::info) << "null session context. backing off...";
            return;
        }

        p->reconnect();
        throw reconnect_error();
    }

    void session::reconnect_hint(const nlohmann::json& hint)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->reconnect_hint(hint);
        });
    }

    nlohmann::json session::get_proxy_settings()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_proxy_settings();
        });
    }

    nlohmann::json session::http_request(const nlohmann::json& params)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->http_request(params);
        });
    }

    void session::refresh_assets(const nlohmann::json& params)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->refresh_assets(params);
        });
    }

    nlohmann::json session::get_assets(const nlohmann::json& params)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_assets(params);
        });
    }

    nlohmann::json session::validate_asset_domain_name(const nlohmann::json& params)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->validate_asset_domain_name(params);
        });
    }

    bool session::set_wo_credentials(const std::string& username, const std::string& password)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->set_wo_credentials(username, password);
        });
    }

    std::string session::get_wo_username()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_wo_username();
        });
    }

    void session::rename_subaccount(uint32_t subaccount, const std::string& new_name)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->rename_subaccount(subaccount, new_name);
        });
    }

    nlohmann::json session::get_settings()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_settings();
        });
    }

    void session::set_notification_handler(GA_notification_handler handler, void* context)
    {
        auto p = get_impl();
        if (!p) {
            // Setting or disabling notifications before connect()
            GDK_RUNTIME_ASSERT(handler || !context);
            m_notification_handler = handler;
            m_notification_context = context;
        } else {
            // Already connected.
            // Only a null handler can be set; this disables notifications
            // for the remainder of the sessions lifetime. This allows handler
            // references for wrapped languages to be dropped safely
            GDK_RUNTIME_ASSERT(!handler && !context);
            p->disable_notifications();
        }
    }

    nlohmann::json session::get_available_currencies()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_available_currencies();
        });
    }

    nlohmann::json session::get_twofactor_config(bool reset_cached)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_twofactor_config(reset_cached);
        });
    }

    nlohmann::json session::encrypt_with_pin(const nlohmann::json& details)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->encrypt_with_pin(details);
        });
    }

    nlohmann::json session::decrypt_with_pin(const nlohmann::json& details)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->decrypt_with_pin(details);
        });
    }

    void session::disable_all_pin_logins()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->disable_all_pin_logins();
        });
    }

    nlohmann::json session::get_unspent_outputs_for_private_key(
        const std::string& private_key, const std::string& password, uint32_t unused)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_unspent_outputs_for_private_key(private_key, password, unused);
        });
    }

    std::string session::broadcast_transaction(const std::string& tx_hex)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->broadcast_transaction(tx_hex);
        });
    }

    void session::send_nlocktimes()
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->send_nlocktimes();
        });
    }

    void session::set_transaction_memo(const std::string& txhash_hex, const std::string& memo)
    {
        exception_wrapper([&] {
            auto p = get_nonnull_impl();
            p->set_transaction_memo(txhash_hex, memo);
        });
    }

    nlohmann::json session::get_transaction_details(const std::string& txhash_hex)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_transaction_details(txhash_hex);
        });
    }

    std::string session::get_system_message()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_system_message();
        });
    }

    nlohmann::json session::get_fee_estimates()
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->get_fee_estimates();
        });
    }

    nlohmann::json session::convert_amount(const nlohmann::json& amount_json)
    {
        return exception_wrapper([&] {
            auto p = get_impl();
            if (p) {
                return p->convert_amount(amount_json);
            }
            // The session is not connected. Conversion to fiat will
            // be attempted using any provided fallback fiat values.
            return amount::convert(amount_json, std::string(), std::string());
        });
    }

    const network_parameters& session::get_network_parameters() const
    {
        auto p = get_nonnull_impl();
        return p->get_network_parameters(); // Note no exception_wrapper
    }

    nlohmann::json session::gl_call(const char* method, const nlohmann::json& params)
    {
        return exception_wrapper([&] {
            auto p = get_nonnull_impl();
            return p->gl_call(method, params);
        });
    }

    session::impl_ptr session::get_nonnull_impl() const
    {
        auto impl = get_impl();
        GDK_RUNTIME_ASSERT(impl != nullptr);
        return impl;
    }

    session::impl_ptr session::get_impl() const
    {
        locker_t locker(m_mutex);
        return m_impl;
    }

} // namespace sdk
} // namespace ga
