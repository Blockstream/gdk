#include "auth_handler.hpp"

#include "exception.hpp"
#include "ga_strings.hpp"
#include "logging.hpp"
#include "session.hpp"
#include "session_impl.hpp"

namespace ga {
namespace sdk {
    namespace {
        // Server gives 3 attempts to get the twofactor code right before it's invalidated
        static const uint32_t TWO_FACTOR_ATTEMPTS = 3;

        static bool is_twofactor_invalid_code_error(const std::string& msg)
        {
            return msg == "Invalid Two Factor Authentication Code";
        }
    } // namespace

    //
    // Auth handling interface
    //
    auth_handler::auth_handler() {}

    auth_handler::~auth_handler() {}

    //
    // Common auth handling implementation
    //
    auth_handler_impl::auth_handler_impl(session& session, const std::string& action, std::shared_ptr<signer> signer)
        : m_session(session)
        , m_action(action)
        , m_attempts_remaining(TWO_FACTOR_ATTEMPTS)
    {
        try {
            init(action, signer, true);
        } catch (const std::exception& e) {
            set_error(e.what());
        }
    }

    auth_handler_impl::auth_handler_impl(session& session, const std::string& action)
        : m_session(session)
        , m_action(action)
        , m_attempts_remaining(TWO_FACTOR_ATTEMPTS)
    {
        try {
            init(action, m_session.get_nonnull_impl()->get_signer(), false);
        } catch (const std::exception& e) {
            set_error(e.what());
        }
    }

    auth_handler_impl::~auth_handler_impl() {}

    void auth_handler_impl::init(const std::string& action, std::shared_ptr<signer> signer, bool is_pre_login)
    {
        m_signer = signer;
        set_action(action);

        if (!is_pre_login && !m_session.is_watch_only()) {
            m_methods = m_session.get_enabled_twofactor_methods();
        }
        m_state = m_methods.empty() ? state_type::make_call : state_type::request_code;
    }

    void auth_handler_impl::set_action(const std::string& action)
    {
        m_action = action;
        m_is_hw_action = m_signer && m_signer->is_hw_device()
            && (action == "get_xpubs" || action == "sign_message" || action == "sign_tx"
                   || action == "get_receive_address" || action == "create_transaction" || action == "get_balance"
                   || action == "get_subaccounts" || action == "get_subaccount" || action == "get_transactions"
                   || action == "get_unspent_outputs" || action == "get_expired_deposits");
    }

    void auth_handler_impl::set_error(const std::string& error_message)
    {
        GDK_LOG_SEV(log_level::debug) << m_action << " call exception: " << error_message;
        m_state = state_type::error;
        m_error = error_message;
    }

    void auth_handler_impl::set_data()
    {
        m_twofactor_data
            = { { "action", m_action }, { "device", m_is_hw_action ? m_signer->get_hw_device() : nlohmann::json() } };
    }

    void auth_handler_impl::request_code(const std::string& method)
    {
        request_code_impl(method);
        m_attempts_remaining = TWO_FACTOR_ATTEMPTS;
    }

    void auth_handler_impl::request_code_impl(const std::string& method)
    {
        GDK_RUNTIME_ASSERT(m_state == state_type::request_code);

        // For gauth request code is a no-op
        if (method != "gauth") {
            m_auth_data = m_session.auth_handler_request_code(method, m_action, m_twofactor_data);
        }

        m_method = method;
        m_state = state_type::resolve_code;
    }

    void auth_handler_impl::resolve_code(const std::string& code)
    {
        GDK_RUNTIME_ASSERT(m_state == state_type::resolve_code);
        m_code = code;
        m_state = state_type::make_call;
    }

    void auth_handler_impl::operator()()
    {
        GDK_RUNTIME_ASSERT(m_state == state_type::make_call);
        try {

            if (m_code.empty() || m_method.empty()) {
                if (!m_twofactor_data.empty()) {
                    // Remove any previous auth attempts
                    m_twofactor_data.erase("method");
                    m_twofactor_data.erase("code");
                }
            } else {
                m_twofactor_data["method"] = m_method;
                m_twofactor_data["code"] = m_code;
            }
            m_state = call_impl();
            m_attempts_remaining = TWO_FACTOR_ATTEMPTS;
        } catch (const autobahn::call_error& e) {
            auto details = get_error_details(e);
            if (is_twofactor_invalid_code_error(details.second)) {
                // The caller entered the wrong code
                // FIXME: Error if the methods time limit is up or we are rate limited
                if (m_method != "gauth" && --m_attempts_remaining == 0) {
                    // No more attempts left, caller should try the action again
                    set_error(res::id_invalid_twofactor_code);
                } else {
                    // Caller should try entering the code again
                    m_state = state_type::resolve_code;
                }
            } else {
                details = remap_ga_server_error(details);
                set_error(details.second.empty() ? e.what() : details.second);
            }
        } catch (const user_error& e) {
            // Just set the undecorated error string as it should be an id for a
            // translatable string resource, displayed as appropriate by the client.
            set_error(e.what());
        } catch (const std::exception& e) {
            set_error(m_action + std::string(" exception:") + e.what());
        }
    }

    nlohmann::json auth_handler_impl::get_status() const
    {
        GDK_RUNTIME_ASSERT(m_state == state_type::error || m_error.empty());

        std::string status_str;
        nlohmann::json status;

        switch (m_state) {
        case state_type::request_code:
            GDK_RUNTIME_ASSERT(!m_is_hw_action);

            // Caller should ask the user to pick 2fa and request a code
            status_str = "request_code";
            status["methods"] = m_methods;
            break;
        case state_type::resolve_code:
            status_str = "resolve_code";
            if (m_is_hw_action) {
                // Caller must interact with the hardware and return
                // the returning data to us
                status["method"] = m_signer->get_hw_device().value("name", std::string());
                status["required_data"] = m_twofactor_data;
            } else {
                // Caller should resolve the code the user has entered
                status["method"] = m_method;
                status["auth_data"] = m_auth_data;
                if (m_method != "gauth") {
                    status["attempts_remaining"] = m_attempts_remaining;
                }
            }
            break;
        case state_type::make_call:
            // Caller should make the call
            status_str = "call";
            break;
        case state_type::done:
            // Caller should destroy the call and continue
            status_str = "done";
            status["result"] = m_result;
            break;
        case state_type::error:
            // Caller should handle the error
            status_str = "error";
            status["error"] = m_error;
            break;
        }
        GDK_RUNTIME_ASSERT(!status_str.empty());
        status["status"] = status_str;
        status["action"] = m_action;
        status["device"] = m_is_hw_action ? m_signer->get_hw_device() : nlohmann::json();
        return status;
    }

} // namespace sdk
} // namespace ga
