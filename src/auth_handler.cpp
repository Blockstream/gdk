#include "auth_handler.hpp"

#include "exception.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "logging.hpp"
#include "memory.hpp"
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
            m_session.auth_handler_request_code(method, m_action, m_twofactor_data);
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

    bool auth_handler_impl::is_hw_action() const { return m_is_hw_action; }

    session& auth_handler_impl::get_session() const { return m_session; }

    std::shared_ptr<signer> auth_handler_impl::get_signer() const { return m_signer; }

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

    //
    // An auth handler that auto-resolves HW actions against a SW implementation
    //
    auto_auth_handler::auto_auth_handler(auth_handler* handler)
        : auth_handler()
        , m_handler(handler)
    {
        GDK_RUNTIME_ASSERT(handler != nullptr);
        step();
    }

    auto_auth_handler::~auto_auth_handler() { delete m_handler; }

    void auto_auth_handler::set_action(const std::string& action)
    {
        (void)action;
        GDK_RUNTIME_ASSERT(false);
    }

    void auto_auth_handler::set_error(const std::string& error_message)
    {
        (void)error_message;
        GDK_RUNTIME_ASSERT(false);
    }

    void auto_auth_handler::set_data() { GDK_RUNTIME_ASSERT(false); }

    void auto_auth_handler::request_code(const std::string& method) { return m_handler->request_code(method); }

    void auto_auth_handler::request_code_impl(const std::string& method)
    {
        (void)method;
        GDK_RUNTIME_ASSERT(false);
    }

    void auto_auth_handler::resolve_code(const std::string& code) { return m_handler->resolve_code(code); }

    void auto_auth_handler::operator()()
    {
        (*m_handler)();
        step();
    }

    auth_handler::state_type auto_auth_handler::call_impl()
    {
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    bool auto_auth_handler::is_hw_action() const { return m_handler->is_hw_action(); }

    session& auto_auth_handler::get_session() const { return m_handler->get_session(); }

    std::shared_ptr<signer> auto_auth_handler::get_signer() const { return m_handler->get_signer(); }

    nlohmann::json auto_auth_handler::get_status() const { return m_handler->get_status(); }

    void auto_auth_handler::step()
    {
        // Step through states resolving any software wallet actions automatically
        const auto status = get_status();
        if (!status.contains("required_data")) {
            return; // Not a HW action, let the caller resolve
        }
        GDK_RUNTIME_ASSERT(is_hw_action());
        GDK_RUNTIME_ASSERT(status.at("status") == "resolve_code");
        const auto& required_data = status["required_data"];
        if (!required_data.at("device").value("name", std::string()).empty()) {
            return; // Caller provided HW device, let the caller resolve
        }
        // We have an action to resolve with the internal software wallet
        nlohmann::json result;

        const std::string action = status.at("action");
        const auto signer = get_signer();
        if (action == "get_xpubs") {
            GDK_RUNTIME_ASSERT(required_data.contains("paths"));
            std::vector<std::string> xpubs;
            const std::vector<nlohmann::json> paths = required_data.at("paths");
            for (const auto& p : paths) {
                const std::vector<uint32_t> path = p;
                xpubs.emplace_back(signer->get_bip32_xpub(path));
            }
            result["xpubs"] = xpubs;
        } else if (action == "sign_message") {
            const std::vector<uint32_t> path = required_data.at("path");
            const std::string message = required_data.at("message");
            const auto message_hash = format_bitcoin_message_hash(ustring_span(message));
            result["signature"] = sig_to_der_hex(signer->sign_hash(path, message_hash));
        } else if (action == "get_receive_address") {
            const auto& addr = required_data.at("address");
            const auto script_hash = h2b(addr.at("blinding_script_hash"));
            result["blinding_key"] = b2h(signer->get_public_key_from_blinding_key(script_hash));
        } else if (action == "create_transaction") {
            auto& blinding_keys = result["blinding_keys"];
            const auto& addresses = required_data.at("transaction").at("change_address");
            for (auto& it : addresses.items()) {
                const auto& addr = it.value();
                if (!addr.value("is_blinded", false)) {
                    const auto script_hash = h2b(addr.at("blinding_script_hash"));
                    blinding_keys[it.key()] = b2h(signer->get_public_key_from_blinding_key(script_hash));
                }
            }
        } else if (action == "get_balance" || action == "get_subaccount" || action == "get_subaccounts"
            || action == "get_transactions" || action == "get_unspent_outputs" || action == "get_expired_deposits") {
            // Should only be requested for liquid_support_level = 'lite'
            GDK_RUNTIME_ASSERT_MSG(false, "Unexpected action for software wallet");
        } else {
            GDK_RUNTIME_ASSERT(action == "sign_tx");
            auto impl = get_session().get_nonnull_impl();
            auto sigs = sign_ga_transaction(*impl, required_data["transaction"], required_data["signing_inputs"]).first;
            result["signatures"] = sigs;
        }
        resolve_code(result.dump());
    }

} // namespace sdk
} // namespace ga
