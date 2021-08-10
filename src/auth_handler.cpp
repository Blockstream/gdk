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
    // Common auth handling implementation
    //
    auth_handler::auth_handler() {}

    auth_handler::~auth_handler() {}

    void auth_handler::signal_hw_request(hw_request /*request*/) { GDK_RUNTIME_ASSERT(false); }

    auth_handler_impl::auth_handler_impl(session& session, const std::string& name, std::shared_ptr<signer> signer)
        : m_session_parent(session)
        , m_session(session.get_nonnull_impl())
        , m_net_params(session.get_network_parameters())
        , m_name(name)
        , m_signer(signer)
        , m_action(name)
        , m_state(state_type::make_call)
        , m_attempts_remaining(TWO_FACTOR_ATTEMPTS)
        , m_hw_request(hw_request::none)
        , m_use_anti_exfil(false)
    {
    }

    auth_handler_impl::auth_handler_impl(session& session, const std::string& name)
        : auth_handler_impl(session, name, session.get_nonnull_impl()->get_signer())
    {
    }

    auth_handler_impl::~auth_handler_impl() {}

    void auth_handler::signal_2fa_request(const std::string& /*action*/) { GDK_RUNTIME_ASSERT(false); }

    void auth_handler::set_error(const std::string& /*error_message*/) { GDK_RUNTIME_ASSERT(false); }

    void auth_handler::request_code_impl(const std::string& /*method*/) { GDK_RUNTIME_ASSERT(false); }

    auth_handler::state_type auth_handler::call_impl()
    {
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    void auth_handler_impl::signal_hw_request(hw_request request)
    {
        m_hw_request = request;
        const char* action = nullptr;
        switch (request) {
        case hw_request::get_xpubs:
            action = "get_xpubs";
            break;
        case hw_request::sign_message:
            action = "sign_message";
            break;
        case hw_request::sign_tx:
            action = "sign_tx";
            break;
        case hw_request::get_master_blinding_key:
            action = "get_master_blinding_key";
            break;
        case hw_request::get_blinding_public_keys:
            action = "get_blinding_public_keys";
            break;
        case hw_request::get_blinding_nonces:
            action = "get_blinding_nonces";
            break;
        case hw_request::none:
        default:
            GDK_RUNTIME_ASSERT(false);
        }
        auto hw_device = m_signer ? m_signer->get_device() : nlohmann::json();
        m_twofactor_data = { { "action", action }, { "device", hw_device } };
        m_state = state_type::resolve_code;
    }

    void auth_handler_impl::signal_2fa_request(const std::string& action)
    {
        m_hw_request = hw_request::none;
        m_action = action;
        if (!m_methods && !m_session->is_watch_only()) {
            m_methods.reset(new std::vector<std::string>(m_session->get_enabled_twofactor_methods()));
        }
        m_twofactor_data = nlohmann::json::object();
        m_state = !m_methods || m_methods->empty() ? state_type::make_call : state_type::request_code;
    }

    void auth_handler_impl::set_error(const std::string& error_message)
    {
        GDK_LOG_SEV(log_level::warning) << m_name << " call exception: " << error_message;
        m_state = state_type::error;
        m_error = error_message;
    }

    void auth_handler_impl::request_code(const std::string& method)
    {
        try {
            GDK_RUNTIME_ASSERT(m_state == state_type::request_code);
            if (!m_methods || std::find(m_methods->begin(), m_methods->end(), method) == m_methods->end()) {
                set_error(std::string("Cannot request a code using disabled Two-Factor method ") + method);
                return;
            }
            request_code_impl(method);
            m_attempts_remaining = TWO_FACTOR_ATTEMPTS;
        } catch (const std::exception& e) {
            set_error(e.what());
        }
    }

    void auth_handler_impl::request_code_impl(const std::string& method)
    {
        // For gauth request code is a no-op
        if (method != "gauth") {
            m_auth_data = m_session->auth_handler_request_code(method, m_action, m_twofactor_data);
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
        // This handler can not be used if the session has been disconnected via GA_disconnect()
        GDK_RUNTIME_ASSERT(m_session.get() == m_session_parent.get_nonnull_impl().get());
        bool is_invalid_code = false;
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
            try {
                m_state = call_impl();
                m_attempts_remaining = TWO_FACTOR_ATTEMPTS;
            } catch (...) {
                // Handle session level exceptions
                m_session_parent.exception_handler(std::current_exception());
            }
        } catch (const autobahn::call_error& e) {
            auto details = get_error_details(e);
            if (is_twofactor_invalid_code_error(details.second)) {
                is_invalid_code = true;
            } else {
                details = remap_ga_server_error(details);
                set_error(details.second.empty() ? e.what() : details.second);
            }
        } catch (const user_error& e) {
            if (is_twofactor_invalid_code_error(e.what())) {
                is_invalid_code = true;
            } else {
                // Just set the undecorated error string as it should be an id for a
                // translatable string resource, displayed as appropriate by the client.
                set_error(e.what());
            }
        } catch (const std::exception& e) {
            set_error(e.what());
        }
        if (is_invalid_code) {
            // The caller entered the wrong code
            // FIXME: Error if the methods time limit is up or we are rate limited
            if (has_retry_counter() && --m_attempts_remaining == 0) {
                // No more attempts left, caller should try the action again
                set_error(res::id_invalid_twofactor_code);
            } else {
                // Caller should try entering the code again
                m_state = state_type::resolve_code;
            }
        }
    }

    auth_handler::hw_request auth_handler_impl::get_hw_request() const { return m_hw_request; }
    auth_handler::state_type auth_handler_impl::get_state() const { return m_state; }

    session_impl& auth_handler_impl::get_session() const { return *m_session; }

    std::shared_ptr<signer> auth_handler_impl::get_signer() const { return m_signer; }

    bool auth_handler_impl::has_retry_counter() const { return m_method != "gauth" && m_method != "telegram"; }

    nlohmann::json auth_handler_impl::get_status() const
    {
        GDK_RUNTIME_ASSERT(m_state == state_type::error || m_error.empty());

        const char* status_str = nullptr;
        std::string action(m_action);
        nlohmann::json status;

        switch (m_state) {
        case state_type::request_code:
            // Caller should ask the user to pick 2fa and request a code
            GDK_RUNTIME_ASSERT(get_hw_request() == hw_request::none);
            GDK_RUNTIME_ASSERT(m_methods && !m_methods->empty());
            status_str = "request_code";
            status.emplace("methods", *m_methods);
            break;
        case state_type::resolve_code:
            status_str = "resolve_code";
            if (get_hw_request() != hw_request::none) {
                // Caller must interact with the hardware and return
                // the returning data to us
                action = m_twofactor_data.at("action");
                status["required_data"] = m_twofactor_data;
            } else {
                // Caller should resolve the code the user has entered
                status.emplace("method", m_method);
                status.emplace("auth_data", m_auth_data);
                if (has_retry_counter()) {
                    status.emplace("attempts_remaining", m_attempts_remaining);
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
            status.emplace("result", m_result);
            break;
        case state_type::error:
            // Caller should handle the error
            status_str = "error";
            status.emplace("error", m_error);
            break;
        }
        GDK_RUNTIME_ASSERT(status_str != nullptr);
        status.emplace("status", status_str);
        status.emplace("name", m_name);
        status.emplace("action", action);
        return status;
    }

    //
    // An auth handler that auto-resolves HW actions where possible
    //
    auto_auth_handler::auto_auth_handler(auth_handler* handler)
        : auth_handler()
        , m_handler(handler)
    {
        GDK_RUNTIME_ASSERT(handler != nullptr);
        step();
    }

    auto_auth_handler::~auto_auth_handler() { delete m_handler; }

    void auto_auth_handler::request_code(const std::string& method) { return m_handler->request_code(method); }

    void auto_auth_handler::resolve_code(const std::string& code) { return m_handler->resolve_code(code); }

    void auto_auth_handler::operator()()
    {
        (*m_handler)();
        step();
    }

    nlohmann::json auto_auth_handler::get_status() const { return m_handler->get_status(); }
    auth_handler::state_type auto_auth_handler::get_state() const { return m_handler->get_state(); }
    auth_handler::hw_request auto_auth_handler::get_hw_request() const { return m_handler->get_hw_request(); }

    session_impl& auto_auth_handler::get_session() const { return m_handler->get_session(); }

    std::shared_ptr<signer> auto_auth_handler::get_signer() const { return m_handler->get_signer(); }

    void auto_auth_handler::step()
    {
        // Step through the resolver state machine, resolving any actions that
        // can be satisfied on the host without involving the external device.
        const auto request = get_hw_request();
        if (request == hw_request::none || get_state() != state_type::resolve_code) {
            return; // Not a HW request, let the caller resolve
        }

        const auto status = get_status();
        const auto& required_data = status.at("required_data");
        const auto signer = get_signer();
        const bool have_master_blinding_key = signer->has_master_blinding_key();
        nlohmann::json result;

        if (request == hw_request::get_master_blinding_key) {
            // Host unblinding: fetch master blinding key
            // Allow the session to handle this request with cached data if it can
            std::string blinding_key;
            bool denied;
            std::tie(blinding_key, denied) = get_session().get_cached_master_blinding_key();
            if (!blinding_key.empty() || denied) {
                // We have a cached blinding key or the user has denied access
                result.emplace("master_blinding_key", blinding_key); // Blank if denied
                resolve_code(result.dump());
                return;
            }
        } else if (have_master_blinding_key && request == hw_request::get_blinding_public_keys) {
            // Host unblinding: generate pubkeys
            auto& public_keys = result["public_keys"];
            for (const auto& script : required_data.at("scripts")) {
                public_keys.push_back(b2h(signer->get_blinding_pubkey_from_script(h2b(script))));
            }
            resolve_code(result.dump());
            return;
        } else if (have_master_blinding_key && request == hw_request::get_blinding_nonces) {
            // Host unblinding: generate nonces
            const auto& public_keys = required_data.at("public_keys");
            const auto& scripts = required_data.at("scripts");
            auto& nonces = result["nonces"];
            for (size_t i = 0; i < public_keys.size(); ++i) {
                const auto blinding_key = signer->get_blinding_key_from_script(h2b(scripts.at(i)));
                nonces.push_back(b2h(sha256(ecdh(h2b(public_keys.at(i)), blinding_key))));
            }
            resolve_code(result.dump());
            return;
        }

        if (required_data.at("device").at("device_type") == "hardware") {
            return; // Caller provided HW device, let the caller resolve
        }

        // We have a request to resolve with the internal software wallet
        if (request == hw_request::get_xpubs) {
            std::vector<std::string> xpubs;
            const std::vector<nlohmann::json> paths = required_data.at("paths");
            for (const auto& p : paths) {
                const std::vector<uint32_t> path = p;
                xpubs.emplace_back(signer->get_bip32_xpub(path));
            }
            result["xpubs"] = xpubs;
        } else if (request == hw_request::sign_message) {
            const std::vector<uint32_t> path = required_data.at("path");
            const std::string message = required_data.at("message");
            const auto message_hash = format_bitcoin_message_hash(ustring_span(message));
            result["signature"] = sig_to_der_hex(signer->sign_hash(path, message_hash));
        } else if (request == hw_request::get_master_blinding_key) {
            result["master_blinding_key"] = b2h(signer->get_master_blinding_key());
        } else if (request == hw_request::sign_tx) {
            auto sigs = sign_ga_transaction(
                get_session(), required_data.at("transaction"), required_data.at("signing_inputs"))
                            .first;
            result["signatures"] = sigs;
        } else {
            GDK_LOG_SEV(log_level::warning) << "Unknown hardware request " << status.dump();
            GDK_RUNTIME_ASSERT_MSG(false, "Unknown hardware request");
        }
        resolve_code(result.dump());
    }

} // namespace sdk
} // namespace ga
