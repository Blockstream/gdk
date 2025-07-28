#include "auth_handler.hpp"
#include "autobahn_wrapper.hpp"
#include "exception.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "json_utils.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "session.hpp"
#include "session_impl.hpp"
#include "signer.hpp"

namespace green {

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

    nlohmann::json& auth_handler::signal_hw_request(hw_request /*request*/)
    {
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    auth_handler* auth_handler::get_next_handler() const { return m_next_handler.get(); }

    void auth_handler::add_next_handler(auth_handler* next)
    {
        GDK_RUNTIME_ASSERT(next);
        GDK_RUNTIME_ASSERT(!m_next_handler);
        m_next_handler = std::unique_ptr<auth_handler>(next);
    }

    std::unique_ptr<auth_handler> auth_handler::remove_next_handler() { return std::move(m_next_handler); }
    void auth_handler::on_next_handler_complete(auth_handler* /*next_handler*/) {}

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
    {
    }

    auth_handler_impl::auth_handler_impl(session& session, const std::string& name)
        : auth_handler_impl(session, name, session.get_nonnull_impl()->get_nonnull_signer())
    {
    }

    auth_handler_impl::~auth_handler_impl() {}

    void auth_handler::signal_2fa_request(const std::string& /*action*/) { GDK_RUNTIME_ASSERT(false); }

    void auth_handler::signal_data_request() { GDK_RUNTIME_ASSERT(false); }

    void auth_handler::set_error(const std::string& /*error_message*/) { GDK_RUNTIME_ASSERT(false); }

    void auth_handler::request_code_impl(const std::string& /*method*/) { GDK_RUNTIME_ASSERT(false); }

    auth_handler::state_type auth_handler::call_impl()
    {
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    nlohmann::json& auth_handler_impl::signal_hw_request(hw_request request)
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
        case hw_request::get_blinding_factors:
            action = "get_blinding_factors";
            break;
        case hw_request::none:
        default:
            GDK_RUNTIME_ASSERT(false);
        }
        auto hw_device = m_signer ? m_signer->get_device() : nlohmann::json();
        m_twofactor_data = { { "action", action }, { "device", hw_device } };
        m_state = state_type::resolve_code;
        return m_twofactor_data;
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

    void auth_handler_impl::signal_data_request()
    {
        m_methods.reset(new std::vector<std::string>{ "data" });
        signal_2fa_request("data");
        m_auth_data = nlohmann::json::object();
    }

    void auth_handler_impl::set_error(const std::string& error_message)
    {
        GDK_LOG(warning) << m_name << " call exception: " << error_message;
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
        // For gauth or data, request code is a no-op
        if (method != "gauth" && method != "data") {
            m_auth_data = m_session->auth_handler_request_code(method, m_action, m_twofactor_data);
        }

        m_method = method;
        m_state = state_type::resolve_code;
    }

    void auth_handler_impl::resolve_code(const std::string& code)
    {
        GDK_RUNTIME_ASSERT(m_state == state_type::resolve_code);
        GDK_RUNTIME_ASSERT(!code.empty());
        if (m_hw_request == hw_request::none) {
            // Caller is resolving a 2FA code
            m_code = code;
            m_state = state_type::make_call;
            return;
        }
        // Otherwise, caller is resolving a HWW action
        try {
            resolve_hw_reply(json_parse(code));
        } catch (const std::exception&) {
            throw user_error("Invalid hardware reply");
        }
    }

    void auth_handler_impl::resolve_hw_reply(nlohmann::json&& reply)
    {
        GDK_RUNTIME_ASSERT(m_state == state_type::resolve_code);
        GDK_RUNTIME_ASSERT(m_hw_request != hw_request::none);
        m_hw_reply = std::move(reply);
        m_state = state_type::make_call;
    }

    void auth_handler_impl::operator()()
    {
        GDK_RUNTIME_ASSERT(m_state == state_type::make_call);
        GDK_RUNTIME_ASSERT(m_session); // Must be connected
        bool is_invalid_code = false;
        try {

            if (m_code.empty() || m_method.empty()) {
                if (!m_twofactor_data.empty()) {
                    // Remove any previous auth attempts
                    j_erase(m_twofactor_data, "method");
                    j_erase(m_twofactor_data, "code");
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

    auth_handler::state_type auth_handler_impl::get_state() const { return m_state; }
    auth_handler::hw_request auth_handler_impl::get_hw_request() const { return m_hw_request; }
    bool auth_handler_impl::is_data_request() const
    {
        return m_methods && m_methods->size() == 1u && m_methods->front() == "data";
    }
    nlohmann::json& auth_handler_impl::get_twofactor_data() { return m_twofactor_data; }
    const std::string& auth_handler_impl::get_code() const { return m_code; }
    nlohmann::json& auth_handler_impl::get_hw_reply() { return m_hw_reply; }

    session_impl& auth_handler_impl::get_session() const { return *m_session; }
    nlohmann::json&& auth_handler_impl::move_result() { return std::move(m_result); }

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
        GDK_RUNTIME_ASSERT(!handler->get_next_handler());
    }

    auth_handler* auto_auth_handler::get_current_handler() const
    {
        auto handler = m_handler;
        while (handler->get_next_handler()) {
            handler = handler->get_next_handler();
        }
        return handler;
    }

    std::unique_ptr<auth_handler> auto_auth_handler::pop_handler()
    {
        auto handler = m_handler;
        auto next = handler->get_next_handler();
        while (next) {
            if (!next->get_next_handler()) {
                break;
            }
            handler = next;
            next = next->get_next_handler();
        }
        return handler == m_handler && !next ? std::unique_ptr<auth_handler>() : handler->remove_next_handler();
    }

    auto_auth_handler::~auto_auth_handler() { delete m_handler; }

    void auto_auth_handler::request_code(const std::string& method) { get_current_handler()->request_code(method); }

    void auto_auth_handler::resolve_code(const std::string& code)
    {
        get_current_handler()->resolve_code(code);
        advance();
    }

    void auto_auth_handler::resolve_hw_reply(nlohmann::json&& reply)
    {
        get_current_handler()->resolve_hw_reply(std::move(reply));
        advance();
    }

    void auto_auth_handler::operator()()
    {
        GDK_RUNTIME_ASSERT(get_state() == state_type::make_call);
        advance();
    }

    nlohmann::json auto_auth_handler::get_status() const { return get_current_handler()->get_status(); }

    auth_handler::state_type auto_auth_handler::get_state() const { return get_current_handler()->get_state(); }

    auth_handler::hw_request auto_auth_handler::get_hw_request() const
    {
        return get_current_handler()->get_hw_request();
    }
    bool auto_auth_handler::is_data_request() const { return get_current_handler()->is_data_request(); }
    nlohmann::json& auto_auth_handler::get_twofactor_data() { return get_current_handler()->get_twofactor_data(); }

    const std::string& auto_auth_handler::get_code() const { return get_current_handler()->get_code(); }
    nlohmann::json& auto_auth_handler::get_hw_reply() { return get_current_handler()->get_hw_reply(); }
    nlohmann::json&& auto_auth_handler::move_result() { return get_current_handler()->move_result(); }

    session_impl& auto_auth_handler::get_session() const { return get_current_handler()->get_session(); }

    std::shared_ptr<signer> auto_auth_handler::get_signer() const { return get_current_handler()->get_signer(); }

    void auto_auth_handler::advance()
    {
        while (step()) {
            // No-op
        }
    }

    bool auto_auth_handler::step()
    {
        // Step through the resolver state machine, resolving any actions that
        // can be satisfied on the host without involving the caller.
        // Returns whether we resolved an action, i.e. whether we should loop
        // attempting to step() again.
        auto handler = get_current_handler();
        const auto state = handler->get_state();

        if (state == state_type::error) {
            return false;
        }

        if (state == state_type::done) {
            auto last_handler = pop_handler();
            if (!last_handler) {
                return false; // handler processing has finished
            }
            // TODO: Intrusive handler processing
            // Allow the next-to-last handler to fetch results from its sub-handler
            get_current_handler()->on_next_handler_complete(last_handler.get());
            return true; // Continue processing the current handler
        }

        if (state == state_type::request_code && handler->is_data_request()) {
            // A request for more data from the caller. Handle it internally,
            // the caller just sees resolve_code for "data" with the details.
            handler->request_code("data");
            return true; // Continue processing the current handler
        }

        // TODO: When multiple signers are supported, get the signer indicated by the
        //       required_data's "device" element
        const auto signer = handler->get_signer();
        const bool is_hardware = signer && signer->is_hardware();
        const auto request = handler->get_hw_request();

        if (state == state_type::make_call) {
            if (is_hardware && request == hw_request::get_xpubs && !m_xpubs_request.empty()) {
                // HW has resolved a get_xpubs request, cache the results
                const auto& paths = j_arrayref(get_twofactor_data(), "paths");
                const auto& xpubs = j_arrayref(get_hw_reply(), "xpubs", paths.size());
                bool updated = false;
                size_t i = 0;
                for (const auto& p : paths) {
                    const auto path = p.get<std::vector<uint32_t>>();
                    updated |= signer->cache_bip32_xpub(path, xpubs.at(i)).second;
                    ++i;
                }
                if (updated) {
                    GDK_LOG(debug) << "signer xpub cache updated";
                    get_session().encache_signer_xpubs(signer);
                }
                // Replace the request/reply with the actually requested xpubs
                auto& actual_paths = j_arrayref(m_xpubs_request, "paths");
                get_hw_reply() = get_xpubs(signer, actual_paths);
                get_twofactor_data()["paths"] = std::move(actual_paths);
            }

            (*handler)(); // Make the call
            return true;
        }

        if (request == hw_request::none || state != state_type::resolve_code) {
            return false; // Not a HW request, let the caller resolve
        }

        auto status = get_status();
        auto& required_data = status.at("required_data");
        const bool have_master_blinding_key = signer->has_master_blinding_key();
        // The internal software wallet must have a master blinding key
        GDK_RUNTIME_ASSERT(!signer->is_liquid() || have_master_blinding_key || is_hardware);
        nlohmann::json result;

        if (request == hw_request::get_master_blinding_key) {
            // Host unblinding: fetch master blinding key
            // Allow the session to handle this request with cached data if it can
            auto [blinding_key, denied] = get_session().get_cached_master_blinding_key();
            if (!blinding_key.empty() || denied) {
                // We have a cached blinding key or the user has denied access
                result.emplace("master_blinding_key", std::move(blinding_key)); // Blank if denied
                handler->resolve_hw_reply(std::move(result));
                return true;
            }
        } else if (have_master_blinding_key && request == hw_request::get_blinding_public_keys) {
            // Host unblinding: generate pubkeys
            auto& blinding_public_keys = result["public_keys"];
            for (const auto& script : required_data.at("scripts")) {
                blinding_public_keys.push_back(b2h(signer->get_blinding_pubkey_from_script(h2b(script))));
            }
            handler->resolve_hw_reply(std::move(result));
            return true;
        } else if (have_master_blinding_key && request == hw_request::get_blinding_nonces) {
            // Host unblinding: generate nonces
            // As we have the master blinding key, we should not be asked for blinding keys
            GDK_RUNTIME_ASSERT(!required_data.at("blinding_keys_required"));
            const auto& public_keys = required_data.at("public_keys");
            const auto& scripts = required_data.at("scripts");
            auto& nonces = result["nonces"];
            for (size_t i = 0; i < public_keys.size(); ++i) {
                const auto blinding_key = signer->get_blinding_key_from_script(h2b(scripts.at(i)));
                nonces.push_back(b2h(sha256(ecdh(h2b(public_keys.at(i)), blinding_key))));
            }
            handler->resolve_hw_reply(std::move(result));
            return true;
        } else if (have_master_blinding_key && request == hw_request::get_blinding_factors) {
            // Host unblinding: Blind a transaction
            handler->resolve_hw_reply(get_blinding_factors(signer->get_master_blinding_key(), required_data));
            return true;
        } else if (request == hw_request::get_xpubs) {
            m_xpubs_request = {};
            std::set<std::vector<uint32_t>> parents;
            const auto& paths = j_arrayref(required_data, "paths");
            for (const auto& p : paths) {
                auto path = p.get<std::vector<uint32_t>>();
                if (!signer->has_bip32_xpub(path)) {
                    while (!path.empty() && !is_hardened(path.back())) {
                        path.pop_back(); // Strip path to its parent
                    }
                    parents.emplace(std::move(path));
                }
            }
            if (parents.empty()) {
                // All requested xpubs can be generated by the internal signer
                handler->resolve_hw_reply(get_xpubs(signer, paths));
                return true;
            }
            // Save the handlers get_xpubs request
            m_xpubs_request = std::move(required_data);
            // Overwite the request with one with our optimal paths
            auto& new_request = handler->signal_hw_request(hw_request::get_xpubs);
            nlohmann::json::array_t parent_paths;
            parent_paths.reserve(parents.size());
            std::copy(parents.begin(), parents.end(), std::back_inserter(parent_paths));
            new_request["paths"] = std::move(parent_paths);
            return false;
        } else if (request == hw_request::sign_tx) {
            // Check if there are any inputs that actually require signing
            auto&& must_sign = [](const auto& in) -> bool { return !in.value("skip_signing", false); };
            const auto& inputs = required_data.at("transaction_inputs");
            if (std::none_of(inputs.begin(), inputs.end(), must_sign)) {
                // No inputs require signing: return empty sigs for each input
                result["signatures"] = nlohmann::json::array_t(inputs.size(), std::string());
                handler->resolve_hw_reply(std::move(result));
                return true;
            }
        }

        if (is_hardware) {
            return false; // Caller provided HW device, let the caller resolve
        }

        // We have a request to resolve with the internal software wallet
        if (request == hw_request::sign_message) {
            const std::vector<uint32_t> path = required_data.at("path");
            const std::string message = required_data.at("message");
            const auto message_hash = format_bitcoin_message_hash(ustring_span(message));
            result["signature"] = sig_only_to_der_hex(signer->ecdsa_sign(path, message_hash));
        } else if (request == hw_request::get_master_blinding_key) {
            result["master_blinding_key"] = b2h(signer->get_master_blinding_key());
        } else if (request == hw_request::sign_tx) {
            const Tx tx(required_data.at("transaction").get<std::string>(), signer->is_liquid());
            result["signatures"] = sign_transaction(get_session(), tx, required_data.at("transaction_inputs"));
        } else {
            GDK_LOG(warning) << "Unknown hardware request " << status.dump();
            GDK_RUNTIME_ASSERT_MSG(false, "Unknown hardware request");
        }
        handler->resolve_hw_reply(std::move(result));
        return true;
    }

    nlohmann::json auto_auth_handler::get_xpubs(
        const std::shared_ptr<signer>& signer, const nlohmann::json::array_t& paths) const
    {
        nlohmann::json::array_t xpubs;
        xpubs.reserve(paths.size());
        for (const auto& p : paths) {
            auto path = p.get<std::vector<uint32_t>>();
            xpubs.emplace_back(signer->get_bip32_xpub(path));
        }
        return nlohmann::json({ { "xpubs", std::move(xpubs) } });
    }

} // namespace green
