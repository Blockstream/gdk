#ifndef GDK_AUTH_HANDLER_HPP
#define GDK_AUTH_HANDLER_HPP
#pragma once

#include "session.hpp"

namespace ga {
namespace sdk {
    struct auth_handler {
        auth_handler(ga::sdk::session& session, const std::string& action, const nlohmann::json& hw_device,
            bool pre_login = false);
        auth_handler(ga::sdk::session& session, const std::string& action, bool pre_login = false);
        auth_handler(const auth_handler&) = delete;
        auth_handler& operator=(const auth_handler&) = delete;
        auth_handler(auth_handler&&) = delete;
        auth_handler& operator=(auth_handler&&) = delete;
        virtual ~auth_handler() = default;

        virtual void request_code(const std::string& method);
        void resolve_code(const std::string& code);

        virtual nlohmann::json get_status() const;
        virtual void operator()();

    protected:
        enum class state_type : uint32_t {
            request_code, // Caller should ask the user to pick 2fa and request a code
            resolve_code, // Caller should resolve the code the user has entered
            make_call, // Caller should make the call
            done, // Caller should destroy the call and continue
            error // User should handle the error
        };

        void set_error(const std::string& error_message);

        void request_code_impl(const std::string& method);
        virtual state_type call_impl() = 0;

        ga::sdk::session& m_session;
        std::vector<std::string> m_methods; // All available methods
        std::string m_method; // Selected 2fa method
        std::string m_action; // Selected 2fa action name (send_raw_tx, set_csvtime etc)
        std::string m_code; // The 2fa code - from the user
        std::string m_error; // Error details if any
        nlohmann::json m_result; // Result of any successful action
        nlohmann::json m_twofactor_data; // Actual data to send along with any call
        state_type m_state; // Current state
        uint32_t m_attempts_remaining;
        nlohmann::json m_hw_device;

    private:
        void init(const nlohmann::json& hw_device, bool pre_login);
    };
} // namespace sdk
} // namespace ga
#endif
