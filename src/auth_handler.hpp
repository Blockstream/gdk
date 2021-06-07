#ifndef GDK_AUTH_HANDLER_HPP
#define GDK_AUTH_HANDLER_HPP
#pragma once

#include "signer.hpp"

namespace ga {
namespace sdk {
    class session;

    struct auth_handler {
        auth_handler();
        auth_handler(const auth_handler&) = delete;
        auth_handler& operator=(const auth_handler&) = delete;
        auth_handler(auth_handler&&) = delete;
        auth_handler& operator=(auth_handler&&) = delete;
        virtual ~auth_handler();

        virtual void request_code(const std::string& method) = 0;
        virtual void resolve_code(const std::string& code) = 0;

        virtual nlohmann::json get_status() const = 0;

        virtual void operator()() = 0;
        virtual bool is_hw_action() const = 0;
        virtual session& get_session() const = 0;
        virtual std::shared_ptr<signer> get_signer() const = 0;

    protected:
        enum class state_type : uint32_t {
            request_code, // Caller should ask the user to pick 2fa and request a code
            resolve_code, // Caller should resolve the code the user has entered
            make_call, // Caller should make the call
            done, // Caller should destroy the call and continue
            error // User should handle the error
        };

        virtual void set_action(const std::string& action) = 0;
        virtual void set_error(const std::string& error_message) = 0;
        virtual void set_data() = 0;

        virtual void request_code_impl(const std::string& method) = 0;
        virtual state_type call_impl() = 0;
    };

    struct auth_handler_impl : public auth_handler {
        auth_handler_impl(session& session, const std::string& action, std::shared_ptr<signer> signer);
        auth_handler_impl(session& session, const std::string& action);
        ~auth_handler_impl();

        virtual void request_code(const std::string& method) override;
        virtual void resolve_code(const std::string& code) final;

        virtual nlohmann::json get_status() const final;

        virtual void operator()() final;
        virtual bool is_hw_action() const final;
        virtual session& get_session() const final;
        virtual std::shared_ptr<signer> get_signer() const final;

    protected:
        virtual void set_action(const std::string& action) final;
        virtual void set_error(const std::string& error_message) final;
        virtual void set_data() final;

        virtual void request_code_impl(const std::string& method) final;

        session& m_session;
        std::shared_ptr<signer> m_signer;
        bool m_is_hw_action;
        std::vector<std::string> m_methods; // All available methods
        std::string m_method; // Selected 2fa method
        std::string m_action; // Selected 2fa action name (send_raw_tx, set_csvtime etc)
        std::string m_code; // The 2fa code - from the user
        std::string m_error; // Error details if any
        nlohmann::json m_result; // Result of any successful action
        nlohmann::json m_twofactor_data; // Actual data to send along with any call
        auth_handler::state_type m_state; // Current state
        uint32_t m_attempts_remaining;

    private:
        void init(const std::string& action, std::shared_ptr<signer> signer, bool is_pre_login);
    };

    struct auto_auth_handler : public auth_handler {
        auto_auth_handler(auth_handler* m_handler);
        ~auto_auth_handler();

        void request_code(const std::string& method) override;
        void resolve_code(const std::string& code) final;

        nlohmann::json get_status() const final;

        void operator()() final;
        bool is_hw_action() const final;
        virtual session& get_session() const final;
        virtual std::shared_ptr<signer> get_signer() const final;

    protected:
        void set_action(const std::string& action) final;
        void set_error(const std::string& error_message) final;
        void set_data() final;

        void request_code_impl(const std::string& method) final;

        state_type call_impl() final;

    private:
        void step();

        auth_handler* m_handler;
    };

} // namespace sdk
} // namespace ga
#endif
