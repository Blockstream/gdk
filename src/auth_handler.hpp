#ifndef GDK_AUTH_HANDLER_HPP
#define GDK_AUTH_HANDLER_HPP
#pragma once

#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

namespace ga {
namespace sdk {
    class session;
    class signer;

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

        // Enum representing a request to a signer/signing request
        enum class hw_request : uint32_t {
            none = 0,
            get_xpubs = 1,
            sign_message = 2,
            sign_tx = 3,
            get_master_blinding_key = 4,
            get_blinding_public_keys = 5,
            get_blinding_nonces = 6
        };

        virtual void signal_hw_request(hw_request request);
        virtual void signal_2fa_request(const std::string& action);
        virtual void set_error(const std::string& error_message);

        virtual void request_code_impl(const std::string& method);
        virtual state_type call_impl();
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
        virtual void signal_hw_request(hw_request request) final;
        virtual void signal_2fa_request(const std::string& action) final;
        virtual void set_error(const std::string& error_message) final;

        virtual void request_code_impl(const std::string& method) final;

        session& m_session;
        std::shared_ptr<signer> m_signer;
        std::unique_ptr<std::vector<std::string>> m_methods; // All available methods
        std::string m_method; // Selected 2fa method
        std::string m_action; // Selected 2fa action name (send_raw_tx, set_csvtime etc)
        std::string m_code; // The 2fa code - from the user
        std::string m_error; // Error details if any
        nlohmann::json m_result; // Result of any successful action
        nlohmann::json m_twofactor_data; // Actual data to send along with any call
        nlohmann::json m_auth_data;
        auth_handler::state_type m_state; // Current state
        uint32_t m_attempts_remaining;
        hw_request m_hw_request;
        bool m_use_anti_exfil;

    private:
        bool has_retry_counter() const;
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

    private:
        void step();

        auth_handler* m_handler;
    };

} // namespace sdk
} // namespace ga
#endif
