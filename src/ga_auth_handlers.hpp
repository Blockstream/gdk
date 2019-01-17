#ifndef GDK_GA_AUTH_HANDLERS_HPP
#define GDK_GA_AUTH_HANDLERS_HPP
#pragma once

#include "auth_handler.hpp"

namespace ga {
namespace sdk {
    class register_call : public auth_handler {
    public:
        register_call(session& session, const nlohmann::json& hw_device, const std::string& mnemonic);

    private:
        state_type call_impl() override;

        std::string m_mnemonic;
    };

    class login_call : public auth_handler {
    public:
        login_call(session& session, const nlohmann::json& hw_device, const std::string& mnemonic,
            const std::string& password);

    private:
        void set_data(const std::string& action);

        state_type call_impl() override;

        std::string m_challenge;
        std::string m_mnemonic;
        std::string m_password;
    };

    class create_subaccount_call : public auth_handler {
    public:
        create_subaccount_call(session& session, const nlohmann::json& details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
        uint32_t m_subaccount;
    };

    class ack_system_message_call : public auth_handler {
    public:
        ack_system_message_call(session& session, const std::string& msg);

    private:
        state_type call_impl() override;

        std::string m_message;
        std::pair<std::string, std::vector<uint32_t>> m_message_info;
    };

    class sign_transaction_call : public auth_handler {
    public:
        sign_transaction_call(session& session, const nlohmann::json& tx_details);

    private:
        state_type call_impl() override;

        nlohmann::json m_tx_details;
    };

    class change_settings_call : public auth_handler {
    public:
        change_settings_call(session& session, const nlohmann::json& settings);

    private:
        state_type call_impl() override;

        nlohmann::json m_settings;
    };

    class change_settings_twofactor_call : public auth_handler {
    public:
        change_settings_twofactor_call(
            session& session, const std::string& method_to_update, const nlohmann::json& details);

    private:
        state_type call_impl() override;

        state_type on_init_done(const std::string& new_action);

        nlohmann::json m_current_config;
        std::string m_method_to_update;
        nlohmann::json m_details;
        nlohmann::json m_gauth_data;
        bool m_enabling;
    };

    class change_limits_call : public auth_handler {
    public:
        change_limits_call(session& session, const nlohmann::json& details);

        void request_code(const std::string& method) override;

    private:
        state_type call_impl() override;

        nlohmann::json m_limit_details;
        bool m_is_decrease;
    };

    class remove_account_call : public auth_handler {
    public:
        remove_account_call(session& session);

    private:
        state_type call_impl() override;
    };

    class send_transaction_call final : public auth_handler {
    public:
        send_transaction_call(session& session, const nlohmann::json& tx_details);

        void request_code(const std::string& method) override;

    private:
        state_type call_impl() override;

        void create_twofactor_data();

        nlohmann::json m_tx_details;
        nlohmann::json m_limit_details;
        bool m_twofactor_required;
        bool m_under_limit;
        uint64_t m_bump_amount = 0;
    };

    class twofactor_reset_call : public auth_handler {
    public:
        twofactor_reset_call(session& session, const std::string& email, bool is_dispute);

    private:
        state_type call_impl() override;

        std::string m_reset_email;
        bool m_is_dispute;
        bool m_confirming;
    };

    class twofactor_cancel_reset_call final : public auth_handler {
    public:
        twofactor_cancel_reset_call(session& session);

    private:
        state_type call_impl() override;
    };
} // namespace sdk
} // namespace ga
#endif
