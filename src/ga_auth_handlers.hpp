#ifndef GDK_GA_AUTH_HANDLERS_HPP
#define GDK_GA_AUTH_HANDLERS_HPP
#pragma once

#include "auth_handler.hpp"

namespace ga {
namespace sdk {
    class register_call : public auth_handler_impl {
    public:
        register_call(session& session, const nlohmann::json& hw_device, const std::string& mnemonic);

    private:
        state_type call_impl() override;

        const nlohmann::json m_hw_device;
        const nlohmann::json m_credential_data;
    };

    class login_user_call : public auth_handler_impl {
    public:
        login_user_call(session& session, const nlohmann::json& hw_device, const nlohmann::json& credential_data);

    private:
        state_type call_impl() override;

        const nlohmann::json m_hw_device;
        nlohmann::json m_credential_data;
        std::string m_challenge;
        std::string m_master_bip32_xpub;

        // Used when AMP subaccounts require new addresses
        std::vector<nlohmann::json> m_addresses;
    };

    class create_subaccount_call : public auth_handler_impl {
    public:
        create_subaccount_call(session& session, const nlohmann::json& details);

    private:
        state_type call_impl() override;
        void initialize();

        nlohmann::json m_details;
        uint32_t m_subaccount;

        // used by 2of3 subaccounts
        std::string m_subaccount_xpub;

        // Used when a new authorized-assets-enabled subaccount is created
        std::vector<nlohmann::json> m_addresses;
        bool m_initialized;
    };

    class ack_system_message_call : public auth_handler_impl {
    public:
        ack_system_message_call(session& session, const std::string& msg);

    private:
        state_type call_impl() override;
        void initialize();

        const std::string m_msg;
        std::pair<std::string, std::vector<uint32_t>> m_message_info;
        bool m_initialized;
    };

    class sign_transaction_call : public auth_handler_impl {
    public:
        sign_transaction_call(session& session, const nlohmann::json& tx_details);

    private:
        state_type call_impl() override;
        void initialize();

        nlohmann::json m_tx_details;
        bool m_initialized;
    };

    class get_receive_address_call : public auth_handler_impl {
    public:
        get_receive_address_call(session& session, const nlohmann::json& details);

    private:
        state_type call_impl() override;
        void initialize();

        const nlohmann::json m_details;
        bool m_initialized;
    };

    class get_previous_addresses_call : public auth_handler_impl {
    public:
        get_previous_addresses_call(session& session, const nlohmann::json& details);

    private:
        state_type call_impl() override;
        void initialize();

        const nlohmann::json m_details;
        bool m_initialized;
    };

    class create_transaction_call : public auth_handler_impl {
    public:
        create_transaction_call(session& session, const nlohmann::json& details);

    private:
        state_type call_impl() override;
        state_type check_change_outputs();

        const nlohmann::json m_details;
    };

    class get_subaccounts_call : public auth_handler_impl {
    public:
        get_subaccounts_call(session& session);

    private:
        state_type call_impl() override;
    };

    class get_subaccount_call : public auth_handler_impl {
    public:
        get_subaccount_call(session& session, uint32_t subaccount);

    private:
        state_type call_impl() override;
        const uint32_t m_subaccount;
    };

    class get_transactions_call : public auth_handler_impl {
    public:
        get_transactions_call(session& session, const nlohmann::json& details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
        const uint32_t m_subaccount;
    };

    class get_unspent_outputs_call : public auth_handler_impl {
    public:
        get_unspent_outputs_call(
            session& session, const nlohmann::json& details, const std::string& name = std::string());

    protected:
        state_type call_impl() override;

    private:
        void initialize();
        void filter_result(bool encache);

        const nlohmann::json m_details;
        bool m_initialized;
    };

    class get_balance_call : public get_unspent_outputs_call {
    public:
        get_balance_call(session& session, const nlohmann::json& details);

    private:
        state_type call_impl() override;
        void compute_balance();
    };

    class set_unspent_outputs_status_call : public auth_handler_impl {
    public:
        set_unspent_outputs_status_call(session& session, const nlohmann::json& details);

    private:
        state_type call_impl() override;

        void initialize();

        nlohmann::json m_details;
        bool m_initialized;
    };

    class change_settings_call : public auth_handler_impl {
    public:
        change_settings_call(session& session, const nlohmann::json& settings);

    private:
        state_type call_impl() override;

        void initialize();

        const nlohmann::json m_settings;
        nlohmann::json m_nlocktime_value;
        bool m_initialized;
    };

    class change_settings_twofactor_call : public auth_handler_impl {
    public:
        change_settings_twofactor_call(
            session& session, const std::string& method_to_update, const nlohmann::json& details);

    private:
        state_type call_impl() override;

        void initialize();
        state_type on_init_done(const std::string& new_action);

        nlohmann::json m_current_config;
        const std::string m_method_to_update;
        nlohmann::json m_details;
        nlohmann::json m_gauth_data;
        bool m_enabling;
        bool m_initialized;
    };

    class update_subaccount_call : public auth_handler_impl {
    public:
        update_subaccount_call(session& session, const nlohmann::json& details);

    private:
        state_type call_impl() override;

        const nlohmann::json m_details;
    };

    class change_limits_call : public auth_handler_impl {
    public:
        change_limits_call(session& session, const nlohmann::json& details);

    private:
        state_type call_impl() override;

        nlohmann::json m_limit_details;
        bool m_initialized;
    };

    class remove_account_call : public auth_handler_impl {
    public:
        explicit remove_account_call(session& session);

    private:
        state_type call_impl() override;
        bool m_initialized;
    };

    class send_transaction_call final : public auth_handler_impl {
    public:
        send_transaction_call(session& session, const nlohmann::json& tx_details);

        void request_code(const std::string& method) override;

    private:
        state_type call_impl() override;

        void initialize();
        void create_twofactor_data();

        nlohmann::json m_tx_details;
        nlohmann::json m_limit_details;
        uint64_t m_bump_amount;
        bool m_twofactor_required;
        bool m_under_limit;
        bool m_initialized;
    };

    class twofactor_reset_call : public auth_handler_impl {
    public:
        twofactor_reset_call(session& session, const std::string& email, bool is_dispute, bool is_undo);

    private:
        state_type call_impl() override;

        const std::string m_reset_email;
        const bool m_is_dispute;
        const bool m_is_undo;
        bool m_confirming;
    };

    class twofactor_cancel_reset_call final : public auth_handler_impl {
    public:
        explicit twofactor_cancel_reset_call(session& session);

    private:
        state_type call_impl() override;
        bool m_initialized;
    };

    class locktime_call : public auth_handler_impl {
    public:
        locktime_call(session& session, const nlohmann::json& params, bool is_csv);

    private:
        state_type call_impl() override;

        nlohmann::json m_params;
        bool m_initialized;
    };
} // namespace sdk
} // namespace ga
#endif
