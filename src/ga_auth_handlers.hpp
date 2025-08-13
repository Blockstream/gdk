#ifndef GDK_GA_AUTH_HANDLERS_HPP
#define GDK_GA_AUTH_HANDLERS_HPP
#pragma once

#include "auth_handler.hpp"

namespace green {

    class Psbt;

    class register_call : public auth_handler_impl {
    public:
        register_call(session& session, nlohmann::json hw_device, nlohmann::json credential_data);

    private:
        state_type call_impl() override;

        nlohmann::json m_hw_device;
        nlohmann::json m_credential_data;
        std::shared_ptr<signer> m_registration_signer;
    };

    class login_user_call : public auth_handler_impl {
    public:
        login_user_call(session& session, nlohmann::json hw_device, nlohmann::json credential_data);

    private:
        state_type call_impl() override;
        state_type request_subaccount_xpubs();
        void upload_ca();

        nlohmann::json m_hw_device;
        nlohmann::json m_credential_data;
        std::string m_challenge;
        std::string m_master_bip32_xpub;
        nlohmann::json m_subaccount_pointers;
    };

    class create_subaccount_call : public auth_handler_impl {
    public:
        create_subaccount_call(session& session, nlohmann::json details);

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

    class cache_control_call : public auth_handler_impl {
    public:
        cache_control_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
    };

    class sign_transaction_call : public auth_handler_impl {
    public:
        sign_transaction_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;
        void initialize();
        void sign_user_inputs();
        void on_next_handler_complete(auth_handler* next_handler) override;

        nlohmann::json m_details;
        std::vector<std::string> m_sweep_private_keys;
        std::vector<std::string> m_sweep_signatures;
        bool m_initialized;
        bool m_user_signed;
        bool m_server_signed;
    };

    class psbt_sign_call : public auth_handler_impl {
    public:
        psbt_sign_call(session& session, nlohmann::json details);
        ~psbt_sign_call();

    private:
        state_type call_impl() override;
        void on_next_handler_complete(auth_handler* next_handler) override;

        nlohmann::json m_details;
        nlohmann::json m_signing_details;
        std::unique_ptr<Psbt> m_psbt;
        bool m_is_synced;
    };

    class psbt_from_json_call : public auth_handler_impl {
    public:
        psbt_from_json_call(session& session, nlohmann::json details);
        ~psbt_from_json_call();

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
    };

    class psbt_get_details_call : public auth_handler_impl {
    public:
        psbt_get_details_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
        bool m_is_synced;
    };

    class get_receive_address_call : public auth_handler_impl {
    public:
        get_receive_address_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;
        void initialize();

        nlohmann::json m_details;
        bool m_initialized;
    };

    class get_previous_addresses_call : public auth_handler_impl {
    public:
        get_previous_addresses_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;
        void initialize();

        nlohmann::json m_details;
        bool m_initialized;
    };

    class create_transaction_call : public auth_handler_impl {
    public:
        create_transaction_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
    };

    class blind_transaction_call : public auth_handler_impl {
    public:
        blind_transaction_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
    };

    class get_subaccounts_call : public auth_handler_impl {
    public:
        get_subaccounts_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
        std::vector<std::string> m_found;
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
        get_transactions_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
    };

    class get_unspent_outputs_call : public auth_handler_impl {
    public:
        get_unspent_outputs_call(session& session, nlohmann::json details, const std::string& name = std::string());

    protected:
        state_type call_impl() override;

    private:
        void initialize();
        void filter_result(bool encache);
        std::string get_sort_by() const;

        nlohmann::json m_details;
        bool m_initialized;
    };

    class get_unspent_outputs_for_private_key_call : public auth_handler_impl {
    public:
        get_unspent_outputs_for_private_key_call(session& session, nlohmann::json details);

    protected:
        state_type call_impl() override;

    private:
        nlohmann::json m_details;
    };

    class get_balance_call : public get_unspent_outputs_call {
    public:
        get_balance_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;
        void compute_balance();
    };

    class set_unspent_outputs_status_call : public auth_handler_impl {
    public:
        set_unspent_outputs_status_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        void initialize();

        nlohmann::json m_details;
        bool m_initialized;
    };

    class change_settings_call : public auth_handler_impl {
    public:
        change_settings_call(session& session, nlohmann::json settings);

    private:
        state_type call_impl() override;

        void initialize();

        nlohmann::json m_settings;
        nlohmann::json m_nlocktime_value;
        bool m_initialized;
    };

    class change_settings_twofactor_call : public auth_handler_impl {
    public:
        change_settings_twofactor_call(session& session, const std::string& method_to_update, nlohmann::json details);

    private:
        state_type call_impl() override;

        void initialize();
        bool is_sms_backup() const;
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
        update_subaccount_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
    };

    class change_limits_call : public auth_handler_impl {
    public:
        change_limits_call(session& session, nlohmann::json details);

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
        send_transaction_call(session& session, nlohmann::json details, bool sign_only = false);

        void request_code(const std::string& method) override;

    private:
        state_type call_impl() override;

        void initialize();
        void create_twofactor_data();

        nlohmann::json m_details;
        nlohmann::json m_limit_details;
        uint64_t m_bump_amount;
        const std::string m_type; // "send", or "sign" if sign_only == true
        bool m_twofactor_required;
        bool m_under_limit;
        bool m_initialized;
    };

    class broadcast_transaction_call final : public auth_handler_impl {
    public:
        broadcast_transaction_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
    };

    class sign_message_call : public auth_handler_impl {
    public:
        sign_message_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
        nlohmann::json m_address_data;
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
        locktime_call(session& session, nlohmann::json params, bool is_csv);

    private:
        state_type call_impl() override;

        nlohmann::json m_params;
        bool m_initialized;
    };

    class get_credentials_call : public auth_handler_impl {
    public:
        get_credentials_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
    };

    class encrypt_with_pin_call : public auth_handler_impl {
    public:
        encrypt_with_pin_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
    };

    class decrypt_with_pin_call : public auth_handler_impl {
    public:
        decrypt_with_pin_call(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
    };

    class rsa_verify : public auth_handler_impl {
    public:
        rsa_verify(session& session, nlohmann::json details);

    private:
        state_type call_impl() override;

        nlohmann::json m_details;
    };

} // namespace green
#endif
