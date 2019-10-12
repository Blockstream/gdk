#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__) || defined(__GNUG__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#else
// ??
#endif

#include "ga_rpc.hpp"
#include "exception.hpp"
#include "logging.hpp"

namespace ga {
namespace sdk {

    static const std::string TOR_SOCKS5_PREFIX("socks5://");

    static inline void check_code(const int32_t return_code)
    {
        switch (return_code) {
        case GA_OK:
            return;

        case GA_RECONNECT:
        case GA_SESSION_LOST:
            throw reconnect_error();

        case GA_TIMEOUT:
            throw timeout_error();

        case GA_NOT_AUTHORIZED:
            throw login_error(""); // TODO: msg from rust

        case GA_ERROR:
        default:
            throw std::runtime_error("call failed with: " + std::to_string(return_code));
            break;
        }
    }

    ga_rpc::ga_rpc(const nlohmann::json& net_params, const nlohmann::json& networks)
        : m_netparams(ga::sdk::network_parameters(net_params))
    {
        GDKRPC_create_session(&m_session, gdkrpc_json(networks).get());
    }

    ga_rpc::~ga_rpc()
    {
        GDKRPC_destroy_session(m_session);
        // gdk_rpc cleanup
    }

    void ga_rpc::on_failed_login() {}

    bool ga_rpc::is_connected(const nlohmann::json& net_params)
    {
        throw std::runtime_error("is_connected not implemented");
    }

    void ga_rpc::set_ping_fail_handler(ping_fail_t handler) {}
    void ga_rpc::set_heartbeat_timeout_handler(websocketpp::pong_timeout_handler)
    {
        // throw std::runtime_error("set_heartbeat_timeout_handler not implemented");
    }

    bool ga_rpc::reconnect()
    {
        ga_rpc::disconnect();
        ga_rpc::connect();
        return true;
    }

    void ga_rpc::reconnect_hint(bool enable, bool restart)
    {
        // TODO (will): is this even needed for gdk-rpc?
        // m_network_control.set_enabled(enable);
        // if (restart) {
        //     stop_reconnect();
        // }
    }

    void ga_rpc::try_reconnect()
    {
        // TODO (will): is this even needed for gdk-rpc?
        reconnect();
    }

    void ga_rpc::tor_sleep_hint(const std::string& hint)
    {
        if (m_tor_ctrl) {
            m_tor_ctrl->tor_sleep_hint(hint);
        }
    }

    std::string ga_rpc::get_tor_socks5()
    {
        return m_tor_ctrl ? m_tor_ctrl->wait_for_socks5(DEFAULT_TOR_SOCKS_WAIT, nullptr) : std::string{};
    }

    void ga_rpc::connect()
    {
        if (m_netparams.use_tor() && m_netparams.socks5().empty()) {
            m_tor_ctrl = tor_controller::get_shared_ref();
            std::string full_socks5
                = m_tor_ctrl->wait_for_socks5(DEFAULT_TOR_SOCKS_WAIT, [&](std::shared_ptr<tor_bootstrap_phase> phase) {
                      emit_notification("tor",
                          { { "tag", phase->tag }, { "summary", phase->summary }, { "progress", phase->progress } });
                  });

            if (full_socks5.empty()) {
                throw timeout_error();
            }

            GDK_RUNTIME_ASSERT(full_socks5.size() > TOR_SOCKS5_PREFIX.size());
            full_socks5.erase(0, TOR_SOCKS5_PREFIX.size());

            m_netparams.get_json_mut()["socks5"] = full_socks5;

            GDK_LOG_SEV(log_level::info) << "tor_socks address " << m_netparams.socks5();
        }

        check_code(GDKRPC_connect(m_session, gdkrpc_json(m_netparams.get_json()).get()));
    }

    void ga_rpc::disconnect() { GDKRPC_disconnect(m_session); }

    nlohmann::json ga_rpc::http_get(const nlohmann::json& params)
    {
        throw std::runtime_error("http_get not implemented");
    }
    nlohmann::json ga_rpc::refresh_assets(const nlohmann::json& params) { return nlohmann::json(); }
    nlohmann::json ga_rpc::validate_asset_domain_name(const nlohmann::json& params) { return nlohmann::json(); }

    void ga_rpc::register_user(const std::string& mnemonic, bool supports_csv) {}
    void ga_rpc::register_user(const std::string& master_pub_key_hex, const std::string& master_chain_code_hex,
        const std::string& gait_path_hex, bool supports_csv)
    {
    }

    std::string ga_rpc::get_challenge(const std::string& address) { throw std::runtime_error("not implemented"); }
    void ga_rpc::authenticate(const std::string& sig_der_hex, const std::string& path_hex, const std::string& device_id,
        const nlohmann::json& hw_device)
    {
        throw std::runtime_error("not implemented");
    }
    void ga_rpc::register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs)
    {
        throw std::runtime_error("register_subaccount_xpubs not implemented");
    }
    void ga_rpc::login(const std::string& mnemonic, const std::string& password)
    {
        check_code(GDKRPC_login(m_session, nullptr, mnemonic.c_str(), password.c_str()));
    }
    void ga_rpc::login_with_pin(const std::string& pin, const nlohmann::json& pin_data)
    {
        throw std::runtime_error("login_with_pin not implemented");
    }
    void ga_rpc::login_watch_only(const std::string& username, const std::string& password)
    {
        throw std::runtime_error("login_watch_only not implemented");
    }
    bool ga_rpc::set_watch_only(const std::string& username, const std::string& password)
    {
        throw std::runtime_error("set_watch_only not implemented");
    }
    std::string ga_rpc::get_watch_only_username()
    {
        // TODO
        return std::string{};
    }
    bool ga_rpc::remove_account(const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("remove_account not implemented");
    }

    uint32_t ga_rpc::get_next_subaccount() { throw std::runtime_error("get_next_subaccount not implemented"); }
    nlohmann::json ga_rpc::create_subaccount(const nlohmann::json& details)
    {
        throw std::runtime_error("create_subaccount not implemented");
    }
    nlohmann::json ga_rpc::create_subaccount(
        const nlohmann::json& details, uint32_t subaccount, const std::string& xpub)
    {
        throw std::runtime_error("create_subaccount not implemented");
    }

    void ga_rpc::change_settings_limits(const nlohmann::json& limit_details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("change_settings_limits not implemented");
    }
    nlohmann::json ga_rpc::get_transactions(const nlohmann::json& details)
    {
        GDKRPC_json* ret;
        nlohmann::json actual_details;

        if (details.is_null()) {
            actual_details["page_id"] = 0;
        } else {
            actual_details = details;
        }

        auto converted_details = gdkrpc_json(actual_details);

        int ok = GDKRPC_get_transactions(m_session, converted_details.get(), &ret);

        if (ok != GA_OK) {
            return nlohmann::json{};
        }

        return gdkrpc_json::from_serde(ret);
    }

    void ga_rpc::gdkrpc_notif_handler(void* self_context, GDKRPC_json* json)
    {
        // "new" needed because we want that to be on the heap. the notif handler will free it
        nlohmann::json* converted_heap = new nlohmann::json(gdkrpc_json::from_serde(json));
        const GA_json* as_ptr = reinterpret_cast<const GA_json*>(converted_heap);

        ga_rpc* self = static_cast<ga_rpc*>(self_context);
        if (self->m_ga_notif_handler) {
            self->m_ga_notif_handler(self->m_ga_notif_context, as_ptr);
        }
    }

    void ga_rpc::emit_notification(std::string event, nlohmann::json details)
    {
        const nlohmann::json* heap_json = new nlohmann::json({ { "event", event }, { event, details } });
        const GA_json* as_ptr = reinterpret_cast<const GA_json*>(heap_json);

        if (m_ga_notif_handler) {
            m_ga_notif_handler(m_ga_notif_context, as_ptr);
        }
    }

    void ga_rpc::set_notification_handler(GA_notification_handler handler, void* context)
    {
        m_ga_notif_handler = handler;
        m_ga_notif_context = context;

        GDKRPC_set_notification_handler(m_session, ga::sdk::ga_rpc::gdkrpc_notif_handler, this);
    }

    nlohmann::json ga_rpc::get_receive_address(const nlohmann::json& details)
    {
        GDKRPC_json* output;
        GDKRPC_get_receive_address(m_session, gdkrpc_json(details).get(), &output);
        return gdkrpc_json::from_serde(output);
    }

    nlohmann::json ga_rpc::get_subaccounts()
    {
        GDKRPC_json* output;
        GDKRPC_get_subaccounts(m_session, &output);
        return gdkrpc_json::from_serde(output);
    }

    nlohmann::json ga_rpc::get_subaccount(uint32_t subaccount)
    {
        GDKRPC_json* output;
        GDKRPC_get_subaccount(m_session, subaccount, &output);
        return gdkrpc_json::from_serde(output);
    }

    void ga_rpc::rename_subaccount(uint32_t subaccount, const std::string& new_name)
    {
        throw std::runtime_error("rename_subaccount not implemented");
    }

    nlohmann::json ga_rpc::get_balance(const nlohmann::json& details)
    {
        GDKRPC_json* output;
        GDKRPC_get_balance(m_session, gdkrpc_json(details).get(), &output);
        return gdkrpc_json::from_serde(output);
    }

    nlohmann::json ga_rpc::get_available_currencies() const
    {

        GDKRPC_json* output;
        GDKRPC_get_available_currencies(m_session, &output);
        return gdkrpc_json::from_serde(output);
    }

    nlohmann::json ga_rpc::get_hw_device() const { return nlohmann::json{}; }

    bool ga_rpc::is_rbf_enabled() const { throw std::runtime_error("is_rbf_enabled not implemented"); }
    bool ga_rpc::is_watch_only() const { return false; }

    nlohmann::json ga_rpc::get_settings()
    {
        GDKRPC_json* output;
        GDKRPC_get_settings(m_session, &output);
        return gdkrpc_json::from_serde(output);
    }

    void ga_rpc::change_settings(const nlohmann::json& settings)
    {
        throw std::runtime_error("change_settings not implemented");
    }

    nlohmann::json ga_rpc::get_twofactor_config(bool reset_cached)
    {
        GDKRPC_json* output;
        GDKRPC_get_twofactor_config(m_session, &output);
        return gdkrpc_json::from_serde(output);
    }

    std::vector<std::string> ga_rpc::get_all_twofactor_methods()
    {
        throw std::runtime_error("get_all_twofactor_methods not implemented");
    }
    std::vector<std::string> ga_rpc::get_enabled_twofactor_methods() { return {}; }

    void ga_rpc::set_email(const std::string& email, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("set_email not implemented");
    }
    void ga_rpc::activate_email(const std::string& code) { throw std::runtime_error("activate_email not implemented"); }
    void ga_rpc::init_enable_twofactor(
        const std::string& method, const std::string& data, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("init_enable_twofactor not implemented");
    }
    void ga_rpc::enable_gauth(const std::string& code, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("enable_gauth not implemented");
    }
    void ga_rpc::enable_twofactor(const std::string& method, const std::string& code)
    {
        throw std::runtime_error("enable_twofactor not implemented");
    }
    void ga_rpc::disable_twofactor(const std::string& method, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("disable_twofactor not implemented");
    }
    void ga_rpc::auth_handler_request_code(
        const std::string& method, const std::string& action, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("auth_handler_request_code not implemented");
    }
    nlohmann::json ga_rpc::reset_twofactor(const std::string& email)
    {
        throw std::runtime_error("reset_twofactor not implemented");
    }
    nlohmann::json ga_rpc::confirm_twofactor_reset(
        const std::string& email, bool is_dispute, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("confirm_twofactor_reset not implemented");
    }
    nlohmann::json ga_rpc::cancel_twofactor_reset(const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("cancel_twofactor_reset not implemented");
    }
    nlohmann::json ga_rpc::set_pin(const std::string& mnemonic, const std::string& pin, const std::string& device_id)
    {
        throw std::runtime_error("set_pin not implemented");
    }
    nlohmann::json ga_rpc::get_unspent_outputs(const nlohmann::json& details)
    {
        throw std::runtime_error("get_unspent_outputs not implemented");
    }
    nlohmann::json ga_rpc::get_unspent_outputs_for_private_key(
        const std::string& private_key, const std::string& password, uint32_t unused)
    {
        throw std::runtime_error("get_unspent_outputs_for_private_key not implemented");
    }
    nlohmann::json ga_rpc::get_transaction_details(const std::string& txhash_hex) const
    {
        throw std::runtime_error("get_transaction_details not implemented");
    }

    nlohmann::json ga_rpc::create_transaction(const nlohmann::json& details)
    {
        GDKRPC_json* transaction;
        GDKRPC_create_transaction(m_session, gdkrpc_json(details).get(), &transaction);
        return gdkrpc_json::from_serde(transaction);
    }

    nlohmann::json ga_rpc::sign_transaction(const nlohmann::json& details)
    {
        GDKRPC_json* signed_tx;
        GDKRPC_sign_transaction(m_session, gdkrpc_json(details).get(), &signed_tx);
        return gdkrpc_json::from_serde(signed_tx);
    }

    nlohmann::json ga_rpc::send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        GDKRPC_json* res;
        GDK_LOG_SEV(log_level::info) << "what";
        GDKRPC_send_transaction(m_session, gdkrpc_json(details).get(), &res);
        GDK_LOG_SEV(log_level::info) << "what2";
        return gdkrpc_json::from_serde(res);
    }

    std::string ga_rpc::broadcast_transaction(const std::string& tx_hex)
    {
        char* tx_hash;
        GDKRPC_broadcast_transaction(m_session, tx_hex.c_str(), &tx_hash);
        auto res = std::string(tx_hash);
        GA_destroy_string(tx_hash);
        return res;
    }

    void ga_rpc::sign_input(const wally_tx_ptr& tx, uint32_t index, const nlohmann::json& u, const std::string& der_hex)
    {
        throw std::runtime_error("sign_input not implemented");
    }

    void ga_rpc::send_nlocktimes() { throw std::runtime_error("send_nlocktimes not implemented"); }
    nlohmann::json ga_rpc::get_expired_deposits(const nlohmann::json& deposit_details)
    {
        throw std::runtime_error("get_expired_deposits not implemented");
    }
    void ga_rpc::set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("set_csvtime not implemented");
    }
    void ga_rpc::set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("set_nlocktime not implemented");
    }

    void ga_rpc::set_transaction_memo(
        const std::string& txhash_hex, const std::string& memo, const std::string& memo_type)
    {
        throw std::runtime_error("set_transaction_memo not implemented");
    }

    nlohmann::json ga_rpc::get_fee_estimates()
    {
        GDKRPC_json* output;
        GDKRPC_get_fee_estimates(m_session, &output);
        return gdkrpc_json::from_serde(output);
    }

    std::string ga_rpc::get_mnemonic_passphrase(const std::string& password)
    {
        char* mnemonic = NULL;
        check_code(GDKRPC_get_mnemonic_passphrase(m_session, password.c_str(), &mnemonic));

        const auto result = std::string(mnemonic, strlen(mnemonic));
        GA_destroy_string(mnemonic);

        return result;
    }

    std::string ga_rpc::get_system_message()
    {
        // TODO
        return std::string{};
    }

    std::pair<std::string, std::vector<uint32_t>> ga_rpc::get_system_message_info(const std::string& system_message)
    {
        throw std::runtime_error("get_system_message_info not implemented");
    }
    void ga_rpc::ack_system_message(const std::string& system_message)
    {
        throw std::runtime_error("ack_system_message not implemented");
    }
    void ga_rpc::ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex)
    {
        throw std::runtime_error("ack_system_message not implemented");
    }

    nlohmann::json ga_rpc::convert_amount(const nlohmann::json& amount_json) const
    {
        GDKRPC_json* output;
        GDKRPC_convert_amount(m_session, gdkrpc_json(amount_json).get(), &output);
        return gdkrpc_json::from_serde(output);
    }

    amount ga_rpc::get_min_fee_rate() const { throw std::runtime_error("get_min_fee_rate not implemented"); }
    amount ga_rpc::get_default_fee_rate() const { throw std::runtime_error("get_default_fee_rate not implemented"); }
    bool ga_rpc::have_subaccounts() const { throw std::runtime_error("have_subaccounts not implemented"); }
    uint32_t ga_rpc::get_block_height() const { throw std::runtime_error("get_block_height not implemented"); }
    amount ga_rpc::get_dust_threshold() const { throw std::runtime_error("get_dust_threshold not implemented"); }
    nlohmann::json ga_rpc::get_spending_limits() const
    {
        throw std::runtime_error("get_spending_limits not implemented");
    }
    bool ga_rpc::is_spending_limits_decrease(const nlohmann::json& limit_details)
    {
        throw std::runtime_error("is_spending_limits_decrease not implemented");
    }

    const network_parameters& ga_rpc::get_network_parameters() const { return m_netparams; }

    signer& ga_rpc::get_signer() { throw std::runtime_error("get_signer not implemented"); }
    ga_pubkeys& ga_rpc::get_ga_pubkeys() { throw std::runtime_error("get_ga_pubkeys not implemented"); }
    ga_user_pubkeys& ga_rpc::get_user_pubkeys() { throw std::runtime_error("get_user_pubkeys not implemented"); }
    ga_user_pubkeys& ga_rpc::get_recovery_pubkeys()
    {
        throw std::runtime_error("get_recovery_pubkeys not implemented");
    }

    void ga_rpc::set_blinding_nonce(const std::string& pubkey, const std::string& script, const std::string& nonce)
    {
        throw std::runtime_error("set_blinding_nonce not yet implemented");
    }

    bool ga_rpc::has_blinding_nonce(const std::string& pubkey, const std::string& script)
    {
        throw std::runtime_error("hash_blinding_nonce not yet implemented");
    }

    liquid_support_level ga_rpc::hw_liquid_support() const
    {
        throw std::runtime_error("hw_liquid_support not yet implemented");
    }

    std::string ga_rpc::get_blinding_key_for_script(const std::string& script_hex)
    {
        throw std::runtime_error("get_blinding_key_for_script not yet implemented");
    }

    nlohmann::json ga_rpc::get_blinded_scripts(const nlohmann::json& details)
    {
        throw std::runtime_error("get_blinded_scripts not yet implemented");
    }

    std::string ga_rpc::blind_address(const std::string& unblinded_addr, const std::string& blinding_key_hex)
    {
        throw std::runtime_error("blind_address not yet implemented");
    }

    std::string ga_rpc::extract_confidential_address(const std::string& blinded_address)
    {
        throw std::runtime_error("extract_confidential_address not yet implemented");
    }

    void ga_rpc::upload_confidential_addresses(uint32_t subaccount, std::vector<std::string> confidential_addresses)
    {
        throw std::runtime_error("upload_confidential_addresses not yet implemented");
    }

    void ga_rpc::blind_output(const nlohmann::json& details, const wally_tx_ptr& tx, uint32_t index,
        const nlohmann::json& o, const std::string& asset_commitment_hex, const std::string& value_commitment_hex,
        const std::string& abf, const std::string& vbf)
    {
        throw std::runtime_error("blind_output not yet implemented");
    }

    void ga_rpc::set_local_encryption_key(byte_span_t key) {}

    void ga_rpc::disable_all_pin_logins() {}

} // namespace sdk
} // namespace ga
