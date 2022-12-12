#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__) || defined(__GNUG__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#else
// ??
#endif

#include "../subprojects/gdk_rust/gdk_rust.h"

#include "exception.hpp"
#include "ga_lightning.hpp"
#include "ga_strings.hpp"
#include "logging.hpp"
#include "session.hpp"
#include "signer.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

namespace ga {
namespace sdk {

    ga_lightning::ga_lightning(network_parameters&& net_params)
        : session_impl(std::move(net_params))
    {
        auto np = m_net_params.get_json();
        const auto res = GDKRUST_create_session(&m_session, np.dump().c_str());
        GDK_RUNTIME_ASSERT(res == GA_OK && m_session);
    }

    ga_lightning::~ga_lightning()
    {
        GDKRUST_destroy_session(m_session);
        // gdk_rust cleanup
    }

    void ga_lightning::connect()
    {
        // TODO
    }

    void ga_lightning::reconnect() { throw std::runtime_error("reconnect not implemented"); }

    void ga_lightning::reconnect_hint(const nlohmann::json& hint)
    {
        throw std::runtime_error("reconnect_hint not implemented");
    }

    void ga_lightning::disconnect() { throw std::runtime_error("disconnect not implemented"); }

    nlohmann::json ga_lightning::validate_asset_domain_name(const nlohmann::json& params)
    {
        throw std::runtime_error("validate_asset_domain_name not implemented");
    }

    void ga_lightning::set_local_encryption_keys(const pub_key_t& /*public_key*/, std::shared_ptr<signer> signer)
    {
        throw std::runtime_error("set_local_encryption_keys not implemented");
    }

    void ga_lightning::start_sync_threads() { throw std::runtime_error("start_sync_threads not implemented"); }

    std::string ga_lightning::get_challenge(const pub_key_t& /*public_key*/)
    {
        throw std::runtime_error("get_challenge not implemented");
    }

    nlohmann::json ga_lightning::authenticate(const std::string& /*sig_der_hex*/, const std::string& /*path_hex*/,
        const std::string& /*root_bip32_xpub*/, std::shared_ptr<signer> signer)
    {
        throw std::runtime_error("authenticate not implemented");
    }

    void ga_lightning::register_subaccount_xpubs(
        const std::vector<uint32_t>& pointers, const std::vector<std::string>& bip32_xpubs)
    {
        throw std::runtime_error("not implemented");
    }

    nlohmann::json ga_lightning::login(std::shared_ptr<signer> signer)
    {
        throw std::runtime_error("login not implemented");
    }
    nlohmann::json ga_lightning::credentials_from_pin_data(const nlohmann::json& pin_data)
    {
        throw std::runtime_error("credentials_from_pin_data not implemented");
    }
    nlohmann::json ga_lightning::login_wo(std::shared_ptr<signer> signer)
    {
        throw std::runtime_error("login_wo not implemented");
    }
    bool ga_lightning::set_wo_credentials(const std::string& username, const std::string& password)
    {
        throw std::runtime_error("set_wo_credentials not implemented");
    }
    std::string ga_lightning::get_wo_username() { throw std::runtime_error("get_wo_username not implemented"); }
    bool ga_lightning::remove_account(const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("remove_account not implemented");
    }

    bool ga_lightning::discover_subaccount(const std::string& xpub, const std::string& type)
    {
        throw std::runtime_error("discover_subaccount not implemented");
    }

    uint32_t ga_lightning::get_next_subaccount(const std::string& type)
    {
        throw std::runtime_error("discover_subaccount not implemented");
    }

    nlohmann::json ga_lightning::create_subaccount(
        const nlohmann::json& details, uint32_t subaccount, const std::string& xpub)
    {
        throw std::runtime_error("create_subaccount not implemented");
    }

    std::pair<std::string, bool> ga_lightning::get_cached_master_blinding_key()
    {
        throw std::runtime_error("get_cached_master_blinding_key not implemented");
    }

    void ga_lightning::set_cached_master_blinding_key(const std::string& master_blinding_key_hex)
    {
        throw std::runtime_error("set_cached_master_blinding_key not implemented");
    }

    void ga_lightning::change_settings_limits(const nlohmann::json& limit_details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("change_settings_limits not implemented");
    }

    nlohmann::json ga_lightning::get_transactions(const nlohmann::json& details)
    {
        throw std::runtime_error("get_transactions not implemented");
    }

    void ga_lightning::GDKRUST_notif_handler(void* self_context, char* json)
    {
        throw std::runtime_error("GDKRUST_notif_handler not implemented");
    }

    void ga_lightning::set_notification_handler(GA_notification_handler handler, void* context)
    {
        session_impl::set_notification_handler(handler, context);
        GDKRUST_set_notification_handler(m_session, GDKRUST_notif_handler, this);
    }

    nlohmann::json ga_lightning::get_receive_address(const nlohmann::json& details)
    {
        throw std::runtime_error("get_receive_address not implemented");
    }

    nlohmann::json ga_lightning::get_previous_addresses(const nlohmann::json& details)
    {
        throw std::runtime_error("get_previous_addresses not implemented");
    }

    nlohmann::json ga_lightning::get_subaccounts() { throw std::runtime_error("get_subaccounts not implemented"); }

    std::vector<uint32_t> ga_lightning::get_subaccount_pointers()
    {
        throw std::runtime_error("get_subaccounts not implemented");
    }

    nlohmann::json ga_lightning::get_subaccount(uint32_t subaccount)
    {
        throw std::runtime_error("get_subaccounts not implemented");
    }

    void ga_lightning::rename_subaccount(uint32_t subaccount, const std::string& new_name)
    {
        throw std::runtime_error("get_subaccounts not implemented");
    }

    void ga_lightning::set_subaccount_hidden(uint32_t subaccount, bool is_hidden)
    {
        throw std::runtime_error("get_subaccounts not implemented");
    }

    std::vector<uint32_t> ga_lightning::get_subaccount_root_path(uint32_t subaccount)
    {
        throw std::runtime_error("get_subaccounts not implemented");
    }

    std::vector<uint32_t> ga_lightning::get_subaccount_full_path(
        uint32_t subaccount, uint32_t pointer, bool is_internal)
    {
        throw std::runtime_error("get_subaccounts not implemented");
    }

    nlohmann::json ga_lightning::get_available_currencies() const
    {
        throw std::runtime_error("get_subaccounts not implemented");
    }

    bool ga_lightning::is_rbf_enabled() const { throw std::runtime_error("is_rbf_enabled not implemented"); }
    bool ga_lightning::is_watch_only() const { throw std::runtime_error("is_watch_only not implemented"); }
    void ga_lightning::ensure_full_session() { throw std::runtime_error("ensure_full_session not implemented"); }

    nlohmann::json ga_lightning::get_settings() { throw std::runtime_error("get_settings not implemented"); }

    nlohmann::json ga_lightning::get_post_login_data()
    {
        throw std::runtime_error("get_post_login_data not implemented");
    }

    void ga_lightning::change_settings(const nlohmann::json& settings)
    {
        throw std::runtime_error("change_settings not implemented");
    }

    nlohmann::json ga_lightning::get_twofactor_config(bool reset_cached)
    {
        throw std::runtime_error("get_twofactor_config not implemented");
    }

    std::vector<std::string> ga_lightning::get_enabled_twofactor_methods()
    {
        throw std::runtime_error("get_enabled_twofactor_methods not implemented");
    }

    void ga_lightning::set_email(const std::string& email, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("set_email not implemented");
    }
    void ga_lightning::activate_email(const std::string& code)
    {
        throw std::runtime_error("activate_email not implemented");
    }
    nlohmann::json ga_lightning::init_enable_twofactor(
        const std::string& method, const std::string& data, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("init_enable_twofactor not implemented");
    }
    void ga_lightning::enable_gauth(const std::string& code, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("enable_gauth not implemented");
    }
    void ga_lightning::enable_twofactor(const std::string& method, const std::string& code)
    {
        throw std::runtime_error("enable_twofactor not implemented");
    }
    void ga_lightning::disable_twofactor(const std::string& method, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("disable_twofactor not implemented");
    }

    nlohmann::json ga_lightning::auth_handler_request_code(
        const std::string& method, const std::string& action, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("auth_handler_request_code not implemented");
    }

    std::string ga_lightning::auth_handler_request_proxy_code(
        const std::string& action, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("auth_handler_request_proxy_code not implemented");
    }

    nlohmann::json ga_lightning::request_twofactor_reset(const std::string& email)
    {
        throw std::runtime_error("request_twofactor_reset not implemented");
    }

    nlohmann::json ga_lightning::confirm_twofactor_reset(
        const std::string& email, bool is_dispute, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("confirm_twofactor_reset not implemented");
    }

    nlohmann::json ga_lightning::request_undo_twofactor_reset(const std::string& email)
    {
        throw std::runtime_error("request_undo_twofactor_reset not implemented");
    }

    nlohmann::json ga_lightning::confirm_undo_twofactor_reset(
        const std::string& email, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("confirm_undo_twofactor_reset not implemented");
    }

    nlohmann::json ga_lightning::cancel_twofactor_reset(const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("cancel_twofactor_reset not implemented");
    }

    nlohmann::json ga_lightning::encrypt_with_pin(const nlohmann::json& details)
    {
        throw std::runtime_error("encrypt_with_pin not implemented");
    }

    nlohmann::json ga_lightning::get_unspent_outputs(
        const nlohmann::json& details, unique_pubkeys_and_scripts_t& /*missing*/)
    {
        throw std::runtime_error("get_unspent_outputs not implemented");
    }

    nlohmann::json ga_lightning::get_unspent_outputs_for_private_key(
        const std::string& private_key, const std::string& password, uint32_t unused)
    {
        throw std::runtime_error("get_unspent_outputs_for_private_key not implemented");
    }

    nlohmann::json ga_lightning::set_unspent_outputs_status(
        const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("set_unspent_outputs_status not implemented");
    }

    wally_tx_ptr ga_lightning::get_raw_transaction_details(const std::string& txhash_hex) const
    {
        throw std::runtime_error("get_raw_transaction_details not implemented");
    }

    nlohmann::json ga_lightning::get_transaction_details(const std::string& txhash_hex) const
    {
        throw std::runtime_error("get_transaction_details not implemented");
    }

    nlohmann::json ga_lightning::create_transaction(const nlohmann::json& details)
    {
        throw std::runtime_error("create_transaction not implemented");
    }

    nlohmann::json ga_lightning::user_sign_transaction(const nlohmann::json& details)
    {
        throw std::runtime_error("user_sign_transaction not implemented");
    }

    nlohmann::json ga_lightning::service_sign_transaction(
        const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("service_sign_transaction not implemented");
    }

    nlohmann::json ga_lightning::psbt_sign(const nlohmann::json& details)
    {
        throw std::runtime_error("psbt_sign not implemented");
    }

    nlohmann::json ga_lightning::send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("send_transaction not implemented");
    }

    std::string ga_lightning::broadcast_transaction(const std::string& tx_hex)
    {
        throw std::runtime_error("broadcast_transaction not implemented");
    }

    void ga_lightning::send_nlocktimes() { throw std::runtime_error("send_nlocktimes not implemented"); }

    void ga_lightning::set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("set_csvtime not implemented");
    }
    void ga_lightning::set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("set_nlocktime not implemented");
    }

    void ga_lightning::set_transaction_memo(const std::string& txhash_hex, const std::string& memo)
    {
        throw std::runtime_error("set_transaction_memo not implemented");
    }

    nlohmann::json ga_lightning::get_fee_estimates() { throw std::runtime_error("get_fee_estimates not implemented"); }

    std::string ga_lightning::get_system_message() { throw std::runtime_error("get_system_message not implemented"); }

    std::pair<std::string, std::vector<uint32_t>> ga_lightning::get_system_message_info(
        const std::string& system_message)
    {
        throw std::runtime_error("get_system_message_info not implemented");
    }

    void ga_lightning::ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex)
    {
        throw std::runtime_error("ack_system_message not implemented");
    }

    nlohmann::json ga_lightning::convert_amount(const nlohmann::json& amount_json) const
    {
        throw std::runtime_error("convert_amount not implemented");
    }

    amount ga_lightning::get_min_fee_rate() const { throw std::runtime_error("get_min_fee_rate not implemented"); }
    amount ga_lightning::get_default_fee_rate() const
    {
        throw std::runtime_error("get_default_fee_rate not implemented");
    }
    uint32_t ga_lightning::get_block_height() const { throw std::runtime_error("get_block_height not implemented"); }
    nlohmann::json ga_lightning::get_spending_limits() const
    {
        throw std::runtime_error("get_spending_limits not implemented");
    }
    bool ga_lightning::is_spending_limits_decrease(const nlohmann::json& limit_details)
    {
        throw std::runtime_error("is_spending_limits_decrease not implemented");
    }

    ga_pubkeys& ga_lightning::get_ga_pubkeys() { throw std::runtime_error("get_ga_pubkeys not implemented"); }
    user_pubkeys& ga_lightning::get_recovery_pubkeys()
    {
        throw std::runtime_error("get_recovery_pubkeys not implemented");
    }

    void ga_lightning::upload_confidential_addresses(
        uint32_t subaccount, const std::vector<std::string>& confidential_addresses)
    {
        throw std::runtime_error("upload_confidential_addresses not yet implemented");
    }

    void ga_lightning::disable_all_pin_logins()
    {
        throw std::runtime_error("disable_all_pin_logins not yet implemented");
    }

    nlohmann::json ga_lightning::gl_call(const char* method, const nlohmann::json& params)
    {
        return rust_call(method, params, m_session);
    }

} // namespace sdk
} // namespace ga
