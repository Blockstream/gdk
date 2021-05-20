#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__) || defined(__GNUG__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#else
// ??
#endif

#include "ga_rust.hpp"
#include "exception.hpp"
#include "logging.hpp"
#include "utils.hpp"

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

    ga_rust::ga_rust(const nlohmann::json& net_params)
        : m_netparams(ga::sdk::network_parameters(net_params))
    {
        GDKRUST_create_session(&m_session, gdkrust_json(m_netparams.get_json()).get());
    }

    ga_rust::~ga_rust()
    {
        call_session("destroy_session", nlohmann::json{});
        // gdk_rust cleanup
    }

    void ga_rust::on_failed_login() {}

    bool ga_rust::is_connected() const { throw std::runtime_error("is_connected not implemented"); }

    void ga_rust::set_ping_fail_handler(ping_fail_t handler) {}
    void ga_rust::set_heartbeat_timeout_handler(websocketpp::pong_timeout_handler)
    {
        // throw std::runtime_error("set_heartbeat_timeout_handler not implemented");
    }

    bool ga_rust::reconnect()
    {
        ga_rust::disconnect();
        if (m_reconnect_restart) {
            ga_rust::connect();
        }
        return true;
    }

    void ga_rust::reconnect_hint(bool enable, bool restart) { m_reconnect_restart = restart; }

    void ga_rust::try_reconnect() { reconnect(); }

    void ga_rust::tor_sleep_hint(const std::string& hint)
    {
        if (m_tor_ctrl) {
            m_tor_ctrl->tor_sleep_hint(hint);
        }
    }

    std::string ga_rust::get_tor_socks5()
    {
        return m_tor_ctrl ? m_tor_ctrl->wait_for_socks5(DEFAULT_TOR_SOCKS_WAIT, nullptr) : std::string{};
    }

    nlohmann::json ga_rust::call_session(const std::string& method, const nlohmann::json& input) const
    {
        GDKRUST_json* ret;
        auto rustinput = gdkrust_json(input).get();
        int res = GDKRUST_call_session(m_session, method.c_str(), rustinput, &ret);
        check_code(res);
        return gdkrust_json::from_serde(ret);
    }

    void ga_rust::connect()
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

        call_session("connect", m_netparams.get_json());
    }

    void ga_rust::disconnect()
    {
        GDK_LOG_SEV(log_level::debug) << "ga_rust::disconnect";
        call_session("disconnect", {});
    }

    nlohmann::json ga_rust::http_request(nlohmann::json params)
    {
        throw std::runtime_error("http_request not implemented");
    }

    nlohmann::json ga_rust::refresh_assets(const nlohmann::json& params)
    {
        return call_session("refresh_assets", params);
    }

    nlohmann::json ga_rust::validate_asset_domain_name(const nlohmann::json& params) { return nlohmann::json(); }

    void ga_rust::register_user(const std::string& mnemonic, bool supports_csv)
    {
        auto details = nlohmann::json{
            { "mnemonic", mnemonic },
            { "supports_csv", supports_csv },
        };

        call_session("register_user", details);
    }

    void ga_rust::register_user(const std::string& master_pub_key_hex, const std::string& master_chain_code_hex,
        const std::string& gait_path_hex, bool supports_csv)
    {
    }

    std::string ga_rust::get_challenge(const std::string& address) { throw std::runtime_error("not implemented"); }
    nlohmann::json ga_rust::authenticate(const std::string& sig_der_hex, const std::string& path_hex,
        const std::string& root_xpub_bip32, const std::string& device_id, const nlohmann::json& hw_device)
    {
        throw std::runtime_error("not implemented");
    }
    void ga_rust::register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs)
    {
        throw std::runtime_error("register_subaccount_xpubs not implemented");
    }
    nlohmann::json ga_rust::login(const std::string& mnemonic, const std::string& password)
    {
        auto details = nlohmann::json{
            { "mnemonic", mnemonic },
            { "password", password },
        };

        auto ret = call_session("login", details);
        m_signer = std::make_shared<software_signer>(m_netparams, mnemonic);
        return ret;
    }
    nlohmann::json ga_rust::login_with_pin(const std::string& pin, const nlohmann::json& pin_data)
    {
        auto details = nlohmann::json{
            { "pin", pin },
            { "pin_data", pin_data },
        };

        auto ret = call_session("login_with_pin", details);
        m_signer = std::make_shared<software_signer>(m_netparams, get_mnemonic_passphrase(std::string()));
        return ret;
    }
    nlohmann::json ga_rust::login_watch_only(const std::string& username, const std::string& password)
    {
        throw std::runtime_error("login_watch_only not implemented");
        __builtin_unreachable();
    }
    bool ga_rust::set_watch_only(const std::string& username, const std::string& password)
    {
        throw std::runtime_error("set_watch_only not implemented");
    }
    std::string ga_rust::get_watch_only_username()
    {
        // TODO
        return std::string{};
    }
    bool ga_rust::remove_account(const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("remove_account not implemented");
    }

    uint32_t ga_rust::get_next_subaccount(const std::string& type)
    {
        return call_session("get_next_subaccount", nlohmann::json{ { "type", type } });
    }

    nlohmann::json ga_rust::create_subaccount(const nlohmann::json& details, uint32_t subaccount)
    {
        auto details_c = nlohmann::json{
            { "subaccount", subaccount },
            { "name", details.at("name") },
        };
        return call_session("create_subaccount", details_c);
    }
    nlohmann::json ga_rust::create_subaccount(
        const nlohmann::json& details, uint32_t subaccount, const std::string& xpub)
    {
        throw std::runtime_error("create_subaccount with xpub not implemented");
    }

    void ga_rust::change_settings_limits(const nlohmann::json& limit_details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("change_settings_limits not implemented");
    }

    nlohmann::json ga_rust::get_transactions(const nlohmann::json& details)
    {
        nlohmann::json actual_details;

        if (details.is_null()) {
            actual_details["page_id"] = 0;
        } else {
            actual_details = details;
        }

        return call_session("get_transactions", actual_details);
    }

    void ga_rust::GDKRUST_notif_handler(void* self_context, GDKRUST_json* json)
    {
        // "new" needed because we want that to be on the heap. the notif handler will free it
        nlohmann::json* converted_heap = new nlohmann::json(gdkrust_json::from_serde(json));
        GA_json* as_ptr = reinterpret_cast<GA_json*>(converted_heap);

        ga_rust* self = static_cast<ga_rust*>(self_context);
        if (self->m_ga_notif_handler) {
            self->m_ga_notif_handler(self->m_ga_notif_context, as_ptr);
        }
    }

    void ga_rust::emit_notification(std::string event, nlohmann::json details)
    {
        nlohmann::json* heap_json = new nlohmann::json({ { "event", event }, { event, details } });
        GA_json* as_ptr = reinterpret_cast<GA_json*>(heap_json);

        if (m_ga_notif_handler) {
            m_ga_notif_handler(m_ga_notif_context, as_ptr);
        }
    }

    void ga_rust::set_notification_handler(GA_notification_handler handler, void* context)
    {
        m_ga_notif_handler = handler;
        m_ga_notif_context = context;

        GDKRUST_set_notification_handler(m_session, ga::sdk::ga_rust::GDKRUST_notif_handler, this);
    }

    nlohmann::json ga_rust::get_receive_address(const nlohmann::json& details)
    {
        return call_session("get_receive_address", details);
    }

    nlohmann::json ga_rust::get_previous_addresses(uint32_t subaccount, uint32_t last_pointer)
    {
        throw std::runtime_error("get_previous_addresses not implemented");
    }

    nlohmann::json ga_rust::get_subaccounts() { return call_session("get_subaccounts", nlohmann::json{}); }

    nlohmann::json ga_rust::get_subaccount(uint32_t subaccount)
    {
        return call_session("get_subaccount", nlohmann::json{ { "index", subaccount } });
    }

    void ga_rust::rename_subaccount(uint32_t subaccount, const std::string& new_name)
    {
        auto details = nlohmann::json{
            { "subaccount", subaccount },
            { "new_name", new_name },
        };
        call_session("rename_subaccount", details);
    }

    void ga_rust::set_subaccount_hidden(uint32_t subaccount, bool is_hidden)
    {
        auto details = nlohmann::json{
            { "subaccount", subaccount },
            { "hidden", is_hidden },
        };
        call_session("set_subaccount_hidden", details);
    }

    std::vector<uint32_t> ga_rust::get_subaccount_root_path(uint32_t subaccount)
    {
        throw std::runtime_error("get_subaccount_root_path not implemented");
    }

    std::vector<uint32_t> ga_rust::get_subaccount_full_path(uint32_t subaccount, uint32_t pointer)
    {
        throw std::runtime_error("get_subaccount_full_path not implemented");
    }

    nlohmann::json ga_rust::get_balance(const nlohmann::json& details) { return call_session("get_balance", details); }

    nlohmann::json ga_rust::get_available_currencies() const
    {
        return call_session("get_available_currencies", nlohmann::json{});
    }

    bool ga_rust::is_rbf_enabled() const { throw std::runtime_error("is_rbf_enabled not implemented"); }
    bool ga_rust::is_watch_only() const { return false; }

    nlohmann::json ga_rust::get_settings() { return call_session("get_settings", nlohmann::json{}); }

    nlohmann::json ga_rust::get_post_login_data() { throw std::runtime_error("get_post_login_data not implemented"); }

    void ga_rust::change_settings(const nlohmann::json& settings) { call_session("change_settings", settings); }

    nlohmann::json ga_rust::get_twofactor_config(bool reset_cached) { return nlohmann::json{}; }

    std::vector<std::string> ga_rust::get_all_twofactor_methods() { return {}; }
    std::vector<std::string> ga_rust::get_enabled_twofactor_methods() { return {}; }

    void ga_rust::set_email(const std::string& email, const nlohmann::json& twofactor_data) {}
    void ga_rust::activate_email(const std::string& code) {}
    void ga_rust::init_enable_twofactor(
        const std::string& method, const std::string& data, const nlohmann::json& twofactor_data)
    {
    }
    void ga_rust::enable_gauth(const std::string& code, const nlohmann::json& twofactor_data) {}
    void ga_rust::enable_twofactor(const std::string& method, const std::string& code) {}
    void ga_rust::disable_twofactor(const std::string& method, const nlohmann::json& twofactor_data) {}

    void ga_rust::auth_handler_request_code(
        const std::string& method, const std::string& action, const nlohmann::json& twofactor_data)
    {
    }

    std::string ga_rust::auth_handler_request_proxy_code(
        const std::string& action, const nlohmann::json& twofactor_data)
    {
        return std::string{};
    }

    nlohmann::json ga_rust::request_twofactor_reset(const std::string& email) { return nlohmann::json{}; }

    nlohmann::json ga_rust::confirm_twofactor_reset(
        const std::string& email, bool is_dispute, const nlohmann::json& twofactor_data)
    {
        return nlohmann::json{};
    }

    nlohmann::json ga_rust::request_undo_twofactor_reset(const std::string& email) { return nlohmann::json{}; }

    nlohmann::json ga_rust::confirm_undo_twofactor_reset(const std::string& email, const nlohmann::json& twofactor_data)
    {
        return nlohmann::json{};
    }

    nlohmann::json ga_rust::cancel_twofactor_reset(const nlohmann::json& twofactor_data) { return nlohmann::json{}; }

    nlohmann::json ga_rust::set_pin(const std::string& mnemonic, const std::string& pin, const std::string& device_id)
    {
        auto details = nlohmann::json{
            { "pin", pin },
            { "mnemonic", mnemonic },
            { "device_id", device_id },
        };

        return call_session("set_pin", details);
    }

    nlohmann::json ga_rust::get_unspent_outputs(const nlohmann::json& details)
    {
        return call_session("get_unspent_outputs", details);
    }

    nlohmann::json ga_rust::get_unspent_outputs_for_private_key(
        const std::string& private_key, const std::string& password, uint32_t unused)
    {
        throw std::runtime_error("get_unspent_outputs_for_private_key not implemented");
    }

    nlohmann::json ga_rust::set_unspent_outputs_status(
        const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("set_unspent_outputs_status not implemented");
    }

    nlohmann::json ga_rust::get_transaction_details(const std::string& txhash_hex) const
    {
        auto details = nlohmann::json(txhash_hex);
        return call_session("get_transaction_details", details);
    }

    nlohmann::json ga_rust::create_transaction(const nlohmann::json& details)
    {
        GDK_LOG_SEV(log_level::debug) << "ga_rust::create_transaction:" << details.dump();
        nlohmann::json result(details);

        auto addressees_p = result.find("addressees");
        for (auto& addressee : *addressees_p) {
            addressee["satoshi"] = addressee.value("satoshi", (long long)0);
            nlohmann::json uri_params = parse_bitcoin_uri(addressee.value("address", ""), m_netparams.bip21_prefix());
            if (!uri_params.is_object())
                continue;

            addressee["address"] = uri_params["address"];

            const auto bip21_params = uri_params["bip21-params"];
            if (!bip21_params.is_object())
                continue;

            const auto uri_amount_p = bip21_params.find("amount");
            if (uri_amount_p != bip21_params.end()) {
                // Use the amount specified in the URI
                const nlohmann::json uri_amount = { { "btc", uri_amount_p->get<std::string>() } };
                addressee["satoshi"] = amount::convert(uri_amount, "USD", "")["satoshi"];
            }

            if (m_netparams.is_liquid()) {
                if (bip21_params.contains("amount") && !bip21_params.contains("assetid")) {
                    throw std::runtime_error("in liquid amount without assetid is not valid"); // fixme return error
                } else if (bip21_params.contains("assetid")) {
                    addressee["asset_id"] = bip21_params["assetid"];
                }
            }
        }
        GDK_LOG_SEV(log_level::debug) << "ga_rust::create_transaction result: " << result.dump();

        return call_session("create_transaction", result);
    }

    nlohmann::json ga_rust::sign_transaction(const nlohmann::json& details)
    {
        return call_session("sign_transaction", details);
    }

    nlohmann::json ga_rust::send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        return call_session("send_transaction", details);
    }

    std::string ga_rust::broadcast_transaction(const std::string& tx_hex)
    {
        return call_session("broadcast_transaction", nlohmann::json(tx_hex)).get<std::string>();
    }

    void ga_rust::send_nlocktimes() { throw std::runtime_error("send_nlocktimes not implemented"); }
    nlohmann::json ga_rust::get_expired_deposits(const nlohmann::json& deposit_details)
    {
        return nlohmann::json::array();
    }

    void ga_rust::set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("set_csvtime not implemented");
    }
    void ga_rust::set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("set_nlocktime not implemented");
    }

    void ga_rust::set_transaction_memo(const std::string& txhash_hex, const std::string& memo)
    {
        auto details = nlohmann::json{
            { "txid", txhash_hex },
            { "memo", memo },
        };

        call_session("set_transaction_memo", details);
    }

    nlohmann::json ga_rust::get_fee_estimates() { return call_session("get_fee_estimates", nlohmann::json{}); }

    std::string ga_rust::get_mnemonic_passphrase(const std::string& password)
    {
        if (!password.empty())
            throw std::runtime_error("get_mnemonic_phassphrase: encrypted mnemonics not yet supported in electrum/rpc");
        return call_session("get_mnemonic", nlohmann::json{}).get<std::string>();
    }

    std::string ga_rust::get_system_message()
    {
        // TODO
        return std::string{};
    }

    std::pair<std::string, std::vector<uint32_t>> ga_rust::get_system_message_info(const std::string& system_message)
    {
        throw std::runtime_error("get_system_message_info not implemented");
    }
    void ga_rust::ack_system_message(const std::string& system_message)
    {
        throw std::runtime_error("ack_system_message not implemented");
    }
    void ga_rust::ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex)
    {
        throw std::runtime_error("ack_system_message not implemented");
    }

    nlohmann::json ga_rust::convert_amount(const nlohmann::json& amount_json) const
    {
        auto currency = amount_json.value("fiat_currency", "USD");
        auto rate = amount_json.value("fiat_rate", "");
        if (rate.empty()) {
            auto currency_query = nlohmann::json{ { "currencies", currency } };
            auto xrates = call_session("exchange_rates", currency_query)["currencies"];
            rate = xrates.value(currency, "");
        }
        return amount::convert(amount_json, currency, rate);
    }

    amount ga_rust::get_min_fee_rate() const { throw std::runtime_error("get_min_fee_rate not implemented"); }
    amount ga_rust::get_default_fee_rate() const { throw std::runtime_error("get_default_fee_rate not implemented"); }
    uint32_t ga_rust::get_block_height() const { throw std::runtime_error("get_block_height not implemented"); }
    amount ga_rust::get_dust_threshold() const { throw std::runtime_error("get_dust_threshold not implemented"); }
    nlohmann::json ga_rust::get_spending_limits() const
    {
        throw std::runtime_error("get_spending_limits not implemented");
    }
    bool ga_rust::is_spending_limits_decrease(const nlohmann::json& limit_details)
    {
        throw std::runtime_error("is_spending_limits_decrease not implemented");
    }

    const network_parameters& ga_rust::get_network_parameters() const { return m_netparams; }

    std::shared_ptr<signer> ga_rust::get_signer() { return m_signer; }
    ga_pubkeys& ga_rust::get_ga_pubkeys() { throw std::runtime_error("get_ga_pubkeys not implemented"); }
    user_pubkeys& ga_rust::get_user_pubkeys() { throw std::runtime_error("get_user_pubkeys not implemented"); }
    ga_user_pubkeys& ga_rust::get_recovery_pubkeys()
    {
        throw std::runtime_error("get_recovery_pubkeys not implemented");
    }

    void ga_rust::set_blinding_nonce(const std::string& pubkey, const std::string& script, const std::string& nonce)
    {
        throw std::runtime_error("set_blinding_nonce not yet implemented");
    }

    bool ga_rust::has_blinding_nonce(const std::string& pubkey, const std::string& script)
    {
        throw std::runtime_error("hash_blinding_nonce not yet implemented");
    }

    nlohmann::json ga_rust::get_blinded_scripts(const nlohmann::json& details) { return nlohmann::json(); }

    void ga_rust::upload_confidential_addresses(
        uint32_t subaccount, const std::vector<std::string>& confidential_addresses)
    {
        throw std::runtime_error("upload_confidential_addresses not yet implemented");
    }

    void ga_rust::set_local_encryption_keys(const pub_key_t& public_key, bool is_hw_wallet) {}

    void ga_rust::disable_all_pin_logins() {}

} // namespace sdk
} // namespace ga
