#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__) || defined(__GNUG__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#else
// ??
#endif

#include "../subprojects/gdk_rust/gdk_rust.h"

#include "exception.hpp"
#include "ga_rust.hpp"
#include "ga_strings.hpp"
#include "ga_tor.hpp"
#include "inbuilt.hpp"
#include "logging.hpp"
#include "session.hpp"
#include "signer.hpp"
#include "utils.hpp"

namespace ga {
namespace sdk {

    namespace {
        static const std::string TOR_SOCKS5_PREFIX("socks5://");

        static std::pair<std::string, std::string> get_exception_details(const nlohmann::json& details)
        {
            std::pair<std::string, std::string> ret;
            if (!details.is_null()) {
                try {
                    ret.first = details.value("error", std::string());
                    ret.second = details.value("message", std::string());
                } catch (const std::exception&) {
                    // Ignore
                }
            }
            return ret;
        }

        static void check_code(const int32_t return_code, const nlohmann::json& json)
        {
            if (return_code != GA_OK) {
                switch (return_code) {
                case GA_RECONNECT:
                case GA_SESSION_LOST:
                    throw reconnect_error();

                case GA_TIMEOUT:
                    throw timeout_error();

                case GA_NOT_AUTHORIZED:
                    throw login_error(get_exception_details(json).second);

                case GA_ERROR:
                default:
                    throw user_error(get_exception_details(json).second);
                }
            }
        }

        static nlohmann::json call(const std::string& method, const nlohmann::json& input)
        {
            char* output = nullptr;
            int res = GDKRUST_call(method.c_str(), input.dump().c_str(), &output);
            nlohmann::json cppjson = nlohmann::json();
            if (output) {
                cppjson = nlohmann::json::parse(output);
                GDKRUST_destroy_string(output);
            }
            check_code(res, cppjson);
            return cppjson;
        }
    } // namespace

    ga_rust::ga_rust(network_parameters&& net_params)
        : session_impl(std::move(net_params))
    {
        const auto res = GDKRUST_create_session(&m_session, m_net_params.get_json().dump().c_str());
        GDK_RUNTIME_ASSERT(res == GA_OK);
    }

    ga_rust::~ga_rust()
    {
        GDKRUST_destroy_session(m_session);
        // gdk_rust cleanup
    }

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
        char* output = nullptr;
        int res = GDKRUST_call_session(m_session, method.c_str(), input.dump().c_str(), &output);
        if (!output) {
            // output was not set by calling `std::ffi::CString::into_raw`;
            // avoid calling GDKRUST_destroy_string.
            const auto cppjson = nlohmann::json();
            check_code(res, cppjson);
            return cppjson;
        }
        const nlohmann::json cppjson = nlohmann::json::parse(output);
        GDKRUST_destroy_string(output);
        check_code(res, cppjson);
        return cppjson;
    }

    void ga_rust::connect()
    {
        nlohmann::json net_params = m_net_params.get_json();

        if (m_net_params.use_tor() && m_net_params.socks5().empty()) {
            m_tor_ctrl = tor_controller::get_shared_ref();
            std::string full_socks5
                = m_tor_ctrl->wait_for_socks5(DEFAULT_TOR_SOCKS_WAIT, [&](std::shared_ptr<tor_bootstrap_phase> p) {
                      nlohmann::json tor_json(
                          { { "tag", p->tag }, { "summary", p->summary }, { "progress", p->progress } });
                      constexpr bool async = false; // Note: ga_session sends this async
                      emit_notification({ { "event", "tor" }, { "tor", tor_json } }, async);
                  });

            if (full_socks5.empty()) {
                throw timeout_error();
            }

            GDK_RUNTIME_ASSERT(full_socks5.size() > TOR_SOCKS5_PREFIX.size());
            full_socks5.erase(0, TOR_SOCKS5_PREFIX.size());

            net_params["socks5"] = full_socks5;

            GDK_LOG_SEV(log_level::info) << "tor_socks address " << full_socks5;
        }

        call_session("connect", net_params);
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
        auto result = call_session("refresh_assets", params);
        const std::array<const char*, 2> keys = { "assets", "icons" };
        for (const auto& key : keys) {
            if (params.value(key, false)) {
                auto& data = result.at(key);
                if (data.empty()) {
                    // An empty result is a sentinel indicating that the initial
                    // data fetch failed. Return the compiled-in data in this case.
                    result[key] = get_inbuilt_data(m_net_params, key).at("body");
                } else {
                    // Filter out any bad keys returned by the asset registry
                    json_filter_bad_asset_ids(data);
                }
            }
        }
        if (params.value("assets", false)) {
            // Add the policy asset to asset data
            const auto policy_asset = m_net_params.policy_asset();
            result["assets"][policy_asset] = { { "asset_id", policy_asset }, { "name", "btc" } };
        }
        return result;
    }

    nlohmann::json ga_rust::validate_asset_domain_name(const nlohmann::json& params) { return nlohmann::json(); }

    std::string ga_rust::get_challenge(const pub_key_t& /*public_key*/) { throw std::runtime_error("not implemented"); }
    nlohmann::json ga_rust::authenticate(const std::string& sig_der_hex, const std::string& path_hex,
        const std::string& root_bip32_xpub, std::shared_ptr<signer> signer)
    {
        throw std::runtime_error("not implemented");
    }
    void ga_rust::register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs)
    {
        throw std::runtime_error("register_subaccount_xpubs not implemented");
    }
    nlohmann::json ga_rust::login(std::shared_ptr<signer> signer)
    {
        {
            locker_t locker(m_mutex);
            // Re-login must use the same signer
            GDK_RUNTIME_ASSERT(!m_signer.get() || m_signer.get() == signer.get());
            m_signer = signer;
        }
        auto details
            = nlohmann::json({ { "mnemonic", signer->get_mnemonic(std::string()) }, { "password", std::string() } });
        return call_session("login", details);
    }
    std::string ga_rust::mnemonic_from_pin_data(const nlohmann::json& pin_data)
    {
        return call_session("mnemonic_from_pin_data", pin_data);
    }
    nlohmann::json ga_rust::login_watch_only(std::shared_ptr<signer> signer)
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
        return call_session("get_next_subaccount", nlohmann::json({ { "type", type } }));
    }

    nlohmann::json ga_rust::create_subaccount(
        const nlohmann::json& details, uint32_t subaccount, const std::string& xpub)
    {
        auto details_c = nlohmann::json({
            { "subaccount", subaccount },
            { "name", details.at("name") },
        });
        return call_session("create_subaccount", details_c);
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

    void ga_rust::GDKRUST_notif_handler(void* self_context, char* json)
    {
        ga_rust* self = static_cast<ga_rust*>(self_context);
        auto notification = nlohmann::json::parse(json);
        GDKRUST_destroy_string(json);
        if (notification.at("event") == "transaction") {
            // FIXME: Get the actual subaccounts affected from the notification
            // See gdk_rust/gdk_electrum/src/lib.rs: "// TODO account number"
            self->remove_cached_utxos(std::vector<uint32_t>());
        }
        self->emit_notification(notification, false);
    }

    void ga_rust::set_notification_handler(GA_notification_handler handler, void* context)
    {
        session_impl::set_notification_handler(handler, context);
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
        return call_session("get_subaccount", nlohmann::json{ { "subaccount", subaccount } });
    }

    void ga_rust::rename_subaccount(uint32_t subaccount, const std::string& new_name)
    {
        auto details = nlohmann::json({
            { "subaccount", subaccount },
            { "new_name", new_name },
        });
        call_session("rename_subaccount", details);
    }

    void ga_rust::set_subaccount_hidden(uint32_t subaccount, bool is_hidden)
    {
        auto details = nlohmann::json({
            { "subaccount", subaccount },
            { "hidden", is_hidden },
        });
        call_session("set_subaccount_hidden", details);
    }

    std::vector<uint32_t> ga_rust::get_subaccount_root_path(uint32_t subaccount)
    {
        // FIXME: Use rust mapping/map in user pubkeys
        const std::array<uint32_t, 3> purpose_lookup{ 49, 84, 44 };
        const bool main_net = m_net_params.is_main_net();
        const bool liquid = m_net_params.is_liquid();

        const uint32_t purpose = purpose_lookup.at(subaccount % 16);
        const uint32_t coin_type = main_net ? (liquid ? 1776 : 0) : 1;
        const uint32_t account = subaccount / 16;
        return std::vector<uint32_t>{ harden(purpose), harden(coin_type), account };
    }

    std::vector<uint32_t> ga_rust::get_subaccount_full_path(uint32_t subaccount, uint32_t pointer)
    {
        throw std::runtime_error("get_subaccount_full_path not implemented");
    }

    nlohmann::json ga_rust::get_available_currencies() const
    {
        return call_session("get_available_currencies", nlohmann::json({}));
    }

    bool ga_rust::is_rbf_enabled() const { throw std::runtime_error("is_rbf_enabled not implemented"); }
    bool ga_rust::is_watch_only() const { return false; }

    nlohmann::json ga_rust::get_settings() { return call_session("get_settings", nlohmann::json({})); }

    nlohmann::json ga_rust::get_post_login_data() { throw std::runtime_error("get_post_login_data not implemented"); }

    void ga_rust::change_settings(const nlohmann::json& settings) { call_session("change_settings", settings); }

    nlohmann::json ga_rust::get_twofactor_config(bool reset_cached) { return nlohmann::json({}); }

    std::vector<std::string> ga_rust::get_enabled_twofactor_methods() { return {}; }

    void ga_rust::set_email(const std::string& email, const nlohmann::json& twofactor_data) {}
    void ga_rust::activate_email(const std::string& code) {}
    nlohmann::json ga_rust::init_enable_twofactor(
        const std::string& method, const std::string& data, const nlohmann::json& twofactor_data)
    {
        return nlohmann::json();
    }
    void ga_rust::enable_gauth(const std::string& code, const nlohmann::json& twofactor_data) {}
    void ga_rust::enable_twofactor(const std::string& method, const std::string& code) {}
    void ga_rust::disable_twofactor(const std::string& method, const nlohmann::json& twofactor_data) {}

    nlohmann::json ga_rust::auth_handler_request_code(
        const std::string& method, const std::string& action, const nlohmann::json& twofactor_data)
    {
        return nlohmann::json();
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
        return nlohmann::json({});
    }

    nlohmann::json ga_rust::request_undo_twofactor_reset(const std::string& email) { return nlohmann::json{}; }

    nlohmann::json ga_rust::confirm_undo_twofactor_reset(const std::string& email, const nlohmann::json& twofactor_data)
    {
        return nlohmann::json({});
    }

    nlohmann::json ga_rust::cancel_twofactor_reset(const nlohmann::json& twofactor_data) { return nlohmann::json{}; }

    nlohmann::json ga_rust::set_pin(const std::string& mnemonic, const std::string& pin, const std::string& device_id)
    {
        auto details = nlohmann::json({
            { "pin", pin },
            { "mnemonic", mnemonic },
            { "device_id", device_id },
        });

        return call_session("set_pin", details);
    }

    nlohmann::json ga_rust::get_unspent_outputs(
        const nlohmann::json& details, unique_pubkeys_and_scripts_t& /*missing*/)
    {
        // FIXME: Use 'missing' once unblinding uses HWW interface
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

    wally_tx_ptr ga_rust::get_raw_transaction_details(const std::string& txhash_hex) const
    {
        const auto tx_hex = call_session("get_raw_transaction_details", nlohmann::json(txhash_hex));
        return tx_from_hex(tx_hex, tx_flags(m_net_params.is_liquid()));
    }

    nlohmann::json ga_rust::create_transaction(const nlohmann::json& details)
    {
        GDK_LOG_SEV(log_level::debug) << "ga_rust::create_transaction:" << details.dump();
        nlohmann::json result(details);

        auto addressees_p = result.find("addressees");
        if (addressees_p != result.end()) {
            for (auto& addressee : *addressees_p) {
                // TODO: unify handling with add_tx_addressee
                nlohmann::json uri_params;
                try {
                    uri_params = parse_bitcoin_uri(addressee.at("address"), m_net_params.bip21_prefix());
                } catch (const std::exception& e) {
                    result["error"] = e.what();
                    return result;
                }
                if (!uri_params.is_null()) {
                    addressee["address"] = uri_params["address"];
                    const auto& bip21_params = uri_params["bip21-params"];
                    addressee["bip21-params"] = bip21_params;
                    const auto uri_amount_p = bip21_params.find("amount");
                    if (uri_amount_p != bip21_params.end()) {
                        // Use the amount specified in the URI
                        const nlohmann::json uri_amount = { { "btc", uri_amount_p->get<std::string>() } };
                        addressee["satoshi"] = amount::convert(uri_amount, "", "")["satoshi"];
                    }
                    if (m_net_params.is_liquid()) {
                        if (bip21_params.contains("amount") && !bip21_params.contains("assetid")) {
                            result["error"] = res::id_invalid_payment_request_assetid;
                            return result;
                        } else if (bip21_params.contains("assetid")) {
                            addressee["asset_id"] = bip21_params["assetid"];
                        }
                    }
                }
                if (!addressee.contains("satoshi")) {
                    result["error"] = res::id_no_amount_specified;
                    return result;
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

    nlohmann::json ga_rust::psbt_sign(const nlohmann::json& details)
    {
        throw std::runtime_error("psbt_sign not implemented");
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
        auto details = nlohmann::json({
            { "txid", txhash_hex },
            { "memo", memo },
        });

        call_session("set_transaction_memo", details);
    }

    nlohmann::json ga_rust::get_fee_estimates() { return call_session("get_fee_estimates", nlohmann::json({})); }

    std::string ga_rust::get_system_message()
    {
        // TODO
        return std::string{};
    }

    std::pair<std::string, std::vector<uint32_t>> ga_rust::get_system_message_info(const std::string& system_message)
    {
        throw std::runtime_error("get_system_message_info not implemented");
    }

    void ga_rust::ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex)
    {
        throw std::runtime_error("ack_system_message not implemented");
    }

    nlohmann::json ga_rust::convert_amount(const nlohmann::json& amount_json) const
    {
        auto currency = amount_json.value("fiat_currency", "USD");
        auto fallback_rate = amount_json.value("fiat_rate", "");
        auto currency_query = nlohmann::json({ { "currencies", currency } });
        auto xrates = call_session("exchange_rates", currency_query)["currencies"];
        auto fetched_rate = xrates.value(currency, "");
        auto rate = fetched_rate.empty() ? fallback_rate : fetched_rate;
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

    ga_pubkeys& ga_rust::get_ga_pubkeys() { throw std::runtime_error("get_ga_pubkeys not implemented"); }
    user_pubkeys& ga_rust::get_user_pubkeys() { throw std::runtime_error("get_user_pubkeys not implemented"); }
    ga_user_pubkeys& ga_rust::get_recovery_pubkeys()
    {
        throw std::runtime_error("get_recovery_pubkeys not implemented");
    }

    void ga_rust::upload_confidential_addresses(
        uint32_t subaccount, const std::vector<std::string>& confidential_addresses)
    {
        throw std::runtime_error("upload_confidential_addresses not yet implemented");
    }

    void ga_rust::disable_all_pin_logins() {}

    int32_t ga_rust::spv_verify_tx(const nlohmann::json& details)
    {
        return GDKRUST_spv_verify_tx(details.dump().c_str());
    }

    std::string ga_rust::psbt_extract_tx(const std::string& psbt_hex)
    {
        const nlohmann::json input = { { "psbt_hex", psbt_hex } };
        return call("psbt_extract_tx", input).at("transaction");
    }

    std::string ga_rust::psbt_merge_tx(const std::string& psbt_hex, const std::string& tx_hex)
    {
        const nlohmann::json input = { { "psbt_hex", psbt_hex }, { "transaction", tx_hex } };
        return call("psbt_merge_tx", input).at("psbt_hex");
    }

} // namespace sdk
} // namespace ga
