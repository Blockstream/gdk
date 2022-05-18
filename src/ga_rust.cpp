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
#include "logging.hpp"
#include "session.hpp"
#include "signer.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

namespace ga {
namespace sdk {

    ga_rust::ga_rust(network_parameters&& net_params)
        : session_impl(std::move(net_params))
    {
        auto np = m_net_params.get_json();
        const auto res = GDKRUST_create_session(&m_session, np.dump().c_str());
        GDK_RUNTIME_ASSERT(res == GA_OK && m_session);
        m_user_pubkeys = std::make_unique<bip44_pubkeys>(m_net_params);
    }

    ga_rust::~ga_rust()
    {
        m_notify = false;
        GDKRUST_destroy_session(m_session);
        // gdk_rust cleanup
    }

    void ga_rust::connect()
    {
        nlohmann::json net_params = m_net_params.get_json();
        net_params["proxy"] = session_impl::connect_tor();
        rust_call("connect", net_params, m_session);
    }

    void ga_rust::reconnect()
    {
        // Called by the top level session handler in reponse to
        // reconnect and timeout errors.
        disconnect();
        connect();
    }

    void ga_rust::reconnect_hint(const nlohmann::json& hint)
    {
        // Called by the user to indicate they want to connect or disconnect
        // the sessions underlying transport
        session_impl::reconnect_hint(hint);

        const auto hint_p = hint.find("hint");
        if (hint_p != hint.end()) {
            if (*hint_p == "connect") {
                connect();
            } else {
                disconnect();
            }
        }
    }

    void ga_rust::disconnect()
    {
        GDK_LOG_SEV(log_level::debug) << "ga_rust::disconnect";
        rust_call("disconnect", {}, m_session);
    }

    nlohmann::json ga_rust::validate_asset_domain_name(const nlohmann::json& params) { return nlohmann::json(); }

    void ga_rust::set_local_encryption_keys(const pub_key_t& /*public_key*/, std::shared_ptr<signer> signer)
    {
        auto master_xpub = signer->get_bip32_xpub(std::vector<uint32_t>());
        rust_call("load_store", { { "master_xpub", std::move(master_xpub) } }, m_session);
        if (!signer->has_master_blinding_key()) {
            // Load the cached master blinding key, if we have it
            std::string blinding_key_hex;
            bool denied;
            std::tie(blinding_key_hex, denied) = get_cached_master_blinding_key();
            if (!denied) {
                signer->set_master_blinding_key(blinding_key_hex);
            }
        }
        // FIXME: Load subaccount paths and xpubs from the store and add them
        // with signer->cache_bip32_xpub() - see ga_session::load_signer_xpubs
        // (This avoids having to go to the HWW to fetch these xpubs)
    }

    void ga_rust::start_sync_threads() { rust_call("start_threads", {}, m_session); }

    std::string ga_rust::get_challenge(const pub_key_t& /*public_key*/) { throw std::runtime_error("not implemented"); }

    nlohmann::json ga_rust::authenticate(const std::string& /*sig_der_hex*/, const std::string& /*path_hex*/,
        const std::string& /*root_bip32_xpub*/, std::shared_ptr<signer> signer)
    {
        set_signer(signer);
        return get_post_login_data();
    }

    void ga_rust::register_subaccount_xpubs(
        const std::vector<uint32_t>& pointers, const std::vector<std::string>& bip32_xpubs)
    {
        // Note we only register each loaded subaccount once.
        const nlohmann::json details({ { "name", std::string() } });
        for (size_t i = 0; i < pointers.size(); ++i) {
            const auto pointer = pointers.at(i);
            if (!m_user_pubkeys->have_subaccount(pointer)) {
                const auto& bip32_xpub = bip32_xpubs.at(i);
                create_subaccount(details, pointer, bip32_xpub);
            }
        }
    }

    nlohmann::json ga_rust::login(std::shared_ptr<signer> signer)
    {
        set_signer(signer);
        std::string empty;
        auto mnemonic = signer->get_mnemonic(empty);
        return rust_call("login", { { "mnemonic", std::move(mnemonic) }, { "password", empty } }, m_session);
    }
    std::string ga_rust::mnemonic_from_pin_data(const nlohmann::json& pin_data)
    {
        return rust_call("mnemonic_from_pin_data", pin_data, m_session);
    }
    nlohmann::json ga_rust::login_wo(std::shared_ptr<signer> signer)
    {
        throw std::runtime_error("login_wo not implemented");
        __builtin_unreachable();
    }
    bool ga_rust::set_wo_credentials(const std::string& username, const std::string& password)
    {
        throw std::runtime_error("set_wo_credentials not implemented");
    }
    std::string ga_rust::get_wo_username()
    {
        // TODO
        return std::string{};
    }
    bool ga_rust::remove_account(const nlohmann::json& twofactor_data)
    {
        rust_call("remove_account", {}, m_session);
        return true;
    }

    bool ga_rust::discover_subaccount(const std::string& xpub, const std::string& type)
    {
        const auto details = nlohmann::json({ { "type", type }, { "xpub", xpub } });
        return rust_call("discover_subaccount", details, m_session);
    }

    uint32_t ga_rust::get_next_subaccount(const std::string& type)
    {
        return rust_call("get_next_subaccount", nlohmann::json({ { "type", type } }), m_session);
    }

    nlohmann::json ga_rust::create_subaccount(
        const nlohmann::json& details, uint32_t subaccount, const std::string& xpub)
    {
        auto details_c = details;
        details_c["subaccount"] = subaccount;
        details_c["xpub"] = xpub;
        auto ret = rust_call("create_subaccount", details_c, m_session);
        m_user_pubkeys->add_subaccount(subaccount, make_xpub(xpub));
        return ret;
    }

    std::pair<std::string, bool> ga_rust::get_cached_master_blinding_key()
    {
        const auto ret = rust_call("get_master_blinding_key", {}, m_session);
        constexpr bool is_denied = false;
        return { ret.value("master_blinding_key", std::string()), is_denied };
    }

    void ga_rust::set_cached_master_blinding_key(const std::string& master_blinding_key_hex)
    {
        GDK_RUNTIME_ASSERT_MSG(
            !master_blinding_key_hex.empty(), "HWW must enable host unblinding for singlesig wallets");
        session_impl::set_cached_master_blinding_key(master_blinding_key_hex);
        rust_call("set_master_blinding_key", { { "master_blinding_key", master_blinding_key_hex } }, m_session);
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

        return rust_call("get_transactions", actual_details, m_session);
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
        return rust_call("get_receive_address", details, m_session);
    }

    nlohmann::json ga_rust::get_previous_addresses(const nlohmann::json& details)
    {
        nlohmann::json actual_details = details;

        // Same pagination as multisig
        actual_details["count"] = 10;

        return rust_call("get_previous_addresses", actual_details, m_session);
    }

    nlohmann::json ga_rust::get_subaccounts() { return rust_call("get_subaccounts", {}, m_session); }

    std::vector<uint32_t> ga_rust::get_subaccount_pointers()
    {
        std::vector<uint32_t> ret;
        for (const auto& pointer : rust_call("get_subaccount_nums", {}, m_session)) {
            ret.emplace_back(pointer);
        }
        return ret;
    }

    nlohmann::json ga_rust::get_subaccount(uint32_t subaccount)
    {
        return rust_call("get_subaccount", nlohmann::json{ { "subaccount", subaccount } }, m_session);
    }

    void ga_rust::rename_subaccount(uint32_t subaccount, const std::string& new_name)
    {
        auto details = nlohmann::json({
            { "subaccount", subaccount },
            { "new_name", new_name },
        });
        rust_call("rename_subaccount", details, m_session);
    }

    void ga_rust::set_subaccount_hidden(uint32_t subaccount, bool is_hidden)
    {
        auto details = nlohmann::json({
            { "subaccount", subaccount },
            { "hidden", is_hidden },
        });
        rust_call("set_subaccount_hidden", details, m_session);
    }

    std::vector<uint32_t> ga_rust::get_subaccount_root_path(uint32_t subaccount)
    {
        return bip44_pubkeys::get_bip44_subaccount_root_path(
            m_net_params.is_main_net(), m_net_params.is_liquid(), subaccount);
    }

    std::vector<uint32_t> ga_rust::get_subaccount_full_path(uint32_t subaccount, uint32_t pointer, bool is_internal)
    {
        return bip44_pubkeys::get_bip44_subaccount_full_path(
            m_net_params.is_main_net(), m_net_params.is_liquid(), subaccount, pointer, is_internal);
    }

    nlohmann::json ga_rust::get_subaccount_xpub(uint32_t subaccount)
    {
        return rust_call("get_subaccount_xpub", { { "subaccount", subaccount } }, m_session);
    }

    nlohmann::json ga_rust::get_available_currencies() const
    {
        return rust_call("get_available_currencies", nlohmann::json({}), m_session);
    }

    bool ga_rust::is_rbf_enabled() const
    {
        return !m_net_params.is_liquid(); // Not supported on liquid
    }

    bool ga_rust::is_watch_only() const { return false; }
    void ga_rust::ensure_full_session()
    { /* TODO: Implement when watch only is implemented */
    }

    nlohmann::json ga_rust::get_settings() { return rust_call("get_settings", nlohmann::json({}), m_session); }

    nlohmann::json ga_rust::get_post_login_data()
    {
        auto master_xpub = get_nonnull_signer()->get_bip32_xpub(std::vector<uint32_t>());
        return get_wallet_hash_id(
            { { "name", m_net_params.network() } }, { { "master_xpub", std::move(master_xpub) } });
    }

    void ga_rust::change_settings(const nlohmann::json& settings) { rust_call("change_settings", settings, m_session); }

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

        return rust_call("set_pin", details, m_session);
    }

    nlohmann::json ga_rust::get_unspent_outputs(
        const nlohmann::json& details, unique_pubkeys_and_scripts_t& /*missing*/)
    {
        // FIXME: Use 'missing' once unblinding uses HWW interface
        return rust_call("get_unspent_outputs", details, m_session);
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
        try {
            const auto tx_hex = rust_call("get_transaction_hex", nlohmann::json(txhash_hex), m_session);
            return tx_from_hex(tx_hex, tx_flags(m_net_params.is_liquid()));
        } catch (const std::exception& e) {
            GDK_LOG_SEV(log_level::warning) << "Error fetching " << txhash_hex << " : " << e.what();
            throw user_error("Transaction not found");
        }
    }

    nlohmann::json ga_rust::get_transaction_details(const std::string& txhash_hex) const
    {
        try {
            return rust_call("get_transaction_details", nlohmann::json(txhash_hex), m_session);
        } catch (const std::exception& e) {
            GDK_LOG_SEV(log_level::warning) << "Error fetching " << txhash_hex << " : " << e.what();
            throw user_error("Transaction not found");
        }
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

        return rust_call("create_transaction", result, m_session);
    }

    nlohmann::json ga_rust::user_sign_transaction(const nlohmann::json& details)
    {
        return rust_call("sign_transaction", details, m_session);
    }

    nlohmann::json ga_rust::service_sign_transaction(
        const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("service_sign_transaction not implemented");
    }

    nlohmann::json ga_rust::psbt_sign(const nlohmann::json& details)
    {
        throw std::runtime_error("psbt_sign not implemented");
    }

    nlohmann::json ga_rust::send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        return rust_call("send_transaction", details, m_session);
    }

    std::string ga_rust::broadcast_transaction(const std::string& tx_hex)
    {
        return rust_call("broadcast_transaction", nlohmann::json(tx_hex), m_session).get<std::string>();
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

        rust_call("set_transaction_memo", details, m_session);
    }

    nlohmann::json ga_rust::get_fee_estimates()
    {
        return rust_call("get_fee_estimates", nlohmann::json({}), m_session);
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

    void ga_rust::ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex)
    {
        throw std::runtime_error("ack_system_message not implemented");
    }

    nlohmann::json ga_rust::convert_amount(const nlohmann::json& amount_json) const
    {
        auto currency = amount_json.value("fiat_currency", "USD");
        auto fallback_rate = amount_json.value("fiat_rate", "");
        auto currency_query = nlohmann::json({ { "currencies", currency } });
        auto xrates = rust_call("exchange_rates", currency_query, m_session)["currencies"];
        auto fetched_rate = xrates.value(currency, "");
        auto rate = fetched_rate.empty() ? fallback_rate : fetched_rate;
        return amount::convert(amount_json, currency, rate);
    }

    amount ga_rust::get_min_fee_rate() const { return amount(m_net_params.is_liquid() ? 100 : 1000); }
    amount ga_rust::get_default_fee_rate() const
    {
        // TODO: Implement using a user block default setting when we have one
        return get_min_fee_rate();
    }
    uint32_t ga_rust::get_block_height() const { return rust_call("get_block_height", {}, m_session); }
    amount ga_rust::get_dust_threshold() const { return amount(546); }

    nlohmann::json ga_rust::get_spending_limits() const
    {
        throw std::runtime_error("get_spending_limits not implemented");
    }
    bool ga_rust::is_spending_limits_decrease(const nlohmann::json& limit_details)
    {
        throw std::runtime_error("is_spending_limits_decrease not implemented");
    }

    ga_pubkeys& ga_rust::get_ga_pubkeys() { throw std::runtime_error("get_ga_pubkeys not implemented"); }
    user_pubkeys& ga_rust::get_recovery_pubkeys() { throw std::runtime_error("get_recovery_pubkeys not implemented"); }

    void ga_rust::upload_confidential_addresses(
        uint32_t subaccount, const std::vector<std::string>& confidential_addresses)
    {
        throw std::runtime_error("upload_confidential_addresses not yet implemented");
    }

    void ga_rust::disable_all_pin_logins() {}

} // namespace sdk
} // namespace ga
