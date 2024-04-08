#if defined(__clang__)
#pragma clang diagnostic ignored "-Wunused-parameter"
#elif defined(__GNUC__) || defined(__GNUG__)
#pragma GCC diagnostic ignored "-Wunused-parameter"
#else
// ??
#endif

#include "gdk_rust.h"

#include "client_blob.hpp"
#include "exception.hpp"
#include "ga_rust.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "json_utils.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "session.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
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

    void ga_rust::connect_session()
    {
        nlohmann::json net_params = m_net_params.get_json();
        net_params["proxy"] = session_impl::connect_tor();
        rust_call("connect", net_params, m_session);
    }

    void ga_rust::reconnect_hint_session(const nlohmann::json& hint, const nlohmann::json& proxy)
    {
        if (const auto hint_p = hint.find("hint"); hint_p != hint.end()) {
            if (*hint_p == "connect") {
                connect_session();
            } else {
                disconnect_session();
            }
        }
    }

    void ga_rust::disconnect_session()
    {
        GDK_LOG(debug) << "ga_rust::disconnect_session";
        rust_call("disconnect", {}, m_session);
    }

    void ga_rust::set_local_encryption_keys(const pub_key_t& public_key, std::shared_ptr<signer> signer)
    {
        GDK_RUNTIME_ASSERT(signer->has_master_bip32_xpub());
        auto master_xpub = signer->get_master_bip32_xpub();

        // Load the cache on the rust side
        rust_call("load_store", { { "master_xpub", master_xpub } }, m_session);

        if (!signer->has_master_blinding_key()) {
            // Load the cached master blinding key, if we have it
            std::string blinding_key_hex;
            bool denied;
            std::tie(blinding_key_hex, denied) = get_cached_master_blinding_key();
            if (!denied) {
                signer->set_master_blinding_key(blinding_key_hex);
            }
        }

        locker_t locker(m_mutex);
        // FIXME: Load subaccount paths and xpubs from the store and add them
        // with signer->cache_bip32_xpub() - see ga_session::load_signer_xpubs
        // (This avoids having to go to the HWW to fetch these xpubs)
        m_login_data = get_wallet_hash_ids({ { "name", m_net_params.network() } }, { { "master_xpub", master_xpub } });
        m_login_data["warnings"] = nlohmann::json::array();

        if (m_blobserver) {
            // FIXME: enable blob for watch-only sessions
            if (!signer->is_watch_only()) {
                // Compute the client blob HMAC key
                const auto tmp_key = pbkdf2_hmac_sha512(public_key, signer::BLOB_SALT);
                const auto tmp_span = gsl::make_span(tmp_key);
                set_optional_variable(m_blob_aes_key, sha256(tmp_span.subspan(SHA256_LEN)));
                set_optional_variable(
                    m_blob_hmac_key, make_byte_array<SHA256_LEN>(tmp_span.subspan(SHA256_LEN, SHA256_LEN)));
            }
            // Load any cached blob data
            get_cached_local_client_blob(std::string());
            // Load the latest blob from the server. If the server blob is
            // newer, this updates our locally cached blob data to it
            const auto& client_id = j_strref(m_login_data, "wallet_hash_id");
            load_client_blob(locker, client_id, true);
        }
    }

    void ga_rust::populate_initial_client_blob(session_impl::locker_t& locker)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(have_writable_client_blob(locker));
        GDK_LOG(info) << "Populating initial client blob";
        // Subaccount xpubs
        const auto signer_xpubs = m_signer->get_cached_bip32_xpubs_json();
        GDK_RUNTIME_ASSERT(!signer_xpubs.empty());
        update_client_blob(locker, std::bind(&client_blob::set_xpubs, m_blob.get(), signer_xpubs));
        // Subaccount names
        const nlohmann::json empty; // Don't re-save xpubs
        for (const auto& sa : get_subaccounts_impl(locker)) {
            nlohmann::json sa_data = { { "name", j_strref(sa, "name") } };
            if (j_bool_or_false(sa, "hidden")) {
                sa_data["hidden"] = true;
            }
            m_blob->update_subaccount_data(j_uint32ref(sa, "pointer"), sa_data, empty);
        }
        // Tx memos
        for (const auto& m : rust_call("get_memos", {}, m_session).items()) {
            m_blob->set_tx_memo(m.key(), m.value());
        }
        m_blob->set_user_version(1); // Initial version
        const auto& client_id = j_strref(m_login_data, "wallet_hash_id");
        if (!save_client_blob(locker, client_id, client_blob::get_zero_hmac())) {
            // We raced and lost with another session creating the initial blob.
            // Load the blob the other session saved and use its metadata.
            // (Note that this will probably never happen in practice).
            load_client_blob(locker, client_id, true);
        }
    }

    void ga_rust::get_cached_local_client_blob(const std::string& /*server_hmac*/)
    {
        // Load our client blob from from the cache if we have one
        if (!m_blob_hmac.empty()) {
            return; // Already loaded
        }
        nlohmann::json local_blob;
        local_blob = rust_call("load_blob", {}, m_session);
        if (!j_str_is_empty(local_blob, "blob")) {
            // We have a local blob, load it into our in-memory blob
            GDK_RUNTIME_ASSERT(m_watch_only || m_blob_hmac_key.has_value());
            m_blob->load(*m_blob_aes_key, base64_to_bytes(j_strref(local_blob, "blob")));
            m_blob_hmac = j_strref(local_blob, "hmac");
        }
    }

    void ga_rust::encache_local_client_blob(session_impl::locker_t& locker, const char* data_b64,
        const std::vector<unsigned char>& data, const std::string& hmac)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        const auto& client_id = j_strref(m_login_data, "wallet_hash_id");
        rust_call("save_blob", { { "blob", data_b64 }, { "client_id", client_id }, { "hmac", hmac } }, m_session);
    }

    void ga_rust::start_sync_threads() { rust_call("start_threads", {}, m_session); }

    std::string ga_rust::get_challenge(const pub_key_t& /*public_key*/) { throw std::runtime_error("not implemented"); }

    nlohmann::json ga_rust::authenticate(const std::string& /*sig_der_hex*/, std::shared_ptr<signer> signer)
    {
        locker_t locker(m_mutex);
        set_signer(locker, signer);
        m_watch_only = false;
        if (m_blobserver && m_blob_hmac.empty()) {
            // No client blob locally or on the blobserver: create it
            populate_initial_client_blob(locker);
        }
        // TODO: If we have the client blob locally and not on the server,
        //       push it to the server.
        return m_login_data;
    }

    void ga_rust::register_subaccount_xpubs(
        const std::vector<uint32_t>& pointers, const std::vector<std::string>& bip32_xpubs)
    {
        // Note we only register each loaded subaccount once.
        // Subaccount to register has already been created, so we
        // set a flag to avoid the checks on the (sub)account gaps.
        const nlohmann::json details({ { "name", std::string() }, { "is_already_created", true } });
        for (size_t i = 0; i < pointers.size(); ++i) {
            const auto pointer = pointers.at(i);
            if (!m_user_pubkeys->have_subaccount(pointer)) {
                const auto& bip32_xpub = bip32_xpubs.at(i);
                create_subaccount(details, pointer, bip32_xpub);
            }
        }
    }
    nlohmann::json ga_rust::credentials_from_pin_data(const nlohmann::json& pin_data)
    {
        return rust_call("credentials_from_pin_data", pin_data, m_session);
    }
    nlohmann::json ga_rust::login_wo(std::shared_ptr<signer> signer)
    {
        {
            locker_t locker(m_mutex);
            set_signer(locker, signer);
            m_watch_only = true;
        }
        return rust_call("login_wo", signer->get_credentials(false), m_session);
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

    uint32_t ga_rust::get_last_empty_subaccount(const std::string& type)
    {
        return rust_call("get_last_empty_subaccount", nlohmann::json({ { "type", type } }), m_session);
    }

    nlohmann::json ga_rust::create_subaccount(
        const nlohmann::json& details, uint32_t subaccount, const std::string& xpub)
    {
        auto details_c = details;
        details_c["subaccount"] = subaccount;
        details_c["xpub"] = xpub;
        auto ret = rust_call("create_subaccount", details_c, m_session);
        m_user_pubkeys->add_subaccount(subaccount, make_xpub(xpub));
        if (!j_bool_or_false(details, "is_already_created")) {
            // Creating a new subaccount, set its metadata
            locker_t locker(m_mutex);
            if (have_writable_client_blob(locker)) {
                const auto signer_xpubs = m_signer->get_cached_bip32_xpubs_json();
                const nlohmann::json sa_data = { { "name", j_strref(details, "name") }, { "hidden", false } };
                update_client_blob(locker,
                    std::bind(&client_blob::update_subaccount_data, m_blob.get(), subaccount, sa_data, signer_xpubs));
            }
        }
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
        auto addr = rust_call("get_receive_address", details, m_session);
        utxo_add_paths(*this, addr);
        return addr;
    }

    nlohmann::json ga_rust::get_previous_addresses(const nlohmann::json& details)
    {
        nlohmann::json actual_details = details;

        // Same pagination as multisig
        actual_details["count"] = 10;

        return rust_call("get_previous_addresses", actual_details, m_session);
    }

    nlohmann::json ga_rust::get_subaccounts_impl(session_impl::locker_t& /*locker*/)
    {
        return rust_call("get_subaccounts", {}, m_session);
    }

    std::vector<uint32_t> ga_rust::get_subaccount_pointers()
    {
        std::vector<uint32_t> ret;
        for (const auto& pointer : rust_call("get_subaccount_nums", {}, m_session)) {
            ret.emplace_back(pointer);
        }
        return ret;
    }

    void ga_rust::update_subaccount(uint32_t subaccount, const nlohmann::json& details)
    {
        GDK_RUNTIME_ASSERT(j_uint32ref(details, "subaccount") == subaccount);
        // Make the rust call to ensure the subaccount is valid, and
        // store the metadata in case the blobserver is not enabled
        rust_call("update_subaccount", details, m_session);
        if (have_writable_client_blob()) {
            session_impl::update_subaccount(subaccount, details);
        }
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

    nlohmann::json ga_rust::get_available_currencies() const
    {
        nlohmann::json p = nlohmann::json::object();
        p["currency_url"] = m_net_params.get_price_url();

        try {
            return rust_call("get_available_currencies", p, m_session);
        } catch (const std::exception& ex) {
            GDK_LOG(error) << "error fetching currencies: " << ex.what();
            return { { "error", ex.what() } };
        }
    }

    bool ga_rust::is_rbf_enabled() const
    {
        return !m_net_params.is_liquid(); // Not supported on liquid
    }

    nlohmann::json ga_rust::get_settings() const { return rust_call("get_settings", nlohmann::json({}), m_session); }

    void ga_rust::change_settings(const nlohmann::json& settings) { rust_call("change_settings", settings, m_session); }

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

    nlohmann::json ga_rust::encrypt_with_pin(const nlohmann::json& details)
    {
        return rust_call("encrypt_with_pin", details, m_session);
    }

    nlohmann::json ga_rust::decrypt_with_pin(const nlohmann::json& details)
    {
        return rust_call("decrypt_with_pin", details, m_session);
    }

    nlohmann::json ga_rust::get_unspent_outputs(
        const nlohmann::json& details, unique_pubkeys_and_scripts_t& /*missing*/)
    {
        // FIXME: Use 'missing' once unblinding uses HWW interface
        return rust_call("get_unspent_outputs", details, m_session);
    }

    nlohmann::json ga_rust::set_unspent_outputs_status(
        const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        throw std::runtime_error("set_unspent_outputs_status not implemented");
    }

    Tx ga_rust::get_raw_transaction_details(const std::string& txhash_hex) const
    {
        try {
            const std::string tx_hex = rust_call("get_transaction_hex", nlohmann::json(txhash_hex), m_session);
            return Tx(tx_hex, m_net_params.is_liquid());
        } catch (const std::exception& e) {
            GDK_LOG(warning) << "Error fetching " << txhash_hex << " : " << e.what();
            throw user_error("Transaction not found");
        }
    }

    nlohmann::json ga_rust::get_scriptpubkey_data(byte_span_t scriptpubkey)
    {
        try {
            return rust_call("get_scriptpubkey_data", nlohmann::json(b2h(scriptpubkey)), m_session);
        } catch (const std::exception&) {
            return nlohmann::json();
        }
    }

    nlohmann::json ga_rust::send_transaction(const nlohmann::json& details, const nlohmann::json& /*twofactor_data*/)
    {
        auto txhash_hex = broadcast_transaction(details.at("transaction"));
        auto result = details;
        if (details.contains("memo")) {
            set_transaction_memo(txhash_hex, details.at("memo"));
        }
        result["txhash"] = std::move(txhash_hex);
        return result;
    }

    std::string ga_rust::broadcast_transaction(const std::string& tx_hex)
    {
        try {
            return rust_call("broadcast_transaction", nlohmann::json(tx_hex), m_session).get<std::string>();
        } catch (const std::exception& e) {
            // Translate core rpc/electrum errors where possible for i18n
            const std::string what = e.what();
            if (what.find("min relay fee not met") != std::string::npos) {
                throw user_error(res::id_fee_rate_is_below_minimum);
            }
            throw;
        }
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
        session_impl::set_transaction_memo(txhash_hex, memo);
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
        nlohmann::json pricing;

        auto param_pricing = amount_json.value("pricing", nlohmann::json::object());
        if (param_pricing.empty()) {
            pricing = get_settings().value("pricing", nlohmann::json({ { "currency", "" }, { "exchange", "" } }));
        } else {
            pricing = param_pricing;
        }

        std::string currency = amount_json.value("fiat_currency", pricing["currency"]);
        std::string exchange = pricing["exchange"];

        std::string fiat_rate;

        if (!currency.empty() && !exchange.empty()) {
            auto currency_query = nlohmann::json({ { "currencies", currency } });
            currency_query["price_url"] = m_net_params.get_price_url();
            currency_query["fallback_rate"] = amount_json.value("fiat_rate", "");
            currency_query["exchange"] = exchange;

            try {
                auto xrates = rust_call("exchange_rates", currency_query, m_session)["currencies"];
                fiat_rate = xrates.value(currency, "");
            } catch (const std::exception& ex) {
                GDK_LOG(warning) << "cannot fetch exchange rate " << ex.what();
            }
        }

        return amount::convert(amount_json, currency, fiat_rate);
    }

    amount ga_rust::get_min_fee_rate() const { return rust_call("get_min_fee_rate", {}, m_session); }
    amount ga_rust::get_default_fee_rate() const
    {
        // TODO: Implement using a user block default setting when we have one
        return get_min_fee_rate();
    }
    uint32_t ga_rust::get_block_height() const { return rust_call("get_block_height", {}, m_session); }

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

    void ga_rust::disable_all_pin_logins() { throw std::runtime_error("disable_all_pin_logins not implemented"); }

    nlohmann::json ga_rust::get_address_data(const nlohmann::json& details)
    {
        return rust_call("get_address_data", details, m_session);
    }

} // namespace sdk
} // namespace ga
