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
#include "ga_cache.hpp"
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

namespace green {

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

    void ga_rust::set_local_encryption_keys(
        session_impl::locker_t& locker, const pub_key_t& public_key, std::shared_ptr<signer> signer)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        const bool is_watch_only = signer->is_watch_only();

        // Load the cache on the rust side
        nlohmann::json store_details;
        if (is_watch_only) {
            // Create a cache filename and encryption key
            auto local_encryption_key = pbkdf2_hmac_sha512(public_key, signer::PASSWORD_SALT);
            // Use a network name unique to rich watch only, so in the future
            // we can use ga_cache for singlesig caching without conflict.
            auto network_name = m_net_params.network() + "RWO";
            const auto [filename, type, encryption_key]
                = cache::get_name_type_and_key(local_encryption_key, network_name, signer);
            store_details = { { "filename", std::move(filename) }, { "encryption_key_hex", b2h(encryption_key) } };
        } else {
            // Use the master xpub to derive the cache filename and encryption key
            GDK_RUNTIME_ASSERT(signer->has_master_bip32_xpub());
            auto master_xpub = signer->get_master_bip32_xpub();
            store_details = { { "master_xpub", std::move(master_xpub) } };
        }
        rust_call("load_store", store_details, m_session);

        if (!signer->has_master_blinding_key()) {
            // Load the cached master blinding key, if we have it
            std::string blinding_key_hex;
            bool denied;
            std::tie(blinding_key_hex, denied) = get_cached_master_blinding_key();
            if (!denied) {
                signer->set_master_blinding_key(blinding_key_hex);
            }
        }

        // Compute client blob id from the privately derived pubkey
        m_blob->compute_client_id(m_net_params.network(), public_key);

        if (is_watch_only) {
            // The client blob encryption key must be provided from credentials
            GDK_RUNTIME_ASSERT_MSG(m_blob->has_key(), "watch_only_data must be provided for singlesig watch only");
        } else {
            // Compute client blob encryption key
            m_blob->compute_keys(public_key);
        }
    }

    void ga_rust::populate_initial_client_blob(session_impl::locker_t& locker)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_LOG(info) << "Populating initial client blob";
        // Subaccount names/xpubs
        m_blob->update_subaccounts_data(get_local_subaccounts_data(), m_signer->get_cached_bip32_xpubs_json());
        // Tx memos
        m_blob->update_tx_memos(rust_call("get_memos", {}, m_session));
        // Master blinding key (Liquid)
        if (m_net_params.is_liquid() && m_signer->has_master_blinding_key()) {
            m_blob->set_master_blinding_key(b2h(m_signer->get_master_blinding_key()));
        }
        m_blob->set_user_version(1); // Initial version
        m_blob->set_is_modified();
        m_blob->set_requires_merge();
    }

    void ga_rust::get_cached_local_client_blob(session_impl::locker_t& locker, const std::string& /*server_hmac*/)
    {
        // Load our client blob from from the cache if we have one
        if (!m_blob->get_hmac().empty()) {
            return; // Already loaded
        }
        const auto blob_data = rust_call("load_blob", {}, m_session);
        if (!j_str_is_empty(blob_data, "blob")) {
            // We have a local blob, load it into our in-memory blob
            GDK_RUNTIME_ASSERT(m_watch_only || m_blob->has_hmac_key());
            m_blob->load(base64_to_bytes(j_strref(blob_data, "blob")), j_strref(blob_data, "hmac"));
            if (j_boolref(blob_data, "requires_merge")) {
                m_blob->set_requires_merge();
            }
        }
    }

    void ga_rust::encache_local_client_blob(
        session_impl::locker_t& locker, std::string data_b64, byte_span_t /*data*/, const std::string& hmac)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        nlohmann::json args{ { "blob", std::move(data_b64) }, { "client_id", m_blob->get_client_id() },
            { "hmac", hmac }, { "requires_merge", m_blob->get_requires_merge() } };
        rust_call("save_blob", args, m_session);
    }

    std::string ga_rust::get_challenge(const pub_key_t& /*public_key*/) { throw std::runtime_error("not implemented"); }

    nlohmann::json ga_rust::authenticate(const std::string& /*sig_der_hex*/, std::shared_ptr<signer> signer)
    {
        locker_t locker(m_mutex);
        set_signer(locker, signer);
        m_watch_only = signer->is_watch_only();
        pub_key_t public_key;
        if (m_watch_only) {
            public_key = set_blob_key_from_credentials(locker);
        } else {
            public_key = xpub_hdkey(signer->get_bip32_xpub(signer::CLIENT_SECRET_PATH)).get_public_key();
        }
        set_local_encryption_keys(locker, public_key, signer);

        // Load any cached blob data
        get_cached_local_client_blob(locker, std::string());
        const auto cached_hmac = m_blob->get_hmac();
        const bool had_cached_blob = !cached_hmac.empty();
        if (!had_cached_blob && !m_watch_only) {
            // We don't have a local client blob. Create one for merging
            populate_initial_client_blob(locker);
        }

        // Load the latest blob from the server. If the server blob is
        // newer, this updates our locally cached blob data to it,
        // and merges any local data if required.
        bool had_server_blob = load_client_blob(locker, true);
        if (!had_cached_blob && !had_server_blob && m_watch_only) {
            // The user has entered the wrong credentials or the
            // client blob is not on the server or in the local cache.
            // The user must either:
            // - Login with correct credentials, or
            // - Perform some action in the full session that will re-create
            //   the client blob on the blobserver.
            GDK_LOG(error) << "Client blob not found for watch-only login credentials";
            throw user_error(res::id_user_not_found_or_invalid);
        }

        if (!m_watch_only) {
            if (!had_server_blob && have_client_blob_server(locker) && !m_blob->get_server_has_failure()) {
                // No server blob, but a working blobserver is configured: save it
                // FIXME: handle race on initial blob creation
                save_client_blob(locker, client_blob::get_zero_hmac());
            }
            if (m_blob->is_modified() || cached_hmac != m_blob->get_hmac()) {
                save_client_blob(locker, m_blob->get_hmac());
            }
        }

        // Load any xpubs from the blob into our signer
        load_signer_xpubs(locker, m_blob->get_xpubs(), signer);

        // Set the master xpub fingerprint in the store
        GDK_RUNTIME_ASSERT(signer->has_master_bip32_xpub());
        auto master_xpub = signer->get_master_bip32_xpub();
        const auto fingerprint = xpub_hdkey(master_xpub).get_fingerprint();
        rust_call("set_fingerprint", nlohmann::json(b2h(fingerprint)), m_session);

        m_login_data = get_wallet_hash_ids(
            { { "name", m_net_params.network() } }, { { "master_xpub", std::move(master_xpub) } });
        m_login_data["warnings"] = nlohmann::json::array();

        subscribe_all(locker);
        return m_login_data;
    }

    void ga_rust::on_post_login()
    {
        locker_t locker(m_mutex);
        const auto version = m_blob->get_user_version();
        if (m_net_params.is_liquid()) {
            // Pass the master blinding key to the rust side, and update
            // it in the blob/signer if not present,i.e. if this is an initial
            // login with no blob and no local cache.
            // Full sessions have the blinding key in the signer, while
            // watch only sessions have it in the client blob.
            std::string master_blinding_key_hex;
            if (m_signer->has_master_blinding_key() && !m_blob->has_master_blinding_key()) {
                master_blinding_key_hex = b2h(m_signer->get_master_blinding_key());
                m_blob->set_master_blinding_key(master_blinding_key_hex);
            } else {
                master_blinding_key_hex = m_blob->get_master_blinding_key();
            }
            GDK_RUNTIME_ASSERT(!master_blinding_key_hex.empty());
            set_cached_master_blinding_key_impl(locker, master_blinding_key_hex);
        }
        // Update the blob with our now-loaded subaccount xpubs
        m_blob->set_xpubs(m_signer->get_cached_bip32_xpubs_json());

        if (m_blob->get_user_version() != version) {
            // Blob has been modified, save it
            m_blob->set_user_version(version + 1);
            save_client_blob(locker, m_blob->get_hmac());
        }
    }

    void ga_rust::start_sync_threads()
    {
        on_post_login();
        rust_call("start_threads", {}, m_session);
    }

    void ga_rust::register_subaccount_xpubs(
        const std::vector<uint32_t>& pointers, const std::vector<std::string>& bip32_xpubs)
    {
        // We only register subaccounts that the rust session has told us
        // exist, so pass is_already_created to avoid new subaccount checks
        nlohmann::json details({ { "name", std::string() }, { "is_already_created", true } });
        for (size_t i = 0; i < pointers.size(); ++i) {
            const auto pointer = pointers.at(i);
            if (!m_user_pubkeys->have_subaccount(pointer)) {
                const auto& bip32_xpub = bip32_xpubs.at(i);
                details["subaccount"] = pointer;
                details["xpub"] = bip32_xpub;
                rust_call("create_subaccount", details, m_session);
                locker_t locker(m_mutex);
                m_user_pubkeys->add_subaccount(pointer, bip32_xpub);
            }
        }
    }

    nlohmann::json ga_rust::credentials_from_pin_data(const nlohmann::json& pin_data)
    {
        return rust_call("credentials_from_pin_data", pin_data, m_session);
    }

    nlohmann::json ga_rust::login_wo(std::shared_ptr<signer> signer)
    {
        const auto credentials = signer->get_credentials();
        {
            locker_t locker(m_mutex);
            set_signer(locker, signer);
            m_watch_only = true;
            if (signer->is_descriptor_watch_only()) {
                m_blobserver.reset(); // No blobserver for descriptor wallets
                locker.unlock();
                return rust_call("login_wo", credentials, m_session);
            }
        }

        authenticate(std::string(), signer);

        // For watch only we must call on_post_login before creating our
        // subaccounts, in order to load the master blinding key for liquid
        // (which register_subaccount_xpubs requires).
        on_post_login();

        // Register the subaccounts using the blob data to identify them
        const auto pointers = get_subaccount_pointers();
        std::vector<std::string> xpubs;
        for (const auto& pointer : pointers) {
            xpubs.push_back(signer->get_bip32_xpub(get_subaccount_root_path(pointer)));
        }
        register_subaccount_xpubs(pointers, xpubs);

        // Call the rust start_threads directly to avoid repeating the call to
        // on_post_login in this class's start_threads method
        rust_call("start_threads", {}, m_session);
        return m_login_data;
    }

    bool ga_rust::remove_account(const nlohmann::json& twofactor_data)
    {
        rust_call("remove_account", {}, m_session);
        return true;
    }

    bool ga_rust::discover_subaccount(uint32_t subaccount, const std::string& xpub, const std::string& type)
    {
        nlohmann::json details = { { "type", type }, { "xpub", xpub } };
        if (!rust_call("discover_subaccount", details, m_session)) {
            return false;
        }
        details = { { "name", std::string() }, { "subaccount", subaccount }, { "xpub", xpub }, { "discovered", true } };
        {
            locker_t locker(m_mutex);
            if (m_blobserver) {
                // Provide any metadata we may already have for the subaccount
                // from another session that created it
                sync_client_blob(locker);
                auto sa_data = m_blob->get_subaccount_data(subaccount);
                details["name"] = j_str_or_empty(sa_data, "name");
                details["hidden"] = j_bool_or_false(sa_data, "hidden");
            }
        }
        rust_call("create_subaccount", details, m_session);
        locker_t locker(m_mutex);
        m_user_pubkeys->add_subaccount(subaccount, xpub);
        return true;
    }

    uint32_t ga_rust::get_next_subaccount(const std::string& type)
    {
        return rust_call("get_next_subaccount", nlohmann::json({ { "type", type } }), m_session);
    }

    uint32_t ga_rust::get_last_empty_subaccount(const std::string& type)
    {
        return rust_call("get_last_empty_subaccount", nlohmann::json({ { "type", type } }), m_session);
    }

    nlohmann::json ga_rust::create_subaccount(nlohmann::json details, uint32_t subaccount, const std::string& xpub)
    {
        details["subaccount"] = subaccount;
        details["xpub"] = xpub;
        auto ret = rust_call("create_subaccount", details, m_session);
        // Creating a new subaccount, set its metadata
        locker_t locker(m_mutex);
        m_user_pubkeys->add_subaccount(subaccount, xpub);
        if (have_writable_client_blob(locker)) {
            nlohmann::json sa_data = { { "name", j_strref(details, "name") }, { "hidden", false } };
            nlohmann::json subaccounts = { { std::to_string(subaccount), std::move(sa_data) } };
            const auto signer_xpubs = m_signer->get_cached_bip32_xpubs_json();
            update_client_blob(
                locker, std::bind(&client_blob::update_subaccounts_data, m_blob.get(), subaccounts, signer_xpubs));
        }
        return ret;
    }

    std::pair<std::string, bool> ga_rust::get_cached_master_blinding_key()
    {
        const auto ret = rust_call("get_master_blinding_key", {}, m_session);
        constexpr bool is_denied = false;
        return { ret.value("master_blinding_key", std::string()), is_denied };
    }

    void ga_rust::set_cached_master_blinding_key_impl(
        session_impl::locker_t& locker, const std::string& master_blinding_key_hex)
    {
        GDK_RUNTIME_ASSERT_MSG(
            !master_blinding_key_hex.empty(), "HWW must enable host unblinding for singlesig wallets");
        session_impl::set_cached_master_blinding_key_impl(locker, master_blinding_key_hex);
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
        auto notification = json_parse(json);
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
        GDKRUST_set_notification_handler(m_session, green::ga_rust::GDKRUST_notif_handler, this);
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

    nlohmann::json ga_rust::get_local_subaccounts_data()
    {
        auto subaccounts = rust_call("get_accounts_settings", {}, m_session);
        for (auto& item : subaccounts.items()) {
            auto& value = item.value();
            if (j_str_or_empty(value, "name").empty()) {
                value.erase("name");
            }
        }
        return subaccounts;
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
        // Make the rust call to ensure the subaccount is valid
        rust_call("update_subaccount", details, m_session);
        if (!m_watch_only) {
            session_impl::update_subaccount(subaccount, details);
        }
    }

    std::vector<uint32_t> ga_rust::get_subaccount_root_path(uint32_t subaccount)
    {
        return m_user_pubkeys->get_subaccount_root_path(subaccount);
    }

    std::vector<uint32_t> ga_rust::get_subaccount_full_path(uint32_t subaccount, uint32_t pointer, bool is_internal)
    {
        return m_user_pubkeys->get_subaccount_full_path(subaccount, pointer, is_internal);
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

    green_pubkeys& ga_rust::get_green_pubkeys() { throw std::runtime_error("get_green_pubkeys not implemented"); }
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

} // namespace green
