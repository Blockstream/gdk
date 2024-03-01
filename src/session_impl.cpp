
#include <boost/algorithm/string.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/strand.hpp>

#include "exception.hpp"
#include "ga_psbt.hpp"
#include "ga_rust.hpp"
#include "ga_session.hpp"
#include "ga_strings.hpp"
#include "ga_tor.hpp"
#include "ga_tx.hpp"
#include "http_client.hpp"
#include "io_runner.hpp"
#include "json_utils.hpp"
#include "logging.hpp"
#include "session_impl.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "xpub_hdkey.hpp"

namespace ga {
namespace sdk {

    namespace {
        static void check_hint(const std::string& hint, const char* hint_type)
        {
            if (hint != "connect" && hint != "disconnect") {
                GDK_RUNTIME_ASSERT_MSG(false, std::string(hint_type) + " must be either 'connect' or 'disconnect'");
            }
            GDK_LOG(info) << "reconnect_hint: " << hint_type << ":" << hint;
        }

    } // namespace

    std::shared_ptr<session_impl> session_impl::create(const nlohmann::json& net_params)
    {
        auto defaults = network_parameters::get(net_params.value("name", std::string()));
        network_parameters np{ net_params, defaults };

        if (np.is_electrum()) {
            return std::make_shared<ga_rust>(std::move(np));
        }
        return std::make_shared<ga_session>(std::move(np));
    }

    session_impl::session_impl(network_parameters&& net_params)
        : m_net_params(net_params)
        , m_io()
        , m_strand(std::make_unique<boost::asio::io_context::strand>(m_io.get_io_context()))
        , m_user_proxy(socksify(m_net_params.get_json().value("proxy", std::string())))
        , m_notification_handler(nullptr)
        , m_notification_context(nullptr)
        , m_watch_only(true)
        , m_notify(true)
    {
        if (m_net_params.use_tor() && m_user_proxy.empty()) {
            // Enable internal tor controller
            m_tor_ctrl = tor_controller::get_shared_ref();
        }
    }

    session_impl::~session_impl()
    {
        no_std_exception_escape([this] { m_strand.reset(); }, "session_impl m_strand");
    }

    void session_impl::set_notification_handler(GA_notification_handler handler, void* context)
    {
        m_notification_handler = handler;
        m_notification_context = context;
    }

    bool session_impl::set_signer(std::shared_ptr<signer> signer)
    {
        locker_t locker(m_mutex);

        if (!m_signer.get()) {
            // Initial login: set the signer for the session
            m_signer = std::move(signer);
            return false;
        } else {
            GDK_RUNTIME_ASSERT(m_signer.get() == signer.get());
            return true;
        }
    }

    void session_impl::disable_notifications() { m_notify = false; }

    void session_impl::emit_notification(nlohmann::json details, bool /*async*/)
    {
        // By default, ignore the async flag
        if (m_notify && m_notification_handler) {
            // We use 'new' here as it is the handlers responsibility to 'delete'
            const auto details_p = reinterpret_cast<GA_json*>(new nlohmann::json(std::move(details)));
            m_notification_handler(m_notification_context, details_p);
        }
    }

    nlohmann::json session_impl::http_request(nlohmann::json params)
    {
        GDK_RUNTIME_ASSERT_MSG(!params.contains("proxy"), "http_request: proxy is not supported");
        const auto proxy_settings = get_proxy_settings();
        params.update(select_url(params["urls"], proxy_settings["use_tor"]));
        params["proxy"] = proxy_settings["proxy"];

        nlohmann::json result;
        try {
            auto root_certificates = m_net_params.gait_wamp_cert_roots();

            // The caller can specify a set of custom root certiifcates to add
            // to the default network roots
            const auto custom_roots_p = params.find("root_certificates");
            if (custom_roots_p != params.end()) {
                for (const auto& custom_root_certificate : *custom_roots_p) {
                    root_certificates.push_back(custom_root_certificate.get<std::string>());
                }
            }

            const bool is_secure = params["is_secure"];
            std::shared_ptr<boost::asio::ssl::context> ssl_ctx;
            if (is_secure) {
                ssl_ctx = tls_init(params["host"], root_certificates, {}, m_net_params.cert_expiry_threshold());
            }

            std::shared_ptr<http_client> client;
            auto&& get = [&] {
                client = make_http_client(m_io.get_io_context(), ssl_ctx.get());
                GDK_RUNTIME_ASSERT(client != nullptr);

                const auto verb = boost::beast::http::string_to_verb(params["method"]);
                return client->request(verb, params).get();
            };

            constexpr uint8_t num_redirects = 5;
            for (uint8_t i = 0; i < num_redirects; ++i) {
                result = get();
                if (!result.value("location", std::string{}).empty()) {
                    GDK_RUNTIME_ASSERT_MSG(!m_net_params.use_tor(), "redirection over Tor is not supported");
                    params.update(parse_url(result["location"]));
                } else {
                    break;
                }
            }
        } catch (const std::exception& ex) {
            result["error"] = ex.what();
            GDK_LOG(warning) << "Error http_request: " << ex.what();
        }
        return result;
    }

    nlohmann::json session_impl::get_registry_config()
    {
        nlohmann::json config = nlohmann::json::object();
        config["proxy"] = get_proxy_settings()["proxy"];
        config["url"] = m_net_params.get_registry_connection_string();
        if (m_net_params.is_main_net()) {
            config["network"] = "liquid";
        } else if (m_net_params.is_development()) {
            config["network"] = "elements-regtest";
        } else {
            config["network"] = "liquid-testnet";
        }
        return config;
    }

    void session_impl::refresh_assets(nlohmann::json params)
    {
        GDK_RUNTIME_ASSERT(m_net_params.is_liquid());

        if (auto signer = get_signer(); signer) {
            GDK_RUNTIME_ASSERT(!params.contains("xpub"));
            // Descriptor watch only does not have the master xpub
            if (!(m_net_params.is_electrum() && signer->is_watch_only())) {
                params["xpub"] = signer->get_master_bip32_xpub();
            }
        }
        params["config"] = get_registry_config();

        try {
            rust_call("refresh_assets", params);
        } catch (const std::exception& ex) {
            GDK_LOG(error) << "error refreshing assets: " << ex.what();
        }
    }

    nlohmann::json session_impl::get_assets(nlohmann::json params)
    {
        GDK_RUNTIME_ASSERT(m_net_params.is_liquid());

        // We only need to set the xpub if we're accessing the registry cache,
        // which in turn only happens if we're querying via asset ids.
        if (params.contains("assets_id")) {
            if (auto signer = get_signer(); signer) {
                // Descriptor watch only does not have the master xpub
                if (!(m_net_params.is_electrum() && signer->is_watch_only())) {
                    params["xpub"] = signer->get_master_bip32_xpub();
                }
            }
        }
        params["config"] = get_registry_config();

        try {
            return rust_call("get_assets", params);
        } catch (const std::exception& ex) {
            GDK_LOG(error) << "error fetching assets: " << ex.what();
            return { { "assets", nlohmann::json::object() }, { "icons", nlohmann::json::object() },
                { "error", ex.what() } };
        }
    }

    nlohmann::json session_impl::validate_asset_domain_name(const nlohmann::json& params)
    {
        nlohmann::json result;
        try {
            const auto& domain = j_strref(params, "domain");
            const auto& asset_id = j_strref(params, "asset_id");

            auto url = "https://" + domain + "/.well-known/liquid-asset-proof-" + asset_id;
            result = http_request({ { "method", "GET" }, { "urls", { std::move(url) } } });

            if (j_str_is_empty(result, "error")) {
                if (!result.contains("body")) {
                    result["error"] = "error fetching domain proof";
                } else {
                    const std::string proof
                        = "Authorize linking the domain name " + domain + " to the Liquid asset " + asset_id + '\n';
                    if (j_strref(result, "body") != proof) {
                        result["error"] = "domain name proof mismatch";
                    }
                }
            }
        } catch (const std::exception& ex) {
            result["error"] = ex.what();
        }
        result.erase("body");
        return result;
    }

    std::string session_impl::connect_tor()
    {
        // Our built in tor implementation creates a socks5 proxy, which we
        // then connect through in the same way as a user-provided proxy.
        // The address of the proxy is returned to us when we ask tor to wake
        // up, via m_tor_ctrl->wait_for_socks5(). Since the address of the
        // internal proxy can change, we must update it when connecting,
        // and when reconnecting via reconnect_hint(). That is done in 2 ways:
        // We return the proxy here when connecting for the derived session to
        // use, and we expose get_proxy_settings() to fetch the current proxy
        // (either for the session to use, as in http_request(), or for the
        // caller to use if they wish to do application level networking while
        // respecting the sessions connection preferences).
        if (m_tor_ctrl) {
            std::string tor_proxy = m_tor_ctrl->wait_for_socks5([&](std::shared_ptr<tor_bootstrap_phase> p) {
                nlohmann::json tor_json({ { "tag", p->tag }, { "summary", p->summary }, { "progress", p->progress } });
                emit_notification({ { "event", "tor" }, { "tor", std::move(tor_json) } }, true);
            });
            tor_proxy = socksify(tor_proxy);
            if (tor_proxy.empty()) {
                GDK_LOG(warning) << "Timeout initiating tor connection";
                throw timeout_error();
            }
            GDK_LOG(info) << "tor socks address " << tor_proxy;
            locker_t locker(m_mutex);
            m_tor_proxy = tor_proxy;
            return tor_proxy;
        }
        return m_user_proxy;
    }

    void session_impl::reconnect_hint(const nlohmann::json& hint)
    {
        auto hint_p = hint.find("hint");
        if (hint_p != hint.end()) {
            check_hint(*hint_p, "hint"); // Validate hint for derived sessions
        }

        if (m_tor_ctrl && (hint_p = hint.find("tor_hint")) != hint.end()) {
            check_hint(*hint_p, "tor_hint");
            if (*hint_p == "connect") {
                m_tor_ctrl->wakeup(); // no-op if already awake
            } else {
                m_tor_ctrl->sleep(); // no-op if already sleeping
            }
        }
    }

    nlohmann::json session_impl::get_proxy_settings()
    {
        locker_t locker(m_mutex);
        return get_proxy_settings(locker);
    }

    nlohmann::json session_impl::get_proxy_settings(locker_t& locker)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        return { { "proxy", m_tor_ctrl ? m_tor_proxy : m_user_proxy }, { "use_tor", m_net_params.use_tor() } };
    }

    nlohmann::json session_impl::get_net_call_params(uint32_t timeout_secs)
    {
        locker_t locker(m_mutex);
        return get_net_call_params(locker, timeout_secs);
    }

    nlohmann::json session_impl::get_net_call_params(locker_t& locker, uint32_t timeout_secs)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        auto np = m_net_params.get_json();
        np.update(get_proxy_settings(locker));
        np.erase("wamp_cert_pins"); // WMP certs are huge & unused, remove them
        np.erase("wamp_cert_roots");
        return { { "network", std::move(np) }, { "timeout", timeout_secs } };
    }

    nlohmann::json session_impl::register_user(const std::string& master_pub_key_hex,
        const std::string& master_chain_code_hex, const std::string& /*gait_path_hex*/, bool /*supports_csv*/)
    {
        // Default impl just returns the wallet hash; registration is only meaningful in multisig
        auto ret = get_wallet_hash_ids(m_net_params, master_chain_code_hex, master_pub_key_hex);
        ret["warnings"] = nlohmann::json::array();
        return ret;
    }

    void session_impl::load_store(std::shared_ptr<signer> /*signer*/)
    {
        // Overriden for ga_rust
    }

    void session_impl::start_sync_threads()
    {
        // Overriden for ga_rust
    }

    std::string session_impl::get_subaccount_type(uint32_t subaccount) { return get_subaccount(subaccount).at("type"); }

    bool session_impl::discover_subaccount(const std::string& /*xpub*/, const std::string& /*type*/)
    {
        // Overriden for ga_rust
        return false;
    }

    uint32_t session_impl::get_last_empty_subaccount(const std::string& /*type*/)
    {
        // Overriden for ga_rust
        throw std::runtime_error("not implemented");
    }

    bool session_impl::encache_blinding_data(const std::string& /*pubkey_hex*/, const std::string& /*script_hex*/,
        const std::string& /*nonce_hex*/, const std::string& /*blinding_pubkey_hex*/)
    {
        return false; // No caching by default, so return 'not updated'
    }

    void session_impl::encache_new_scriptpubkeys(const uint32_t /*subaccount*/)
    {
        // Overriden for multisig
    }

    nlohmann::json session_impl::get_scriptpubkey_data(byte_span_t /*scriptpubkey*/) { return nlohmann::json(); }

    nlohmann::json session_impl::get_address_data(const nlohmann::json& /*details*/)
    {
        GDK_RUNTIME_ASSERT(false); // Only used by rust
        return nlohmann::json();
    }

    nlohmann::json session_impl::get_transaction_details(const std::string& txhash_hex) const
    {
        const auto tx = get_raw_transaction_details(txhash_hex);
        nlohmann::json ret = { { "txhash", txhash_hex } };
        update_tx_size_info(m_net_params, tx, ret);
        return ret;
    }

    void session_impl::save_cache()
    {
        // Refers to the ga_session cache at the moment, so a no-op for rust sessions
    }

    void session_impl::set_cached_master_blinding_key(const std::string& master_blinding_key_hex)
    {
        if (!master_blinding_key_hex.empty()) {
            // Add the master blinding key to the signer to allow it to unblind.
            // This validates the key is of the correct format
            get_nonnull_signer()->set_master_blinding_key(master_blinding_key_hex);
        }
    }

    session_impl::utxo_cache_value_t session_impl::get_cached_utxos(uint32_t subaccount, uint32_t num_confs) const
    {
        locker_t locker(m_utxo_cache_mutex);
        // FIXME: If we have no unconfirmed txs, 0 and 1 conf results are
        // identical, so we could share 0 & 1 conf storage
        auto p = m_utxo_cache.find({ subaccount, num_confs });
        return p == m_utxo_cache.end() ? utxo_cache_value_t() : p->second;
    }

    session_impl::utxo_cache_value_t session_impl::set_cached_utxos(
        uint32_t subaccount, uint32_t num_confs, nlohmann::json& utxos)
    {
        // Convert null UTXOs into an empty element
        auto& outputs = utxos.at("unspent_outputs");
        if (outputs.is_null()) {
            outputs = nlohmann::json::object();
        }
        // Encache
        locker_t locker(m_utxo_cache_mutex);
        auto entry = std::make_shared<const nlohmann::json>(std::move(utxos));
        m_utxo_cache[std::make_pair(subaccount, num_confs)] = entry;
        return entry;
    }

    void session_impl::remove_cached_utxos(const std::vector<uint32_t>& subaccounts)
    {
        std::vector<utxo_cache_value_t> tmp_values; // Delete outside of lock
        utxo_cache_t tmp_cache;
        {
            locker_t locker(m_utxo_cache_mutex);
            if (subaccounts.empty()) {
                // Empty subaccount list means clear the entire cache
                std::swap(m_utxo_cache, tmp_cache);
            } else {
                // Remove all entries for affected subaccounts
                for (auto p = m_utxo_cache.begin(); p != m_utxo_cache.end(); /* no-op */) {
                    if (std::find(subaccounts.begin(), subaccounts.end(), p->first.first) != subaccounts.end()) {
                        tmp_values.push_back(p->second);
                        m_utxo_cache.erase(p++);
                    } else {
                        ++p;
                    }
                }
            }
        }
    }

    void session_impl::process_unspent_outputs(nlohmann::json& /*utxos*/)
    {
        // Only needed for multisig until singlesig supports HWW
    }

    std::shared_ptr<signer> session_impl::get_nonnull_signer()
    {
        auto signer = get_signer();
        if (!signer) {
            // The session is not logged in
            throw user_error("Authentication required");
        }
        return signer;
    }

    std::shared_ptr<signer> session_impl::get_signer()
    {
        locker_t locker(m_mutex);
        return m_signer;
    }

    bool session_impl::is_watch_only() const
    {
        locker_t locker(m_mutex);
        return m_watch_only;
    }

    void session_impl::ensure_full_session()
    {
        if (is_watch_only()) {
            // TODO: have a better error, and map this error when returned from the server
            throw user_error("Authentication required");
        }
    }

    nlohmann::json session_impl::get_twofactor_config(bool /*reset_cached*/)
    {
        ensure_full_session();
        // Singlesig does not support 2fa. Overridden for multisig.
        nlohmann::json reset_2fa = { { "days_remaining", -1 }, { "is_active", false }, { "is_disputed", false } };
        auto empty_list = nlohmann::json::array();
        return { { "all_methods", empty_list }, { "any_enabled", false }, { "enabled_methods", empty_list },
            { "twofactor_reset", std::move(reset_2fa) }, { "limits", get_spending_limits() }

        };
    }

    nlohmann::json session_impl::get_spending_limits() const
    {
        // Singlesig does not support spending limits. Overridden for multisig.
        auto limits = convert_amount({ { "satoshi", 0 } });
        limits["is_fiat"] = false;
        return limits;
    }

    void session_impl::encache_signer_xpubs(std::shared_ptr<signer> /*signer*/)
    {
        // Overriden for multisig
    }

    ga_pubkeys& session_impl::get_ga_pubkeys()
    {
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    user_pubkeys& session_impl::get_user_pubkeys()
    {
        GDK_RUNTIME_ASSERT_MSG(m_user_pubkeys != nullptr, "Cannot derive keys in watch-only mode");
        return *m_user_pubkeys;
    }

    user_pubkeys& session_impl::get_recovery_pubkeys()
    {
        GDK_RUNTIME_ASSERT(false);
        __builtin_unreachable();
    }

    // Post-login idempotent
    amount session_impl::get_dust_threshold(const std::string& asset_id_hex) const
    {
        if (m_net_params.is_liquid() && asset_id_hex != m_net_params.get_policy_asset()) {
            return amount(1); // No dust threshold for assets
        }
        // BTC and L-BTC use the same threshold. For Liquid, txs are ~10x larger,
        // but fees are 10x smaller. Fees, OP_RETURN and blinded outputs are not
        // subject to the dust limit. As we only create blinded output, we only
        // respect the limit to save users fees on L-BTC sends and change.
        return amount(546);
    }

    nlohmann::json session_impl::sync_transactions(uint32_t /*subaccount*/, unique_pubkeys_and_scripts_t& /*missing*/)
    {
        // Overriden for multisig
        return nlohmann::json();
    }

    void session_impl::store_transactions(uint32_t /*subaccount*/, nlohmann::json& /*txs*/)
    {
        // Overriden for multisig
    }

    void session_impl::postprocess_transactions(nlohmann::json& /*tx_list*/)
    {
        // Overriden for multisig
    }

    bool session_impl::has_recovery_pubkeys_subaccount(uint32_t /*subaccount*/) { return false; }

    std::string session_impl::get_service_xpub(uint32_t /*subaccount*/) { return std::string(); }

    std::string session_impl::get_recovery_xpub(uint32_t /*subaccount*/) { return std::string(); }

    std::vector<unsigned char> session_impl::output_script_from_utxo(const nlohmann::json& utxo)
    {
        locker_t locker(m_mutex);
        return output_script_from_utxo(locker, utxo);
    }

    std::vector<unsigned char> session_impl::output_script_from_utxo(locker_t& locker, const nlohmann::json& utxo)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        using namespace address_type;
        const auto& addr_type = j_strref(utxo, "address_type");

        if (addr_type == p2pkh || m_net_params.is_electrum()) {
            // Sweep or singlesig UTXO
            return scriptpubkey_p2pkh_from_public_key(pubkeys_from_utxo(locker, utxo).at(0));
        }
        // Multisig UTXO
        return multisig_output_script_from_utxo(
            m_net_params, get_ga_pubkeys(), get_user_pubkeys(), get_recovery_pubkeys(), utxo);
    }

    std::vector<pub_key_t> session_impl::pubkeys_from_utxo(const nlohmann::json& utxo)
    {
        locker_t locker(m_mutex);
        return pubkeys_from_utxo(locker, utxo);
    }

    std::vector<pub_key_t> session_impl::pubkeys_from_utxo(locker_t& locker, const nlohmann::json& utxo)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        using namespace address_type;
        const auto& addr_type = j_strref(utxo, "address_type");
        const bool is_electrum = m_net_params.is_electrum();

        if (addr_type == p2pkh) {
            if (!utxo.contains("subaccount")) {
                // Sweep UTXO
                auto pub_key = h2b<EC_PUBLIC_KEY_LEN>(j_strref(utxo, "public_key"));
                GDK_VERIFY(wally_ec_public_key_verify(pub_key.data(), pub_key.size()));
                return { std::move(pub_key) };
            }
            // Multisig doesn't support p2pkh except for sweep UTXOs
            GDK_RUNTIME_ASSERT(is_electrum);
        } else if (is_electrum) {
            GDK_RUNTIME_ASSERT(addr_type == p2sh_p2wpkh || addr_type == p2wpkh);
        } else {
            GDK_RUNTIME_ASSERT(addr_type == csv || addr_type == p2wsh || addr_type == p2sh);
        }

        const auto subaccount = j_uint32ref(utxo, "subaccount");
        const auto pointer = j_uint32ref(utxo, "pointer");
        if (is_electrum) {
            const auto is_internal = j_boolref(utxo, "is_internal");
            return { get_user_pubkeys().derive(subaccount, pointer, is_internal) };
        }
        // TODO: consider returning the recovery key (2of3) as well
        return { get_ga_pubkeys().derive(subaccount, pointer), get_user_pubkeys().derive(subaccount, pointer) };
    }

    nlohmann::json session_impl::decrypt_with_pin(const nlohmann::json& /*details*/)
    {
        GDK_RUNTIME_ASSERT(false);
        return nlohmann::json();
    }

    nlohmann::json session_impl::get_external_unspent_outputs(const nlohmann::json& details)
    {
        auto private_key = j_strref(details, "private_key");
        auto password = j_str_or_empty(details, "password");

        std::string address_type = "p2pkh";
        if (boost::algorithm::starts_with(private_key, "p2pkh:")) {
            private_key = private_key.substr(strlen("p2pkh:"));
            address_type = "p2pkh";
        } else if (boost::algorithm::starts_with(private_key, "p2wpkh:")) {
            private_key = private_key.substr(strlen("p2wpkh:"));
            address_type = "p2wpkh";
        } else if (boost::algorithm::starts_with(private_key, "p2wpkh-p2sh:")) {
            private_key = private_key.substr(strlen("p2wpkh-p2sh:"));
            address_type = "p2sh-p2wpkh";
        }

        std::vector<unsigned char> private_key_bytes;
        bool is_compressed;
        try {
            std::tie(private_key_bytes, is_compressed)
                = to_private_key_bytes(private_key, password, m_net_params.is_main_net());
        } catch (const std::exception&) {
            throw user_error(res::id_invalid_private_key);
        }
        auto private_key_hex = b2h(private_key_bytes);
        auto public_key_hex = b2h(ec_public_key_from_private_key(private_key_bytes, !is_compressed));
        GDK_LOG(debug) << "lookup up " << address_type << " pubkey " << public_key_hex;

        constexpr uint32_t timeout_secs = 10;
        auto opt = get_net_call_params(timeout_secs);
        opt["public_key"] = std::move(public_key_hex);
        opt["address_type"] = std::move(address_type);

        nlohmann::json utxos = rust_call("get_unspent_outputs_for_private_key", opt);
        for (auto& utxo : utxos) {
            utxo["private_key"] = private_key_hex;
            utxo["is_compressed"] = is_compressed;
        }
        return { { "unspent_outputs", { { "btc", std::move(utxos) } } } };
    }

    nlohmann::json session_impl::service_sign_transaction(const nlohmann::json& /*details*/,
        const nlohmann::json& /*twofactor_data*/, std::vector<std::vector<unsigned char>>& /*old_scripts*/)
    {
        // Only implemented for multisig
        throw std::runtime_error("service_sign_transaction not implemented");
    }
} // namespace sdk
} // namespace ga
