#include "session_impl.hpp"
#include "exception.hpp"
#include "ga_lightning.hpp"
#include "ga_rust.hpp"
#include "ga_session.hpp"
#include "ga_tor.hpp"
#include "http_client.hpp"
#include "logging.hpp"
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
            GDK_LOG_SEV(log_level::info) << "reconnect_hint: " << hint_type << ":" << hint;
        }

    } // namespace

    std::shared_ptr<session_impl> session_impl::create(const nlohmann::json& net_params)
    {
        auto defaults = network_parameters::get(net_params.value("name", std::string()));
        network_parameters np{ net_params, defaults };

        if (np.is_electrum()) {
            return std::make_shared<ga_rust>(std::move(np));
        }
        if (np.is_lightning()) {
            return std::make_shared<ga_lightning>(std::move(np));
        }
        return std::make_shared<ga_session>(std::move(np));
    }

    session_impl::session_impl(network_parameters&& net_params)
        : m_net_params(net_params)
        , m_io()
        , m_work_guard(boost::asio::make_work_guard(m_io))
        , m_user_proxy(socksify(m_net_params.get_json().value("proxy", std::string())))
        , m_notification_handler(nullptr)
        , m_notification_context(nullptr)
        , m_notify(true)
    {
        if (m_net_params.use_tor() && m_user_proxy.empty()) {
            // Enable internal tor controller
            m_tor_ctrl = tor_controller::get_shared_ref();
        }
        m_run_thread = std::thread([this] { m_io.run(); });
    }

    session_impl::~session_impl()
    {
        no_std_exception_escape([this] { m_work_guard.reset(); }, "session_impl dtor(1)");
        no_std_exception_escape([this] { m_run_thread.join(); }, "session_impl dtor(2)");
    }

    void session_impl::set_notification_handler(GA_notification_handler handler, void* context)
    {
        m_notification_handler = handler;
        m_notification_context = context;
    }

    bool session_impl::set_signer(std::shared_ptr<signer> signer)
    {
        locker_t locker(m_mutex);

        const bool is_initial_login = m_signer == nullptr;
        if (is_initial_login) {
            m_signer = signer;
        } else {
            // Re-login must use the same signer
            GDK_RUNTIME_ASSERT(m_signer.get() == signer.get());
        }
        return is_initial_login;
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
                client = make_http_client(m_io, ssl_ctx.get());
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
            GDK_LOG_SEV(log_level::warning) << "Error http_request: " << ex.what();
        }
        return result;
    }

    nlohmann::json session_impl::get_registry_config() const
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

    void session_impl::refresh_assets(const nlohmann::json& params)
    {
        GDK_RUNTIME_ASSERT(m_net_params.is_liquid());

        nlohmann::json p = params;

        auto session_signer = get_signer();
        if (session_signer != nullptr) {
            GDK_RUNTIME_ASSERT(!p.contains("xpub"));
            p["xpub"] = session_signer->get_master_bip32_xpub();
        }

        p["config"] = get_registry_config();

        try {
            rust_call("refresh_assets", p);
        } catch (const std::exception& ex) {
            GDK_LOG_SEV(log_level::error) << "error fetching assets: " << ex.what();
        }
    }

    nlohmann::json session_impl::get_assets(const nlohmann::json& params)
    {
        GDK_RUNTIME_ASSERT(m_net_params.is_liquid());

        nlohmann::json p = params;

        p["xpub"] = get_nonnull_signer()->get_master_bip32_xpub();
        p["config"] = get_registry_config();

        try {
            return rust_call("get_assets", p);
        } catch (const std::exception& ex) {
            GDK_LOG_SEV(log_level::error) << "error fetching assets: " << ex.what();
            return { { "assets", nlohmann::json::object() }, { "icons", nlohmann::json::object() },
                { "error", ex.what() } };
        }
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
                GDK_LOG_SEV(log_level::warning) << "Timeout initiating tor connection";
                throw timeout_error();
            }
            GDK_LOG_SEV(log_level::info) << "tor socks address " << tor_proxy;
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

    nlohmann::json session_impl::get_proxy_settings() const
    {
        std::string proxy = m_user_proxy;
        if (m_tor_ctrl) {
            locker_t locker(m_mutex);
            proxy = m_tor_proxy;
        }
        return { { "proxy", proxy }, { "use_tor", m_net_params.use_tor() } };
    }

    nlohmann::json session_impl::register_user(const std::string& master_pub_key_hex,
        const std::string& master_chain_code_hex, const std::string& /*gait_path_hex*/, bool /*supports_csv*/)
    {
        // Default impl just returns the wallet hash; registration is only meaningful in multisig
        return get_wallet_hash_ids(m_net_params, master_chain_code_hex, master_pub_key_hex);
    }

    nlohmann::json session_impl::login(std::shared_ptr<signer> /*signer*/)
    {
        GDK_RUNTIME_ASSERT(false); // Only used by rust until it supports HWW
        return nlohmann::json();
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

    bool session_impl::encache_blinding_data(const std::string& /*pubkey_hex*/, const std::string& /*script_hex*/,
        const std::string& /*nonce_hex*/, const std::string& /*blinding_pubkey_hex*/)
    {
        return false; // No caching by default, so return 'not updated'
    }

    void session_impl::encache_scriptpubkey_data(byte_span_t /*scriptpubkey*/, const uint32_t /*subaccount*/,
        const uint32_t /*branch*/, const uint32_t /*pointer*/, const uint32_t /*subtype*/,
        const uint32_t /*script_type*/)
    {
        // Overriden for multisig
    }

    void session_impl::encache_new_scriptpubkeys(const uint32_t /*subaccount*/)
    {
        // Overriden for multisig
    }

    nlohmann::json session_impl::get_scriptpubkey_data(byte_span_t /*scriptpubkey*/)
    {
        // Overriden for multisig
        return nlohmann::json();
    }

    nlohmann::json session_impl::psbt_get_details(const nlohmann::json& /*details*/) { return nlohmann::json(); }

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
        GDK_RUNTIME_ASSERT(signer != nullptr);
        return signer;
    }

    std::shared_ptr<signer> session_impl::get_signer()
    {
        locker_t locker(m_mutex);
        return m_signer;
    }

    void session_impl::encache_signer_xpubs(std::shared_ptr<signer> /*signer*/)
    {
        // Overriden for multisig
    }

    // Post-login idempotent
    user_pubkeys& session_impl::get_user_pubkeys()
    {
        GDK_RUNTIME_ASSERT_MSG(m_user_pubkeys != nullptr, "Cannot derive keys in watch-only mode");
        return *m_user_pubkeys;
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
        const std::string addr_type = utxo.at("address_type");
        const auto pubkeys = pubkeys_from_utxo(utxo);

        GDK_RUNTIME_ASSERT(addr_type == address_type::p2sh_p2wpkh || addr_type == address_type::p2wpkh
            || addr_type == address_type::p2pkh);
        return scriptpubkey_p2pkh_from_public_key(pubkeys.at(0));
    }

    std::vector<pub_key_t> session_impl::pubkeys_from_utxo(const nlohmann::json& utxo)
    {
        const uint32_t subaccount = utxo.at("subaccount");
        const uint32_t pointer = utxo.at("pointer");
        const bool is_internal = utxo.at("is_internal");
        locker_t locker(m_mutex);
        return std::vector<pub_key_t>({ get_user_pubkeys().derive(subaccount, pointer, is_internal) });
    }

    nlohmann::json session_impl::decrypt_with_pin(const nlohmann::json& /*details*/)
    {
        GDK_RUNTIME_ASSERT(false);
        return nlohmann::json();
    }

    nlohmann::json session_impl::gl_call(const char* /*method*/, const nlohmann::json& /*params*/)
    {
        // Overriden for ga_lightning
        return nlohmann::json();
    }

} // namespace sdk
} // namespace ga
