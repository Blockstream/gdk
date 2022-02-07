#include "session_impl.hpp"
#include "exception.hpp"
#include "ga_rust.hpp"
#include "ga_session.hpp"
#include "ga_tor.hpp"
#include "logging.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"

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

#ifdef BUILD_GDK_RUST
        if (np.is_electrum()) {
            return std::make_shared<ga_rust>(std::move(np));
        }
#endif
        return std::make_shared<ga_session>(std::move(np));
    }

    session_impl::session_impl(network_parameters&& net_params)
        : m_net_params(net_params)
        , m_user_proxy(socksify(m_net_params.get_json().value("proxy", std::string())))
        , m_notification_handler(nullptr)
        , m_notification_context(nullptr)
        , m_notify(true)
    {
        if (m_net_params.use_tor() && m_user_proxy.empty()) {
            // Enable internal tor controller
            m_tor_ctrl = tor_controller::get_shared_ref();
        }
    }

    session_impl::~session_impl() {}

    void session_impl::set_notification_handler(GA_notification_handler handler, void* context)
    {
        m_notification_handler = handler;
        m_notification_context = context;
    }

    void session_impl::emit_notification(nlohmann::json details, bool /*async*/)
    {
        // By default, ignore the async flag
        if (m_notify && m_notification_handler) {
            // We use 'new' here as it is the handlers responsibility to 'delete'
            const auto details_p = reinterpret_cast<GA_json*>(new nlohmann::json(details));
            m_notification_handler(m_notification_context, details_p);
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
        return { { "wallet_hash_id", get_wallet_hash_id(m_net_params, master_chain_code_hex, master_pub_key_hex) } };
    }

    nlohmann::json session_impl::login(std::shared_ptr<signer> /*signer*/)
    {
        GDK_RUNTIME_ASSERT(false); // Only used by rust until it supports HWW
        return nlohmann::json();
    }

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

    nlohmann::json session_impl::psbt_get_details(const nlohmann::json& /*details*/)
    {
        // Overriden for multisig
        return nlohmann::json();
    }

    void session_impl::set_local_encryption_keys(const pub_key_t& /*public_key*/, std::shared_ptr<signer> /*signer*/)
    {
        // Refers to the ga_session cache at the moment, so a no-op for rust sessions
    }

    void session_impl::save_cache()
    {
        // Refers to the ga_session cache at the moment, so a no-op for rust sessions
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

    std::pair<std::string, bool> session_impl::get_cached_master_blinding_key()
    {
        // Overriden for multisig
        return std::make_pair(std::string(), false);
    }

    void session_impl::set_cached_master_blinding_key(const std::string& /*master_blinding_key_hex*/)
    {
        // Overriden for multisig
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

} // namespace sdk
} // namespace ga
