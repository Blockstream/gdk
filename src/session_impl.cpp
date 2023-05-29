#include "session_impl.hpp"
#include "boost_wrapper.hpp"
#include "exception.hpp"
#include "ga_rust.hpp"
#include "ga_session.hpp"
#include "ga_tor.hpp"
#include "ga_tx.hpp"
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

    struct io_context_and_guard {
        io_context_and_guard()
            : m_io()
            , m_work_guard(boost::asio::make_work_guard(m_io))
        {
        }

        boost::asio::io_context m_io;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_work_guard;
    };

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
        , m_io(std::make_unique<io_context_and_guard>())
        , m_user_proxy(socksify(m_net_params.get_json().value("proxy", std::string())))
        , m_notification_handler(nullptr)
        , m_notification_context(nullptr)
        , m_notify(true)
    {
        if (m_net_params.use_tor() && m_user_proxy.empty()) {
            // Enable internal tor controller
            m_tor_ctrl = tor_controller::get_shared_ref();
        }
        m_run_thread = std::thread([this] { m_io->m_io.run(); });
    }

    session_impl::~session_impl()
    {
        no_std_exception_escape([this] { m_io->m_work_guard.reset(); }, "session_impl dtor(1)");
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
                client = make_http_client(m_io->m_io, ssl_ctx.get());
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

        // We only need to set the xpub if we're accessing the registry cache,
        // which in turn only happens if we're querying via asset ids.
        if (p.contains("assets_id")) {
            auto session_signer = get_signer();
            if (session_signer != nullptr) {
                p["xpub"] = session_signer->get_master_bip32_xpub();
            }
        }

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

    // TODO: Remove this from all session types once tx creation is shared
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

    nlohmann::json session_impl::get_scriptpubkey_data(byte_span_t /*scriptpubkey*/) { return nlohmann::json(); }

    nlohmann::json session_impl::get_address_data(const nlohmann::json& /*details*/)
    {
        GDK_RUNTIME_ASSERT(false); // Only used by rust
        return nlohmann::json();
    }

    nlohmann::json session_impl::psbt_get_details(const nlohmann::json& details)
    {
        const bool is_liquid = m_net_params.is_liquid();
        const auto psbt = psbt_from_base64(details.at("psbt"));
        const auto tx = psbt_extract_tx(psbt);

        nlohmann::json::array_t inputs;
        inputs.reserve(tx->num_inputs);
        for (size_t i = 0; i < tx->num_inputs; ++i) {
            const std::string txhash_hex = b2h_rev(tx->inputs[i].txhash);
            const uint32_t vout = tx->inputs[i].index;
            for (const auto& utxo : details.at("utxos")) {
                if (utxo.value("txhash", std::string()) == txhash_hex && utxo.at("pt_idx") == vout) {
                    inputs.emplace_back(std::move(utxo));
                    break;
                }
            }
        }

        nlohmann::json::array_t outputs;
        outputs.reserve(tx->num_outputs);
        for (size_t i = 0; i < tx->num_outputs; ++i) {
            const auto& o = tx->outputs[i];
            if (!o.script_len) {
                continue; // Liquid fee
            }
            const auto scriptpubkey = gsl::make_span(o.script, o.script_len);
            auto output_data = get_scriptpubkey_data(scriptpubkey);
            if (output_data.empty()) {
                continue; // Scriptpubkey does not belong the wallet
            }
            if (is_liquid) {
                const auto unblinded = unblind_output(*this, tx, i);
                if (unblinded.contains("error")) {
                    GDK_LOG_SEV(log_level::warning) << "output " << i << ": " << unblinded.at("error");
                    continue; // Failed to unblind
                }
                output_data.update(unblinded);
            }
            outputs.emplace_back(output_data);
        }

        return nlohmann::json{ { "inputs", std::move(inputs) }, { "outputs", std::move(outputs) } };
    }

    void session_impl::create_transaction(nlohmann::json& details) { create_ga_transaction(*this, details); }

    nlohmann::json session_impl::psbt_sign(const nlohmann::json& details)
    {
        const bool is_liquid = m_net_params.is_liquid();
        const bool is_electrum = m_net_params.is_electrum();
        const auto psbt = psbt_from_base64(details.at("psbt"));
        auto tx = psbt_extract_tx(psbt);

        // Get our inputs in order, with UTXO details for signing,
        // or a "skip_signing" indicator if they aren't ours.
        std::vector<nlohmann::json> inputs;
        inputs.reserve(tx->num_inputs);
        size_t num_sigs_required = 0;
        for (size_t i = 0; i < tx->num_inputs; ++i) {
            const std::string txhash_hex = b2h_rev(tx->inputs[i].txhash);
            const uint32_t vout = tx->inputs[i].index;
            nlohmann::json input_utxo({ { "skip_signing", true } });
            for (const auto& utxo : details.at("utxos")) {
                if (!utxo.empty() && utxo.at("txhash") == txhash_hex && utxo.at("pt_idx") == vout) {
                    input_utxo = utxo;
                    const uint32_t sighash = psbt->inputs[i].sighash;
                    input_utxo["user_sighash"] = sighash ? sighash : WALLY_SIGHASH_ALL;
                    ++num_sigs_required;
                    break;
                }
            }
            inputs.emplace_back(input_utxo);
        }

        nlohmann::json::array_t utxos;
        if (!num_sigs_required) {
            // No signatures required, return the PSBT unchanged
            return { { "utxos", utxos }, { "psbt", details.at("psbt") } };
        }
        const bool is_partial = num_sigs_required != tx->num_inputs;
        if (!is_electrum && is_partial) {
            // Multisig partial signing. Ensure all inputs to be signed are segwit
            for (const auto& utxo : inputs) {
                if (json_get_value(utxo, "address_type") == "p2sh") {
                    throw user_error("Non-segwit utxos cannnot be used with psbt_sign");
                }
            }
        }

        // FIXME: refactor to use HWW path
        const auto flags = tx_flags(is_liquid);
        nlohmann::json tx_details = { { "transaction", tx_to_hex(tx, flags) } };
        const auto signatures = sign_ga_transaction(*this, tx_details, inputs).first;

        const bool is_low_r = get_signer()->supports_low_r();
        for (size_t i = 0; i < inputs.size(); ++i) {
            const auto& utxo = inputs.at(i);
            const std::string& signature = signatures.at(i);
            if (utxo.value("skip_signing", false)) {
                GDK_RUNTIME_ASSERT(signature.empty());
                continue;
            }
            add_input_signature(tx, i, utxo, signature, is_low_r);
        }

        utxos.reserve(inputs.size());
        for (auto& utxo : inputs) {
            if (!utxo.value("skip_signing", false)) {
                utxos.emplace_back(std::move(utxo));
            }
        }
        nlohmann::json result = { { "utxos", std::move(utxos) } };

        if (!is_electrum) {
            // Multisig
            std::vector<byte_span_t> old_scripts;
            std::vector<std::vector<unsigned char>> new_scripts;
            auto&& restore_tx = [&tx, &old_scripts] {
                for (size_t i = 0; i < old_scripts.size(); ++i) {
                    tx->inputs[i].script = (unsigned char*)old_scripts[i].data();
                    tx->inputs[i].script_len = old_scripts[i].size();
                }
                old_scripts.clear();
            };
            auto restore_tx_on_throw = gsl::finally([&restore_tx] { restore_tx(); });

            if (is_partial) {
                // Partial signing. For p2sh-wrapped inputs, replace
                // input scriptSigs with redeemScripts before passing to the
                // Green backend. The backend checks the redeemScript for
                // segwit-ness to verify the tx is segwit before signing.
                old_scripts.reserve(tx->num_inputs);
                new_scripts.reserve(tx->num_inputs);
                for (size_t i = 0; i < tx->num_inputs; ++i) {
                    auto& txin = tx->inputs[i];
                    old_scripts.emplace_back(gsl::make_span(txin.script, txin.script_len));
                    new_scripts.emplace_back(psbt_get_input_redeem_script(psbt, i));
                    auto& redeem_script = new_scripts.back();
                    if (!redeem_script.empty()) {
                        redeem_script = script_push_from_bytes(redeem_script);
                        txin.script = redeem_script.data();
                        txin.script_len = redeem_script.size();
                    }
                }
            }

            // We pass the UTXOs in (under a dummy asset key which is unused)
            // for housekeeping purposes such as internal cache updates.
            nlohmann::json u = { { "dummy", std::move(result["utxos"]) } };
            tx_details = { { "transaction", tx_to_hex(tx, flags) }, { "utxos", std::move(u) } };
            restore_tx();

            if (details.contains("blinding_nonces")) {
                tx_details["blinding_nonces"] = details["blinding_nonces"];
            }
            auto ret = service_sign_transaction(tx_details, nlohmann::json::object());
            tx = tx_from_hex(ret.at("transaction"), flags);
            result["utxos"] = std::move(tx_details["utxos"]["dummy"]);
        }

        for (size_t i = 0; i < inputs.size(); ++i) {
            const auto& utxo = inputs.at(i);
            const std::string& signature = signatures.at(i);
            GDK_RUNTIME_ASSERT(signature.empty() == !utxo.empty());
            if (utxo.empty()) {
                /* Finalize the input, but don't remove its finalization data.
                 * FIXME: see comment below on partial signing */
                GDK_VERIFY(wally_psbt_set_input_final_witness(psbt.get(), i, tx->inputs[i].witness));
                GDK_VERIFY(wally_psbt_set_input_final_scriptsig(
                    psbt.get(), i, tx->inputs[i].script, tx->inputs[i].script_len));
            }
        }

        /* For partial signing, we must keep the redeem script in the PSBT
         * for inputs that we have finalized, despite this breaking the spec
         * behaviour. FIXME: Use an extension field for this, since some
         * inputs may have been already properly finalized before we sign.
         */
        uint32_t b64_flags = is_partial ? WALLY_PSBT_SERIALIZE_FLAG_REDUNDANT : 0;
        result["psbt"] = psbt_to_base64(psbt, b64_flags);
        return result;
    }

    nlohmann::json session_impl::user_sign_transaction(const nlohmann::json& details)
    {
        return sign_ga_transaction(*this, details);
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
        GDK_RUNTIME_ASSERT(m_net_params.is_electrum()); // Default impl is single sig
        const std::string addr_type = utxo.at("address_type");
        const auto pubkeys = pubkeys_from_utxo(utxo);

        GDK_RUNTIME_ASSERT(addr_type == address_type::p2sh_p2wpkh || addr_type == address_type::p2wpkh
            || addr_type == address_type::p2pkh);
        return scriptpubkey_p2pkh_from_public_key(pubkeys.at(0));
    }

    std::vector<pub_key_t> session_impl::pubkeys_from_utxo(const nlohmann::json& utxo)
    {
        GDK_RUNTIME_ASSERT(m_net_params.is_electrum()); // Default impl is single sig
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

} // namespace sdk
} // namespace ga
