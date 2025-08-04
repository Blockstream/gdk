#include <array>
#include <cstdio>
#include <fstream>
#include <map>
#include <string>
#include <thread>
#include <vector>

#include <sys/stat.h>
#include <sys/types.h>

#ifndef WIN32
#include <unistd.h>
#endif
#include "session.hpp"
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/lexical_cast.hpp>
#include <nlohmann/json.hpp>

#include "assertion.hpp"
#include "autobahn_wrapper.hpp"
#include "client_blob.hpp"
#include "containers.hpp"
#include "exception.hpp"
#include "ga_cache.hpp"
#include "ga_session.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "json_utils.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "signer.hpp"
#include "threading.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "version.h"
#include "wamp_transport.hpp"
#include "xpub_hdkey.hpp"

using namespace std::literals;

namespace green {

    namespace {
        static const std::string USER_AGENT_CAPS("[v2,sw,csv,csv_opt]");
        static const std::string USER_AGENT_CAPS_NO_CSV("[v2,sw]");

        static const std::string MASKED_GAUTH_SEED("***");
        static const uint32_t DEFAULT_MIN_FEE = 1000; // 1 satoshi/byte
        static const uint32_t DEFAULT_MIN_FEE_LIQUID = 100; // 0.1 satoshi/byte
        static const uint32_t NUM_FEE_ESTIMATES = 25; // Min fee followed by blocks 1-24

        static const std::string ZEROS(64, '0');

        // Multi-call categories
        constexpr uint32_t MC_TX_CACHE = 0x1; // Call affects the tx cache

        // Transaction notification fields that we know about.
        // If we see a notification with fields other than these, we ignore
        // it so we don't process it incorrectly (forward compatibility).
        // Fields under the TXN_OPTIONAL key are exempt from this check.
        static const std::string TXN_OPTIONAL("optional");
        static const std::array<const std::string, 4> TX_NTFY_FIELDS
            = { "subaccounts", "txhash", "value", TXN_OPTIONAL };

        static bool ignore_tx_notification(const nlohmann::json& details)
        {
            for (const auto& item : details.items()) {
                const std::string key = item.key();
                if (std::find(TX_NTFY_FIELDS.begin(), TX_NTFY_FIELDS.end(), key) == TX_NTFY_FIELDS.end()) {
                    GDK_LOG(info) << "Ignoring tx notification: unknown field " << item.key();
                    return true; // Skip this notification as we don't understand it
                }
            }
            return false; // All fields are known, process the notification
        }

        static std::vector<uint32_t> cleanup_tx_notification(nlohmann::json& details)
        {
            // Convert affected subaccounts from (singular/array of)(null/number)
            // to a sorted array of subaccounts
            std::vector<uint32_t> affected;
            const auto& subaccounts = details["subaccounts"];
            if (subaccounts.is_null()) {
                affected.push_back(0);
            } else if (subaccounts.is_array()) {
                for (const auto& sa : subaccounts) {
                    if (sa.is_null()) {
                        affected.push_back(0);
                    } else {
                        affected.push_back(sa.get<uint32_t>());
                    }
                }
            } else {
                affected.push_back(subaccounts.get<uint32_t>());
            }
            std::sort(affected.begin(), affected.end());
            details["subaccounts"] = affected;

            // Move TXN_OPTIONAL fields to the top level
            auto optional_p = details.find(TXN_OPTIONAL);
            if (optional_p != details.end()) {
                for (auto& item : optional_p->items()) {
                    std::swap(details[item.key()], item.value());
                }
                details.erase(optional_p);
            }

            return affected;
        }

        static msgpack::object_handle mp_cast(const nlohmann::json& json)
        {
            if (json.is_null()) {
                return msgpack::object_handle();
            }
            const auto buffer = nlohmann::json::to_msgpack(json);
            return msgpack::unpack(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        }

        static nlohmann::json get_twofactor_reset_status(
            const session_impl::locker_t& locker, const nlohmann::json& server_data)
        {
            GDK_RUNTIME_ASSERT(locker.owns_lock());

            if (server_data.empty() || server_data.is_null()) {
                // login_data before we login is empty, return disabled config in this case
                return { { "is_active", false }, { "days_remaining", -1 }, { "is_disputed", false } };
            }
            return { { "is_active", server_data.value("reset_2fa_active", false) },
                { "days_remaining", server_data.value("reset_2fa_days_remaining", -1) },
                { "is_disputed", server_data.value("reset_2fa_disputed", false) } };
        }

        static amount::value_type get_limit_total(const nlohmann::json& details)
        {
            const auto& total_p = details.at("total");
            amount::value_type total;
            if (total_p.is_number()) {
                total = total_p;
            } else {
                const std::string total_str = total_p;
                total = strtoull(total_str.c_str(), nullptr, 10);
            }
            return total;
        }

        // Make sure appearance settings match our expectations
        static void cleanup_appearance_settings(const session_impl::locker_t& locker, nlohmann::json& appearance)
        {
            GDK_RUNTIME_ASSERT(locker.owns_lock());

            nlohmann::json clean({
                { "unit", std::string("BTC") },
                { "replace_by_fee", true },
                { "sound", true },
                { "altimeout", 5u },
                { "required_num_blocks", 12u },
                { "notifications_settings", nlohmann::json::object() },
            });
            clean.update(appearance);

            if (!clean["altimeout"].is_number_unsigned()) {
                clean["altimeout"] = 5u;
            }
            if (!clean["replace_by_fee"].is_boolean()) {
                clean["replace_by_fee"] = true;
            }
            if (!clean["required_num_blocks"].is_number_unsigned()) {
                clean["required_num_blocks"] = 12u;
            }
            if (!clean["sound"].is_boolean()) {
                clean["sound"] = true;
            }
            if (!clean["unit"].is_string()) {
                clean["unit"] = std::string("BTC");
            }

            GDK_RUNTIME_ASSERT(clean["notifications_settings"].is_object());
            nlohmann::json clean_notifications_settings({
                { "email_incoming", false },
                { "email_outgoing", false },
                { "email_login", false },
            });
            clean_notifications_settings.update(clean["notifications_settings"]);
            clean["notifications_settings"] = clean_notifications_settings;
            GDK_RUNTIME_ASSERT(clean["notifications_settings"]["email_incoming"].is_boolean());
            GDK_RUNTIME_ASSERT(clean["notifications_settings"]["email_outgoing"].is_boolean());
            GDK_RUNTIME_ASSERT(clean["notifications_settings"]["email_login"].is_boolean());

            // Make sure the default block target is one of [3, 12, or 24]
            uint32_t required_num_blocks = clean["required_num_blocks"];
            if (required_num_blocks > 12u) {
                required_num_blocks = 24u;
            } else if (required_num_blocks >= 6u) {
                required_num_blocks = 12u;
            } else {
                required_num_blocks = 3u;
            }
            clean["required_num_blocks"] = required_num_blocks;

            appearance = clean;
        }

        static auto get_wo_appearance_overrides(const session_impl::locker_t& locker, const nlohmann::json& appearance)
        {
            GDK_RUNTIME_ASSERT(locker.owns_lock());
            nlohmann::json wo_appearance{};
            for (const auto& key : { "unit"sv, "sound"sv, "altimeout"sv, "required_num_blocks"sv }) {
                if (auto p = appearance.find(key); p != appearance.end()) {
                    if (!p->is_string() || !p->get_ref<const std::string&>().empty()) {
                        wo_appearance[key] = *p;
                    }
                }
            }
            return wo_appearance;
        }

        // Get username/password for using the Green backend as our blobserver
        static std::pair<std::string, std::string> get_green_wo_credentials(byte_span_t entropy)
        {
            // Generate the watch only server username/password. Unlike non-blob
            // watch only logins, we don't want the server to know the original
            // username/password, since we use these to encrypt the client blob
            // decryption key.
            const auto u_blob = pbkdf2_hmac_sha512_256(entropy, signer::WO_SEED_U);
            const auto p_blob = pbkdf2_hmac_sha512_256(entropy, signer::WO_SEED_P);
            return { b2h(u_blob), b2h(p_blob) };
        }

        std::string get_user_agent(bool supports_csv, const std::string& version)
        {
            constexpr auto max_len = 64;
            const auto& caps = supports_csv ? USER_AGENT_CAPS : USER_AGENT_CAPS_NO_CSV;
            auto user_agent = caps + version;
            if (user_agent.size() > max_len) {
                GDK_LOG(warning) << "Truncating user agent string, exceeds max length (" << max_len << ")";
                user_agent = user_agent.substr(0, max_len);
            }
            return user_agent;
        }

        static std::vector<uint32_t> bytes_to_bip32_path(byte_span_t bytes)
        {
            GDK_RUNTIME_ASSERT(bytes.size() % 2 == 0);
            std::vector<uint32_t> ret(bytes.size() / 2);
            for (size_t i = 0; i < bytes.size(); i += 2) {
                ret[i / 2] = (bytes[i] << 8) | bytes[i + 1];
            }
            return ret;
        }
    } // namespace

    ga_session::ga_session(network_parameters&& net_params)
        : session_impl(std::move(net_params))
        , m_min_fee_rate(m_net_params.is_liquid() ? DEFAULT_MIN_FEE_LIQUID : DEFAULT_MIN_FEE)
        , m_earliest_block_time(0)
        , m_next_subaccount(0)
        , m_fee_estimates_ts(std::chrono::system_clock::now())
        , m_system_message_id(0)
        , m_system_message_ack_id(0)
        , m_tx_last_notification(std::chrono::system_clock::now())
        , m_last_block_notification()
        , m_multi_call_category(0)
        , m_cache(std::make_shared<cache>(m_net_params, m_net_params.network()))
        , m_user_agent(std::string(GDK_COMMIT) + " " + m_net_params.user_agent())
    {
        m_user_pubkeys = std::make_unique<green_user_pubkeys>(m_net_params);

        constexpr bool is_mandatory = true;
        m_wamp = std::make_shared<wamp_transport>(
            m_net_params, *session_impl::m_strand,
            [this](nlohmann::json details, bool async) { emit_notification(std::move(details), async); }, "wamp",
            is_mandatory);
        m_wamp_connections.push_back(m_wamp);

        m_fee_estimates.assign(NUM_FEE_ESTIMATES, m_min_fee_rate);
    }

    ga_session::~ga_session()
    {
        m_wamp.reset();
        m_notify = false;
        no_std_exception_escape([this] { reset_all_session_data(true); });
    }

    void ga_session::reconnect_hint_session(const nlohmann::json& /*hint*/, const nlohmann::json& /*proxy*/)
    {
        // Currently a no-op
    }

    void ga_session::emit_notification(nlohmann::json details, bool async)
    {
        if (m_notify) {
            if (async) {
                boost::asio::post(*m_strand, [this, details] { emit_notification(details, false); });
            } else {
                session_impl::emit_notification(details, false);
            }
        }
    }

    std::shared_ptr<ga_session::nlocktime_t> ga_session::update_nlocktime_info(session_impl::locker_t& locker)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        if (!m_nlocktimes && !m_watch_only) {
            auto nlocktime_json = wamp_cast_json(m_wamp->call(locker, "txs.upcoming_nlocktime"));
            m_nlocktimes = std::make_shared<nlocktime_t>();
            for (auto& v : j_ref(nlocktime_json, "list")) {
                const auto vout = j_uint32ref(v, "output_n");
                auto k{ j_strref(v, "txhash") + ":" + std::to_string(vout) };
                m_nlocktimes->emplace(std::make_pair(std::move(k), std::move(v)));
            }
        }

        return m_nlocktimes;
    }

    void ga_session::set_fee_estimates(session_impl::locker_t& locker, const nlohmann::json& fee_estimates)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_LOG(debug) << "Set fee estimates " << fee_estimates.dump();

        // Convert server estimates into an array of NUM_FEE_ESTIMATES estimates
        // ordered by block, with the minimum allowable fee at position 0
        std::map<uint32_t, uint32_t> ordered_estimates;
        for (const auto& e : fee_estimates) {
            const bool is_min_fee = !e.is_object();
            const auto& fee_rate = is_min_fee ? e : e["feerate"];
            double btc_per_k;
            if (fee_rate.is_string()) {
                const std::string fee_rate_str = fee_rate;
                btc_per_k = boost::lexical_cast<double>(fee_rate_str);
            } else {
                btc_per_k = fee_rate;
            }
            if (btc_per_k > 0) {
                const long long satoshi_per_k = std::lround(btc_per_k * amount::coin_value);
                const long long uint32_t_max = std::numeric_limits<uint32_t>::max();
                if (satoshi_per_k < DEFAULT_MIN_FEE || satoshi_per_k > uint32_t_max) {
                    continue;
                }
                if (is_min_fee) {
                    m_min_fee_rate = satoshi_per_k;
                } else {
                    const uint32_t actual_block = e["blocks"];
                    if (actual_block > 0 && actual_block <= NUM_FEE_ESTIMATES - 1) {
                        ordered_estimates[actual_block] = static_cast<uint32_t>(satoshi_per_k);
                    }
                }
            }
        }

        std::vector<uint32_t> new_estimates(NUM_FEE_ESTIMATES);
        new_estimates[0] = m_min_fee_rate;
        size_t i = 1;
        for (const auto& e : ordered_estimates) {
            while (i <= e.first) {
                // Set the estimate not allowing it to be lower than the minimum rate
                new_estimates[i] = e.second < m_min_fee_rate ? m_min_fee_rate : e.second;
                ++i;
            }
        }

        if (i != 1u) {
            // We have updated estimates, use them
            while (i < NUM_FEE_ESTIMATES) {
                new_estimates[i] = new_estimates[i - 1];
                ++i;
            }

            std::swap(m_fee_estimates, new_estimates);
        }
        m_fee_estimates_ts = std::chrono::system_clock::now();
    }

    nlohmann::json ga_session::register_user(std::shared_ptr<signer> signer)
    {
        auto wallet_hash_ids = session_impl::register_user(signer);

        if (!signer->is_watch_only()) {
            // Get our gait path xpub and compute gait_path from it
            const auto gait_bip32_xpub = signer->get_bip32_xpub(signer::REGISTER_PATH);
            const auto gait_path = b2h(green_pubkeys::get_gait_path_bytes(xpub_hdkey(gait_bip32_xpub)));
            const bool supports_csv = signer->supports_arbitrary_scripts();
            const auto agent = get_user_agent(supports_csv, m_user_agent);
            const auto master_key = xpub_hdkey(signer->get_master_bip32_xpub());

            // Register the full session with the Green backend
            auto result = m_wamp->call(
                "login.register", b2h(master_key.get_public_key()), b2h(master_key.get_chain_code()), agent, gait_path);
            GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));
        }

        return wallet_hash_ids;
    }

    std::string ga_session::get_challenge(const pub_key_t& public_key)
    {
        const nlohmann::json fake_utxo{ { "address_type", "p2pkh" }, { "public_key", b2h(public_key) } };
        const auto address = get_address_from_utxo(*this, fake_utxo);
        const bool nlocktime_support = true;
        return wamp_cast(m_wamp->call("login.get_trezor_challenge", address, nlocktime_support));
    }

    void ga_session::upload_confidential_addresses(uint32_t subaccount, const std::vector<std::string>& addresses)
    {
        GDK_RUNTIME_ASSERT(!addresses.empty());

        auto result = m_wamp->call("txs.upload_authorized_assets_confidential_address", subaccount, addresses);
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));

        // Update required_ca
        locker_t locker(m_mutex);
        auto& required = m_subaccounts.at(subaccount)["required_ca"];
        const uint32_t remaining = required.get<uint32_t>();
        if (remaining) {
            required = addresses.size() > remaining ? 0u : remaining - addresses.size();
        }
    }

    nlohmann::json ga_session::on_post_login(locker_t& locker, nlohmann::json& login_data,
        const std::string& root_bip32_xpub, bool watch_only, bool is_relogin)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(m_signer);
        const bool is_main_net = m_net_params.is_main_net();

        nlohmann::json old_settings;
        if (is_relogin) {
            GDK_RUNTIME_ASSERT(m_watch_only == watch_only);
            old_settings = get_settings(locker);
        }

        const auto old_reset_status = get_twofactor_reset_status(locker, m_login_data);

        // Swap current login data with new; for relogin 'login_data' holds the old values
        m_login_data.swap(login_data);
        auto warnings = j_array(m_login_data, "warnings").value_or(nlohmann::json::array());

        // Parse gait_path into a derivation path.
        // Each pair of bytes is interpreted as a 16 bit child number.
        const auto gait_path_bytes = j_bytesref(m_login_data, "gait_path", m_gait_path.size() * 2);
        const auto gait_path = bytes_to_bip32_path(gait_path_bytes);
        if (is_relogin) {
            GDK_RUNTIME_ASSERT(std::equal(m_gait_path.begin(), m_gait_path.end(), gait_path.begin()));
        } else {
            std::copy(gait_path.begin(), gait_path.end(), m_gait_path.begin());
        }

        if (!m_green_pubkeys) {
            // Create our GA and recovery pubkey collections
            m_green_pubkeys = std::make_unique<green_pubkeys>(m_net_params, m_gait_path);
            m_recovery_pubkeys = std::make_unique<green_recovery_pubkeys>(m_net_params);
        }

        const uint32_t min_fee_rate = m_login_data["min_fee"];
        if (min_fee_rate != m_min_fee_rate) {
            m_min_fee_rate = min_fee_rate;
            m_fee_estimates.assign(NUM_FEE_ESTIMATES, m_min_fee_rate);
        }
        m_fiat_source = m_login_data["exchange"];
        m_fiat_currency = m_login_data["fiat_currency"];
        update_fiat_rate(locker, j_str_or_empty(m_login_data, "fiat_exchange"));

        if (watch_only) {
            // Check whether the user has locally overriden their pricing source
            const auto currency = m_cache->get_key_value_string("currency");
            if (!currency.empty()) {
                const auto exchange = m_cache->get_key_value_string("exchange");
                if (!exchange.empty() && (currency != m_fiat_currency || exchange != m_fiat_source)) {
                    GDK_LOG(info) << "Pricing source override " << currency << '/' << exchange;
                    constexpr bool is_login = true;
                    try {
                        set_pricing_source(locker, currency, exchange, is_login);
                    } catch (const user_error& e) {
                        // Add a warning that the pricing source is invalid,
                        // but only if we don't already have one from login.
                        auto&& match = [](const auto& warning) -> bool {
                            const auto prefix = "Your previous pricing source is no longer available"sv;
                            return boost::algorithm::starts_with(warning, prefix);
                        };
                        if (std::none_of(warnings.begin(), warnings.end(), match)) {
                            warnings.push_back(e.what());
                        }
                    }
                }
            }
        }

        m_subaccounts.clear();
        m_next_subaccount = 0;
        for (const auto& sa : m_login_data["subaccounts"]) {
            const auto subaccount = j_uint32ref(sa, "pointer");
            auto sa_type = j_str_or_empty(sa, "type");
            if (sa_type == "simple") {
                sa_type = "2of2";
            }
            std::optional<xpub_hdkey> recovery_key;

            if (sa_type == "2of3") {
                // 2of3 subaccount: Fetch and validate the recovery key
                const auto& pub_key = j_strref(sa, "2of3_backup_pubkey");
                const auto& chain_code = j_strref(sa, "2of3_backup_chaincode");
                const auto xpub = j_str_or_empty(sa, "2of3_backup_xpub");
                if (xpub.empty()) {
                    // Old style: only the pubkey/chaincode are given
                    recovery_key = xpub_hdkey(is_main_net, h2b(pub_key), h2b(chain_code));
                } else {
                    // New style: the full BIP32 xpub is given
                    recovery_key = xpub_hdkey(xpub);
                }
                const auto xpub_sig = j_bytes_or_empty(sa, "2of3_backup_xpub_sig");
                // TODO: fail if *any* 2of3 subaccount has missing or invalid
                //       signature of the corresponding backup/recovery key.
                if (!xpub_sig.empty() && !root_bip32_xpub.empty()) {
                    // Validate the recovery xpub signature to guard against a
                    // malicious backend substituting its own key
                    GDK_RUNTIME_ASSERT(!xpub.empty());
                    GDK_RUNTIME_ASSERT(b2h(recovery_key->get_public_key()) == pub_key);
                    GDK_RUNTIME_ASSERT(b2h(recovery_key->get_chain_code()) == chain_code);
                    const auto message = format_recovery_key_message(xpub, subaccount);
                    const auto message_hash = format_bitcoin_message_hash(ustring_span(message));
                    const auto login_key = xpub_hdkey(root_bip32_xpub).derive(signer::LOGIN_PATH);
                    const auto login_pubkey = login_key.get_public_key();
                    GDK_RUNTIME_ASSERT(ec_sig_verify(login_pubkey, message_hash, xpub_sig));
                }
            }

            insert_subaccount(locker, subaccount, sa_type, j_str_or_empty(sa, "name"),
                j_str_or_empty(sa, "receiving_id"), recovery_key, j_uint32_or_zero(sa, "required_ca"));

            if (subaccount > m_next_subaccount) {
                m_next_subaccount = subaccount;
            }
        }
        ++m_next_subaccount;

        // Insert the main account so callers can treat all accounts equally
        constexpr uint32_t required_ca = 0;
        insert_subaccount(locker, 0, "2of2", {}, j_str_or_empty(m_login_data, "receiving_id"), {}, required_ca);

        m_system_message_id = j_uint32_or_zero(m_login_data, "next_system_message_id");
        m_system_message_ack_id = 0;
        m_system_message_ack = std::string();
        m_watch_only = watch_only;

        const auto p = m_login_data.find("limits");
        update_spending_limits(locker, p == m_login_data.end() ? nlohmann::json::object() : *p);

        cleanup_appearance_settings(locker, m_login_data["appearance"]);
        if (watch_only) {
            auto overrides_str = m_cache->get_key_value_string("appearance");
            if (overrides_str.empty()) {
                overrides_str.push_back('{');
                overrides_str.push_back('}');
            }
            auto overrides = json_parse(overrides_str);
            m_login_data["appearance"].update(overrides);
        }

        m_earliest_block_time = m_login_data["earliest_key_creation_time"];

        if (have_writable_client_blob(locker) && m_blob->get_xpubs().empty()) {
            // A full session with no blob xpubs. This can happen if we are
            // upgrading/logging in from an earlier gdk version that didn't
            // automatically save them. Add them to the client blob now.
            GDK_LOG(info) << "adding missing client blob xpubs";
            const auto signer_xpubs = m_signer->get_cached_bip32_xpubs_json();
            GDK_RUNTIME_ASSERT(!signer_xpubs.empty());
            update_client_blob(locker, std::bind(&client_blob::set_xpubs, m_blob.get(), signer_xpubs));
        }

        // Make sure our list of valid csv blocks values matches the server,
        // and that our current csv blocks setting is valid.
        GDK_RUNTIME_ASSERT(m_net_params.are_matching_csv_buckets(j_arrayref(m_login_data, "csv_times")));
        const auto csv_blocks = j_uint32ref(m_login_data, "csv_blocks");
        GDK_RUNTIME_ASSERT(m_net_params.is_valid_csv_value(csv_blocks));
        m_csv_blocks = csv_blocks;
        if (!m_watch_only) {
            m_nlocktime = m_login_data["nlocktime_blocks"];
        }

        set_fee_estimates(locker, m_login_data["fee_estimates"]);

        // Notify the caller of their settings / 2fa reset status
        auto settings = get_settings(locker);
        const bool must_notify_settings = old_settings != settings;

        auto reset_status = get_twofactor_reset_status(locker, m_login_data);
        const bool must_notify_reset = !is_relogin || old_reset_status != reset_status;

        if (must_notify_settings || must_notify_reset) {
            unique_unlock unlocker(locker);
            if (must_notify_settings) {
                emit_notification({ { "event", "settings" }, { "settings", std::move(settings) } }, false);
            }
            if (must_notify_reset) {
                emit_notification(
                    { { "event", "twofactor_reset" }, { "twofactor_reset", std::move(reset_status) } }, false);
            }
        }

        for (const auto& sa : m_subaccounts) {
            nlohmann::json ntf = { { "pointer", sa.first }, { "event_type", "synced" } };
            emit_notification({ { "event", "subaccount" }, { "subaccount", std::move(ntf) } }, false);
        }

        subscribe_all(locker);

        // Notify the caller of their current block
        nlohmann::json block_json
            = { { "block_height", m_login_data.at("block_height") }, { "block_hash", m_login_data.at("block_hash") },
                  { "diverged_count", 0 }, { "previous_hash", m_login_data.at("prev_block_hash") } };

        nlohmann::json post_login_data = { { "wallet_hash_id", j_strref(m_login_data, "wallet_hash_id") },
            { "warnings", std::move(warnings) }, { "xpub_hash_id", j_strref(m_login_data, "xpub_hash_id") } };

        on_new_block(locker, block_json, is_relogin); // Unlocks 'locker'
        return post_login_data;
    }

    void ga_session::update_fiat_rate(session_impl::locker_t& locker, const std::string& rate_str)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        // TODO: Remove None check when backends are fixed
        if (rate_str.empty() || rate_str == "None") {
            m_fiat_rate.clear(); // No rate available
            return;
        }
        try {
            m_fiat_rate = amount::format_amount(rate_str, 8);
        } catch (const std::exception& e) {
            m_fiat_rate.clear();
            GDK_LOG(error) << "failed to update fiat rate from string '" << rate_str << "': " << e.what();
        }
    }

    void ga_session::update_spending_limits(session_impl::locker_t& locker, const nlohmann::json& limits)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        if (limits.is_null()) {
            m_limits_data = { { "is_fiat", false }, { "per_tx", 0 }, { "total", 0 } };
        } else {
            m_limits_data = limits;
        }
    }

    amount ga_session::get_min_fee_rate() const
    {
        locker_t locker(m_mutex);
        if (auto fee_rate = m_net_params.get_min_fee_rate(); fee_rate) {
            return amount(*fee_rate); // Overridden by the user for this session
        }
        return amount(m_min_fee_rate);
    }

    amount ga_session::get_default_fee_rate() const
    {
        locker_t locker(m_mutex);
        const auto block = j_uint32_or_zero(m_login_data["appearance"], "required_num_blocks");
        GDK_RUNTIME_ASSERT(block < NUM_FEE_ESTIMATES);
        return amount(m_fee_estimates[block]);
    }

    uint32_t ga_session::get_block_height() const
    {
        locker_t locker(m_mutex);
        return m_last_block_notification["block_height"];
    }

    nlohmann::json ga_session::get_spending_limits() const
    {
        locker_t locker(m_mutex);
        return get_spending_limits(locker);
    }

    nlohmann::json ga_session::get_spending_limits(locker_t& locker) const
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        amount::value_type total = get_limit_total(m_limits_data);

        const bool is_fiat = m_limits_data["is_fiat"];
        nlohmann::json converted_limits;
        if (is_fiat) {
            converted_limits = convert_fiat_cents(locker, total);
        } else {
            converted_limits = convert_amount(locker, { { "satoshi", total } });
        }
        converted_limits["is_fiat"] = is_fiat;
        return converted_limits;
    }

    bool ga_session::is_spending_limits_decrease(const nlohmann::json& details)
    {
        locker_t locker(m_mutex);

        const bool current_is_fiat = m_limits_data.at("is_fiat").get<bool>();
        const bool new_is_fiat = details.at("is_fiat").get<bool>();
        GDK_RUNTIME_ASSERT(new_is_fiat == details.contains("fiat"));

        if (current_is_fiat != new_is_fiat) {
            return false;
        }

        const auto current_total = j_amountref(m_limits_data, "total").value();
        if (new_is_fiat) {
            return amount::get_fiat_cents(details["fiat"]) <= current_total;
        }
        return j_amountref(convert_amount(locker, details)) <= current_total;
    }

    std::unique_ptr<session_impl::locker_t> ga_session::get_multi_call_locker(
        uint32_t category_flags, bool wait_for_lock)
    {
        std::unique_ptr<locker_t> locker{ new locker_t(m_mutex, std::defer_lock) };
        for (;;) {
            locker->lock();
            if (!(m_multi_call_category & category_flags)) {
                // No multi calls of this category are in progress.
                // Exit the loop with the locker locked
                break;
            }
            // Unlock and sleep to allow other threads to make progress
            locker->unlock();
            std::this_thread::sleep_for(1ms);
            if (!wait_for_lock) {
                // Exit the loop with the locker unlocked
                break;
            }
            // Continue around loop to try again
        }
        return locker;
    }

    void ga_session::on_new_transaction(const std::vector<uint32_t>& subaccounts, nlohmann::json details)
    {
        auto locker_p{ get_multi_call_locker(MC_TX_CACHE, false) };
        auto& locker = *locker_p;

        if (!locker.owns_lock()) {
            // Try again: 'post' this to allow the competing thread to proceed.
            boost::asio::post(*m_strand, [this, subaccounts, details] { on_new_transaction(subaccounts, details); });
            return;
        }

        no_std_exception_escape([&]() {
            using namespace std::chrono_literals;

            const auto now = std::chrono::system_clock::now();
            if (now < m_tx_last_notification || now - m_tx_last_notification > 60s) {
                // Time has adjusted, or more than 60s since last notification,
                // clear any cached notifications to deliver new ones even if
                // duplicates
                m_tx_notifications.clear();
            }

            m_tx_last_notification = now;

            const auto json_str = details.dump();
            if (std::find(m_tx_notifications.begin(), m_tx_notifications.end(), json_str) != m_tx_notifications.end()) {
                GDK_LOG(debug) << "eliding notification:" << json_str;
                return; // Elide duplicate notifications sent by the server
            }

            m_tx_notifications.emplace_back(json_str); // Record this notification as delivered

            if (m_tx_notifications.size() > 8u) {
                // Limit the size of notifications to elide. It is extremely unlikely
                // for unique transactions to be notified fast enough for this to occur,
                // but we strongly bound the vector size just in case.
                m_tx_notifications.erase(m_tx_notifications.begin()); // pop the oldest
            }

            const std::string txhash_hex = details.at("txhash");
            for (auto subaccount : subaccounts) {
                const auto p = m_subaccounts.find(subaccount);
                // TODO: Handle other logged in sessions creating subaccounts
                GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");

                // Update affected subaccounts as required
                GDK_LOG(debug) << "Tx sync(" << subaccount << "): new tx " << txhash_hex;
                m_cache->on_new_transaction(subaccount, txhash_hex);
                m_synced_subaccounts.erase(subaccount);
            }
            m_nlocktimes.reset();

            const std::string value_str = details.value("value", std::string{});
            if (!value_str.empty()) {
                int64_t satoshi = strtol(value_str.c_str(), nullptr, 10);
                details["satoshi"] = abs(satoshi);

                // TODO: We can't determine if this is a re-deposit based on the
                // information the server give us. We should fetch the tx details
                // in tx_list format, cache them, and notify that data instead.
                const bool is_deposit = satoshi >= 0;
                details["type"] = is_deposit ? "incoming" : "outgoing";
                j_erase(details, "value");
            } else {
                // TODO: figure out what type is for liquid
            }
            m_nlocktimes.reset();
            unique_unlock unlocker(locker);
            remove_cached_utxos(subaccounts);
            emit_notification({ { "event", "transaction" }, { "transaction", std::move(details) } }, false);
        });
    }

    void ga_session::purge_tx_notification(const std::string& txhash_hex)
    {
        auto&& filter = [&txhash_hex](const auto& ntf) -> bool { return ntf.find(txhash_hex) != std::string::npos; };
        locker_t locker(m_mutex);
        m_tx_notifications.erase(
            std::remove_if(m_tx_notifications.begin(), m_tx_notifications.end(), filter), m_tx_notifications.end());
    }

    void ga_session::on_new_block(nlohmann::json details, bool is_relogin)
    {
        auto locker_p{ get_multi_call_locker(MC_TX_CACHE, false) };
        auto& locker = *locker_p;

        if (!locker.owns_lock()) {
            // Try again: 'post' this to allow the competing thread to proceed.
            boost::asio::post(*m_strand, [this, details, is_relogin] { on_new_block(details, is_relogin); });
            return;
        }
        on_new_block(locker, details, is_relogin);
    }

    void ga_session::on_new_block(locker_t& locker, nlohmann::json details, bool is_relogin)
    {
        no_std_exception_escape([&]() {
            GDK_RUNTIME_ASSERT(locker.owns_lock());

            details["initial_timestamp"] = m_earliest_block_time;
            j_rename(details, "count", "block_height");
            j_erase(details, "diverged_count");

            auto& last = m_last_block_notification;
            bool treat_as_reorg = false;
            bool may_have_missed_tx = false;

            if (last.empty()) {
                // First login for this session.
                GDK_LOG(debug) << "Tx sync: first login";
                treat_as_reorg = true;
            } else if (is_relogin && last != details) {
                // Re-login and we have missed a block or a reorg while logged out
                GDK_LOG(debug) << "Tx sync: re-login, reorg or missed block";
                // If the current block isn't the next sequentially from our last,
                // treat this as a reorg since we can't differentiate reorgs from
                // multiple missed blocks.
                treat_as_reorg = details["previous_hash"] != last["block_hash"];
                may_have_missed_tx = true;
            } else if (details["previous_hash"] != last["block_hash"]) {
                // Missed a block or encountered a reorg while logged in
                GDK_LOG(debug) << "Tx sync: reorg or missed block";
                treat_as_reorg = true;
                may_have_missed_tx = true;
            } else {
                // Received the next sequential block while logged in,
                // or re-login and the block hasn't changed.
                // (happy path, continue below to delete mempool txs only)
                GDK_LOG(debug) << "Tx sync: new n+1 block";
            }

            GDK_LOG(debug) << "Tx sync: on new block" << (treat_as_reorg ? " (treat_as_reorg)" : "")
                           << (may_have_missed_tx ? " (may_have_missed_tx)" : "");

            std::vector<uint32_t> modified_subaccounts;
            uint32_t reorg_block = 0;
            if (treat_as_reorg) {
                // Calculate the block to reorg from
                const uint32_t last_seen_block_height = m_cache->get_latest_block();
                const uint32_t num_reorg_blocks = std::min(m_net_params.get_max_reorg_blocks(), last_seen_block_height);
                reorg_block = last_seen_block_height - num_reorg_blocks;
                GDK_LOG(debug) << "Tx sync: removing " << num_reorg_blocks << " blocks from cache tip "
                               << last_seen_block_height;
            }

            // Update the tx cache.
            for (const auto& sa : m_subaccounts) {
                bool removed_txs = false;
                if (treat_as_reorg) {
                    // Delete all txs newer than the block we may have reorged from
                    removed_txs |= m_cache->delete_block_txs(sa.first, reorg_block);
                    // Remove mempool txs in case any are older than the potential reorg
                    removed_txs |= m_cache->delete_mempool_txs(sa.first);
                } else {
                    // The backend does not notify us when an existing mempool tx
                    // becomes confirmed. Therefore delete from the oldest mempool
                    // tx forward in case one of them confirmed in this block.
                    removed_txs |= m_cache->delete_mempool_txs(sa.first);
                }
                if (removed_txs || may_have_missed_tx) {
                    // If we were synced, we are no longer synced if we removed
                    // any txs or may have missed a new mempool tx
                    GDK_LOG(debug) << "Tx sync(" << sa.first << "): marking unsynced";
                    m_synced_subaccounts.erase(sa.first);
                    modified_subaccounts.push_back(sa.first);
                }
            }

            last = details;
            m_cache->set_latest_block(last["block_height"]);
            m_cache->save_db();

            locker.unlock();
            if (treat_as_reorg) {
                // In the event of a re-org, nuke the entire UTXO cache
                remove_cached_utxos(std::vector<uint32_t>());
            } else if (!modified_subaccounts.empty()) {
                // Otherwise just nuke the subaccounts that may have changed
                remove_cached_utxos(modified_subaccounts);
            }
            emit_notification({ { "event", "block" }, { "block", std::move(details) } }, false);
        });
    }

    void ga_session::on_new_tickers(nlohmann::json details)
    {
        std::string fiat_source, fiat_currency, fiat_rate;
        {
            locker_t locker(m_mutex);

            no_std_exception_escape([&]() {
                const auto exchange_p = details.find(m_fiat_source);
                if (exchange_p != details.end()) {
                    const auto rate_p = exchange_p->find(m_fiat_currency);
                    if (rate_p != exchange_p->end()) {
                        fiat_source = m_fiat_source;
                        fiat_currency = m_fiat_currency;
                        fiat_rate = *rate_p;
                        update_fiat_rate(locker, fiat_rate);
                    }
                }
            });
        }
        if (!fiat_rate.empty()) {
            emit_notification(
                { { "event", "ticker" },
                    { "ticker",
                        { { "exchange", std::move(fiat_source) }, { "currency", std::move(fiat_currency) },
                            { "rate", std::move(fiat_rate) } } } },
                false);
        } else {
            GDK_LOG(warning) << "Ignoring irrelevant ticker update";
        }
    }

    void ga_session::derive_wallet_identifiers(
        locker_t& locker, nlohmann::json& login_data, const std::vector<unsigned char>& entropy, bool is_relogin)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        auto hash_ids
            = get_wallet_hash_ids(m_net_params, j_strref(login_data, "chain_code"), j_strref(login_data, "public_key"));
        for (const auto& key : { "wallet_hash_id"sv, "xpub_hash_id"sv }) {
            const auto& value = j_strref(hash_ids, key);
            if (is_relogin && !m_login_data.empty() && m_login_data.contains(key)) {
                // Computed ID must match the one we originally logged on with
                GDK_RUNTIME_ASSERT(j_strref(m_login_data, key) == value);
            }
            // Set the newly computed ID
            login_data[key] = value;
        }

        if (m_blobserver && m_signer->is_watch_only()) {
            // Blobserver watch only login.
            const auto public_key = set_blob_key_from_credentials(locker);
            set_local_encryption_keys(locker, public_key, m_signer);

            // Compute client blob id from the privately derived pubkey
            m_blob->compute_client_id(m_net_params.network(), public_key);
        } else {
            pub_key_t encryption_key;
            if (m_signer->is_watch_only()) {
                // Non-blobserver watch only login
                encryption_key = get_watch_only_cache_encryption_key(entropy, login_data.at("cache_password"));
            } else {
                // Full login, with or without a blobserver
                encryption_key = xpub_hdkey(m_signer->get_bip32_xpub(signer::CLIENT_SECRET_PATH)).get_public_key();
                if (m_blobserver) {
                    m_blob->compute_client_id(m_net_params.network(), encryption_key);
                }
            }
            set_local_encryption_keys(locker, encryption_key, m_signer);
            const std::string wo_blob_key_hex = j_str_or_empty(login_data, "wo_blob_key");
            if (!wo_blob_key_hex.empty()) {
                m_blob->set_key(decrypt_watch_only_data(entropy, wo_blob_key_hex));
            }
        }
    }

    nlohmann::json ga_session::authenticate(const std::string& sig_der_hex, std::shared_ptr<signer> signer)
    {
        locker_t locker(m_mutex);
        const bool is_relogin = set_signer(locker, signer);

        constexpr bool minimal = true; // Don't return balance/nlocktime info
        const std::string id; // Device id, no longer used
        const auto user_agent = get_user_agent(m_signer->supports_arbitrary_scripts(), m_user_agent);

        auto result = m_wamp->call(locker, "login.authenticate", sig_der_hex, minimal, "GA", id, user_agent);
        nlohmann::json login_data = wamp_cast_json(result);

        if (login_data.is_boolean()) {
            // Login failed
            locker.unlock();
            reset_all_session_data(false);
            throw login_error(res::id_login_failed);
        }
        if (is_relogin) {
            // Re-login. Discard all cached data which may be out of date
            reset_cached_session_data(locker);
        }

        // Compute wallet identifiers
        derive_wallet_identifiers(locker, login_data, {}, is_relogin);

        const bool reset_2fa_active = j_bool_or_false(login_data, "reset_2fa_active");
        const std::string server_hmac = login_data["client_blob_hmac"];
        bool is_blob_on_server = server_hmac != client_blob::get_zero_hmac();
        bool is_elsewhere = server_hmac == client_blob::get_one_hmac();
        if (is_elsewhere) {
            GDK_RUNTIME_ASSERT(is_blob_on_server); // Server must indicate we have a blob
            GDK_RUNTIME_ASSERT(m_blobserver); // We must have a blobserver connection
        } else if (is_blob_on_server) {
            // The Green backend is our blobserver; let the blob know that
            // it has a mandatory server.
            m_blob->set_server_is_mandatory();
        }

        if (!reset_2fa_active && !is_blob_on_server && m_blob->get_hmac().empty()) {
            // No client blob: create one, save it to the server and cache it,
            // but only when the wallet isn't locked for a two factor reset.
            // Subaccount names/xpubs
            auto signer_xpubs = m_signer->get_cached_bip32_xpubs_json();
            nlohmann::json subaccounts;
            for (const auto& sa : login_data["subaccounts"]) {
                nlohmann::json sa_data = { { "name", j_strref(sa, "name") } };
                subaccounts.emplace(std::to_string(j_uint32ref(sa, "pointer")), std::move(sa_data));
            }
            m_blob->update_subaccounts_data(subaccounts, signer_xpubs);
            // Tx memos
            nlohmann::json tx_memos = wamp_cast_json(m_wamp->call(locker, "txs.get_memos"));
            for (const auto& m : tx_memos["bip70"].items()) {
                m_blob->set_tx_memo(m.key(), m.value());
            }
            for (const auto& m : tx_memos["memos"].items()) {
                m_blob->set_tx_memo(m.key(), m.value());
            }

            m_blob->set_user_version(1); // Initial version

            // If this save fails due to a race, m_blob->get_hmac() will be empty below
            save_client_blob(locker, server_hmac);
            // Our blob was enabled, either by us or another login we raced with
            is_blob_on_server = true;

            // Delete all cached txs since they may have memos embedded
            for (const auto& sa : login_data["subaccounts"]) {
                m_cache->delete_transactions(sa["pointer"]);
            }
        }

        get_cached_local_client_blob(locker, server_hmac);

        if (is_blob_on_server) {
            // The server has a blob for this wallet. If we haven't got an
            // up to date copy of it loaded yet, do so.
            if (is_relogin && m_blob->get_hmac() != server_hmac) {
                // Re-login, and our blob has been updated on the server: re-load below
                m_blob->set_hmac({});
            }
            if (m_blob->get_hmac().empty()) {
                // No cached blob, or our cached blob is out of date:
                // Load the latest blob from the server and cache it
                load_client_blob(locker, true);
            }
            GDK_RUNTIME_ASSERT(!m_blob->get_hmac().empty()); // Must have a client blob from this point
        }

        if (!is_relogin) {
            m_cache->update_to_latest_minor_version();
        }
        m_cache->save_db();

        constexpr bool watch_only = false;
        return on_post_login(locker, login_data, m_signer->get_master_bip32_xpub(), watch_only, is_relogin);
    }

    void ga_session::subscribe_all(session_impl::locker_t& locker)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        const auto receiving_id = j_strref(m_login_data, "receiving_id");

        {
            unique_unlock unlocker(locker);
            const bool is_initial = true;
            m_wamp->subscribe(
                "com.greenaddress.tickers", [this](nlohmann::json event) { on_new_tickers(event); }, is_initial);
        }

        if (m_blobserver) {
            session_impl::subscribe_all(locker);
        } else {
            unique_unlock unlocker(locker);
            auto blob_feed = "com.greenaddress.cbs.wallet_" + receiving_id;
            m_wamp->subscribe(blob_feed, [this](nlohmann::json event) { on_client_blob_updated(std::move(event)); });
        }

        unique_unlock unlocker(locker);
        m_wamp->subscribe("com.greenaddress.txs.wallet_" + receiving_id, [this](nlohmann::json event) {
            if (!ignore_tx_notification(event)) {
                std::vector<uint32_t> subaccounts = cleanup_tx_notification(event);
                on_new_transaction(subaccounts, event);
            }
        });

        m_wamp->subscribe("com.greenaddress.blocks", [this](nlohmann::json event) { on_new_block(event, false); });
    }

    void ga_session::get_cached_local_client_blob(session_impl::locker_t& locker, const std::string& server_hmac)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        if (m_blob->get_hmac().empty()) {
            // Load our client blob from from the cache if we have one
            std::string db_hmac;
            if (m_watch_only) {
                db_hmac = m_cache->get_key_value_string("client_blob_hmac");
            }
            m_cache->get_key_value("client_blob", { [this, &db_hmac, &server_hmac](const auto& db_blob) {
                if (db_blob.has_value()) {
                    GDK_RUNTIME_ASSERT(m_watch_only || m_blob->has_hmac_key());
                    if (!m_watch_only) {
                        db_hmac = m_blob->compute_hmac(*db_blob);
                    }
                    if (db_hmac == server_hmac) {
                        // Cached blob is current, load it
                        m_blob->load(*db_blob, server_hmac);
                    }
                }
            } });
        }
    }

    nlohmann::json ga_session::load_client_blob_impl(session_impl::locker_t& locker)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        if (m_blobserver) {
            return session_impl::load_client_blob_impl(locker);
        }
        return wamp_cast_json(m_wamp->call(locker, "login.get_client_blob", 0));
    }

    nlohmann::json ga_session::save_client_blob_impl(
        locker_t& locker, const std::string& old_hmac, const std::string& blob_b64, const std::string& hmac)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        if (m_blobserver) {
            if (old_hmac == client_blob::get_zero_hmac()) {
                // First time saving a blob. Let the Green backend know we
                // are storing our blob elsewhere (via the one-HMAC sentinel value).
                const auto one_hmac = client_blob::get_one_hmac();
                auto ret
                    = wamp_cast_json(m_wamp->call(locker, "login.set_client_blob", one_hmac, 0, one_hmac, old_hmac));
            }
            return session_impl::save_client_blob_impl(locker, old_hmac, blob_b64, hmac);
        }
        return wamp_cast_json(m_wamp->call(locker, "login.set_client_blob", blob_b64, 0, hmac, old_hmac));
    }

    void ga_session::encache_local_client_blob(
        session_impl::locker_t& locker, std::string /*data_b64*/, byte_span_t data, const std::string& hmac)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        m_cache->upsert_key_value("client_blob", data);
        if (m_watch_only) {
            m_cache->upsert_key_value("client_blob_hmac", ustring_span(hmac));
        }
        m_cache->save_db();
    }

    void ga_session::set_local_encryption_keys(
        locker_t& locker, const pub_key_t& public_key, std::shared_ptr<signer> signer)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        if (!set_optional_variable(m_local_encryption_key, pbkdf2_hmac_sha512(public_key, signer::PASSWORD_SALT))) {
            // Already set, we are re-logging in with the same credentials
            return;
        }
        if (!signer->is_watch_only()) {
            m_blob->compute_keys(public_key);
        }
        m_cache->load_db(m_local_encryption_key.value(), signer);
        // Save the cache in case we carried forward data from a previous version
        m_cache->save_db(); // No-op if unchanged
        load_local_signer_xpubs(locker, signer);
    }

    void ga_session::save_cache()
    {
        locker_t locker(m_mutex);
        m_cache->save_db(); // No-op if unchanged
    }

    void ga_session::reset_cached_session_data(session_impl::locker_t& locker)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        swap_with_default(m_tx_notifications);
        m_nlocktimes.reset();
    }

    void ga_session::reset_all_session_data(bool in_dtor)
    {
        try {
            locker_t locker(m_mutex);
            m_signer.reset();
            remove_cached_utxos(std::vector<uint32_t>());
            swap_with_default(m_login_data);
            m_local_encryption_key.reset();
            m_blob->reset();
            swap_with_default(m_limits_data);
            swap_with_default(m_twofactor_config);
            swap_with_default(m_subaccounts);
            m_green_pubkeys.reset();
            m_user_pubkeys->clear();
            m_recovery_pubkeys.reset();
            const auto now = std::chrono::system_clock::now();
            m_fee_estimates_ts = now;
            swap_with_default(m_tx_notifications);
            m_tx_last_notification = now;
            m_nlocktimes.reset();
            if (!in_dtor) {
                m_cache = std::make_shared<cache>(m_net_params, m_cache->get_network_name());
                m_synced_subaccounts.clear();
            }
        } catch (const std::exception& ex) {
        }
    }

    nlohmann::json ga_session::get_settings() const
    {
        locker_t locker(m_mutex);
        return get_settings(locker);
    }

    nlohmann::json ga_session::get_settings(session_impl::locker_t& locker) const
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        nlohmann::json settings;

        remap_appearance_settings(locker, m_login_data["appearance"], settings, false);

        settings["pricing"]["currency"] = m_fiat_currency;
        settings["pricing"]["exchange"] = m_fiat_source;
        settings["csvtime"] = m_csv_blocks;
        if (!m_watch_only) {
            settings["nlocktime"] = m_nlocktime;
        }

        return settings;
    }

    void ga_session::change_settings(const nlohmann::json& settings)
    {
        locker_t locker(m_mutex);

        auto& appearance = m_login_data["appearance"];
        nlohmann::json new_appearance = appearance;
        remap_appearance_settings(locker, settings, new_appearance, true);
        cleanup_appearance_settings(locker, new_appearance);
        if (new_appearance != appearance) {
            if (m_watch_only) {
                // Locally cache and apply any values we have overridden
                auto overrides = get_wo_appearance_overrides(locker, new_appearance);
                m_cache->upsert_key_value("appearance", ustring_span(overrides.dump()));
                appearance.update(overrides);
            } else {
                m_wamp->call(locker, "login.set_appearance", mp_cast(new_appearance).get());
                appearance = std::move(new_appearance);
            }
        }

        if (auto p = settings.find("pricing"); p != settings.end()) {
            auto currency = j_str_or_empty(*p, "currency");
            if (currency.empty()) {
                currency = m_fiat_currency;
            }
            auto exchange = j_str_or_empty(*p, "exchange");
            if (exchange.empty()) {
                exchange = m_fiat_source;
            }
            if (currency != m_fiat_currency || exchange != m_fiat_source) {
                constexpr bool is_login = false;
                set_pricing_source(locker, currency, exchange, is_login);
            }
        }
    }

    // Re-map settings that are erroneously inside "appearance" to the top level
    // For historic reasons certain settings have been put under appearance and the server
    // still expects to find them there, but logically they don't belong there at all so
    // a more consistent scheme is presented via the gdk
    void ga_session::remap_appearance_settings(session_impl::locker_t& locker, const nlohmann::json& src_json,
        nlohmann::json& dst_json, bool from_settings) const
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        const auto remap_appearance_setting = [&src_json, &dst_json](auto src, auto dst) {
            const auto source_p = src_json.find(src);
            if (source_p != src_json.end()) {
                dst_json[dst] = *source_p;
            }
        };

        static const char* n = "notifications";
        static const char* n_ = "notifications_settings";
        remap_appearance_setting(from_settings ? n : n_, from_settings ? n_ : n);

        remap_appearance_setting("unit", "unit");
        remap_appearance_setting("pgp", "pgp");
        remap_appearance_setting("sound", "sound");
        remap_appearance_setting("altimeout", "altimeout");
        remap_appearance_setting("required_num_blocks", "required_num_blocks");
    }

    nlohmann::json ga_session::decrypt_with_pin_impl(const nlohmann::json& details, bool is_login)
    {
        try {
            // FIXME: clear password after use
            const auto& pin = details.at("pin");
            const auto& data = details.at("pin_data");
            const auto password = get_pin_password(pin, data.at("pin_identifier"));
            const std::string salt = data.at("salt");
            const auto key = pbkdf2_hmac_sha512_256(password, ustring_span(salt));

            // FIXME: clear data after use
            const auto plaintext = aes_cbc_decrypt_from_hex(key, data.at("encrypted_data"));
            return json_parse(plaintext);
        } catch (const autobahn::call_error& e) {
            GDK_LOG(warning) << "pin " << (is_login ? "login " : "") << "failed: " << e.what();
            if (is_login) {
                reset_all_session_data(false);
            }
            throw login_error(res::id_invalid_pin);
        }
    }

    nlohmann::json ga_session::credentials_from_pin_data(const nlohmann::json& pin_data)
    {
        constexpr bool is_login = true;
        return decrypt_with_pin_impl(pin_data, is_login);
    }

    // Idempotent
    nlohmann::json ga_session::authenticate_wo(session_impl::locker_t& locker, const std::string& username,
        const std::string& password, const std::string& user_agent, bool with_blob)
    {
        try {
            nlohmann::json args = { { "username", username }, { "password", password }, { "minimal", "true" } };
            auto ret
                = m_wamp->call(locker, "login.watch_only_v2", "custom", mp_cast(args).get(), user_agent, with_blob);
            return wamp_cast_json(ret);
        } catch (const autobahn::call_error& e) {
            const auto details = get_error_details(e);
            if (with_blob && boost::algorithm::starts_with(details.second, "User not found")) {
                return {};
            }
            throw;
        }
    }

    nlohmann::json ga_session::login_wo(std::shared_ptr<signer> signer)
    {
        locker_t locker(m_mutex);
        const bool is_relogin = set_signer(locker, signer);

        const bool is_liquid = m_net_params.is_liquid();
        const auto credentials = signer->get_credentials();
        const auto& username = j_strref(credentials, "username");
        const auto& password = j_strref(credentials, "password");
        const auto user_agent = get_user_agent(true, m_user_agent);

        // First, try using client blob
        const auto entropy = compute_watch_only_entropy(username, password);
        const auto u_p = get_green_wo_credentials(entropy);
        auto login_data = authenticate_wo(locker, u_p.first, u_p.second, user_agent, true);
        if (login_data.empty()) {
            // Client blob login failed: try a non-blob watch only login
            if (is_liquid) {
                // Liquid doesn't support non-blob watch only
                throw user_error(res::id_user_not_found_or_invalid);
            }
            login_data = authenticate_wo(locker, username, password, user_agent, false);
        }

        if (is_relogin) {
            // Re-login. Discard all cached data which may be out of date
            reset_cached_session_data(locker);
        }

        // Compute wallet identifiers
        derive_wallet_identifiers(locker, login_data, entropy, is_relogin);

        const std::string server_hmac = login_data["client_blob_hmac"];
        bool is_blob_on_server = server_hmac != client_blob::get_zero_hmac();
        if (m_blobserver) {
            is_blob_on_server = load_client_blob(locker, true);
        } else if (is_blob_on_server) {
            get_cached_local_client_blob(locker, server_hmac);
        }

        if (is_blob_on_server && m_blob->has_key()) {
            // The server has a blob for this wallet. If we haven't got an
            // up to date copy of it loaded yet, do so.
            if (is_relogin && m_blob->get_hmac() != server_hmac) {
                // Re-login, and our blob has been updated on the server: re-load below
                m_blob->set_hmac({});
            }
            if (m_blob->get_hmac().empty()) {
                // No cached blob, or our cached blob is out of date:
                // Load the latest blob from the server and cache it
                load_client_blob(locker, true);
            }
            GDK_RUNTIME_ASSERT(!m_blob->get_hmac().empty()); // Must have a client blob from this point
        }

        std::string root_bip32_xpub;
        if (!m_blob->get_hmac().empty()) {
            // Load any cached xpubs from the client blob.
            // If the client blob values differ from the cached values,
            // cache_bip32_xpub will throw.
            const auto blob_xpubs = m_blob->get_xpubs();
            for (auto& item : blob_xpubs.items()) {
                // Inverted: See encache_signer_xpubs()
                const auto path = item.value().get<std::vector<uint32_t>>();
                m_signer->cache_bip32_xpub(path, item.key());
            }
            GDK_RUNTIME_ASSERT(m_signer->has_master_bip32_xpub());
            root_bip32_xpub = m_signer->get_master_bip32_xpub();
        }

        if (is_liquid) {
            const auto [blinding_key_hex, denied] = get_cached_master_blinding_key();
            GDK_RUNTIME_ASSERT(!blinding_key_hex.empty() && !denied);
            m_signer->set_master_blinding_key(blinding_key_hex);
        }

        constexpr bool watch_only = true;
        auto ret = on_post_login(locker, login_data, root_bip32_xpub, watch_only, is_relogin);

        // Note that locker is unlocked at this point
        if (m_blob->has_key()) {
            const auto subaccount_pointers = get_subaccount_pointers();
            std::vector<std::string> bip32_xpubs;
            bip32_xpubs.reserve(subaccount_pointers.size());
            for (const auto& pointer : subaccount_pointers) {
                const auto path = m_user_pubkeys->get_path_to_subaccount(pointer);
                bip32_xpubs.emplace_back(signer->get_bip32_xpub(path));
            }
            register_subaccount_xpubs(subaccount_pointers, bip32_xpubs);
        }
        return ret;
    }

    void ga_session::register_subaccount_xpubs(
        const std::vector<uint32_t>& pointers, const std::vector<std::string>& bip32_xpubs)
    {
        locker_t locker(m_mutex);

        GDK_RUNTIME_ASSERT(!m_subaccounts.empty());
        GDK_RUNTIME_ASSERT(pointers.size() == m_subaccounts.size());
        GDK_RUNTIME_ASSERT(pointers.at(0) == 0); // Subaccount 0 must be first
        GDK_RUNTIME_ASSERT(bip32_xpubs.size() == m_subaccounts.size());

        for (size_t i = 0; i < pointers.size(); ++i) {
            m_user_pubkeys->add_subaccount(pointers.at(i), bip32_xpubs.at(i));
        }
    }

    nlohmann::json ga_session::get_fee_estimates()
    {
        const auto now = std::chrono::system_clock::now();

        locker_t locker(m_mutex);

        if (now < m_fee_estimates_ts || now - m_fee_estimates_ts > 120s) {
            // Time adjusted or more than 2 minutes old: Update
            constexpr bool return_min = true;
            auto fee_estimates = m_wamp->call(locker, "login.get_fee_estimates", return_min);
            set_fee_estimates(locker, wamp_cast_json(fee_estimates));
        }

        // TODO: augment with last_updated, user preference for display?
        return { { "fees", m_fee_estimates } };
    }

    std::string ga_session::get_system_message()
    {
        locker_t locker(m_mutex);

        if (!m_system_message_ack.empty()) {
            return m_system_message_ack; // Existing unacked message
        }

        if (m_watch_only || m_system_message_id == 0) {
            return std::string(); // Watch-only user, or no outstanding messages
        }

        // Get the next message to ack
        const auto system_message_id = m_system_message_id;
        nlohmann::json details = wamp_cast_json(m_wamp->call(locker, "login.get_system_message", system_message_id));

        // Note the inconsistency with login_data key "next_system_message_id":
        // We don't rename the key as we don't expose the details JSON to callers
        m_system_message_id = details["next_message_id"];
        m_system_message_ack_id = details["message_id"];
        m_system_message_ack = details["message"];
        return m_system_message_ack;
    }

    // Idempotent
    std::pair<std::string, std::vector<uint32_t>> ga_session::get_system_message_info(const std::string& message)
    {
        const auto message_hash_hex = b2h(sha256d(ustring_span(message)));
        const auto ls_uint32_hex = message_hash_hex.substr(message_hash_hex.length() - 8);
        const uint32_t ls_uint32 = std::stoul(ls_uint32_hex, nullptr, 16);
        const std::vector<uint32_t> path = { { 0x4741b11e, 6, unharden(ls_uint32) } };
        return std::make_pair(message_hash_hex, path);
    }

    void ga_session::ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex)
    {
        locker_t locker(m_mutex);
        ack_system_message(locker, message_hash_hex, sig_der_hex);
    }

    void ga_session::ack_system_message(
        session_impl::locker_t& locker, const std::string& message_hash_hex, const std::string& sig_der_hex)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        const auto ack_id = m_system_message_ack_id;
        auto result = m_wamp->call(locker, "login.ack_system_message", ack_id, message_hash_hex, sig_der_hex);
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));

        m_system_message_ack = std::string();
    }

    nlohmann::json ga_session::convert_amount(const nlohmann::json& amount_json) const
    {
        locker_t locker(m_mutex);
        return convert_amount(locker, amount_json);
    }

    nlohmann::json ga_session::convert_amount(locker_t& locker, const nlohmann::json& amount_json) const
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        return amount::convert(amount_json, m_fiat_currency, m_fiat_rate);
    }

    nlohmann::json ga_session::convert_fiat_cents(session_impl::locker_t& locker, amount::value_type fiat_cents) const
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        return amount::convert_fiat_cents(fiat_cents, m_fiat_currency);
    }

    nlohmann::json ga_session::set_wo_credentials(const nlohmann::json& credentials)
    {
        auto ret = session_impl::set_wo_credentials(credentials);
        std::pair<std::string, std::string> u_p{ j_strref(credentials, "username"), j_strref(credentials, "password") };
        std::string wo_blob_key_hex;

        if (!u_p.first.empty()) {
            // Enabling watch only login.
            // Derive the username/password to use, encrypt the client blob key for upload
            const auto entropy = compute_watch_only_entropy(u_p.first, u_p.second);
            u_p = get_green_wo_credentials(entropy);
            wo_blob_key_hex = encrypt_watch_only_data(entropy, m_blob->get_key());
        }
        bool ok = wamp_cast<bool>(m_wamp->call("addressbook.sync_custom", u_p.first, u_p.second, wo_blob_key_hex));
        if (!ok) {
            throw user_error("failed to create watch only session");
        }
        return ret;
    }

    std::string ga_session::get_watch_only_username()
    {
        auto username = session_impl::get_watch_only_username();
        if (username.empty()) {
            // If the username is blank, attempt to fetch from the
            // server, we have a non-client blob watch only (or no
            // watch only set up).
            const auto result = wamp_cast_json(m_wamp->call("addressbook.get_sync_status"));
            username = j_str_or_empty(result, "username");
        }
        return username;
    }

    // Idempotent
    bool ga_session::remove_account(const nlohmann::json& twofactor_data)
    {
        return wamp_cast<bool>(m_wamp->call("login.remove_account", mp_cast(twofactor_data).get()));
    }

    nlohmann::json ga_session::get_subaccounts_impl(session_impl::locker_t& locker)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        nlohmann::json::array_t subaccounts;
        subaccounts.reserve(m_subaccounts.size());
        for (const auto& sa : m_subaccounts) {
            subaccounts.emplace_back(sa.second);
        }
        return nlohmann::json(std::move(subaccounts));
    }

    std::vector<uint32_t> ga_session::get_subaccount_pointers()
    {
        std::vector<uint32_t> ret;
        locker_t locker(m_mutex);
        ret.reserve(m_subaccounts.size());
        for (const auto& sa : m_subaccounts) {
            ret.emplace_back(sa.second.at("pointer"));
        }
        return ret;
    }

    void ga_session::update_subaccount(uint32_t subaccount, const nlohmann::json& details)
    {
        {
            locker_t locker(m_mutex);

            const auto p = m_subaccounts.find(subaccount);
            GDK_USER_ASSERT(p != m_subaccounts.end(), "Unknown subaccount"); // FIXME: res::
            if (!have_writable_client_blob(locker)) {
                throw user_error(res::id_2fa_reset_in_progress);
            }
        }
        session_impl::update_subaccount(subaccount, details);
    }

    nlohmann::json ga_session::insert_subaccount(session_impl::locker_t& locker, uint32_t subaccount,
        const std::string& sa_type, const std::string& name, const std::string& receiving_id,
        const std::optional<xpub_hdkey>& recovery_key, uint32_t required_ca)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(m_signer != nullptr);

        GDK_RUNTIME_ASSERT(m_subaccounts.find(subaccount) == m_subaccounts.end());
        GDK_RUNTIME_ASSERT(sa_type == "2of2" || sa_type == "2of3" || sa_type == "2of2_no_recovery");

        std::string recovery_xpub = recovery_key ? recovery_key->to_base58() : std::string();
        nlohmann::json sa = {
            { "name", name },
            { "pointer", subaccount },
            { "receiving_id", receiving_id },
            { "type", sa_type },
            { "recovery_xpub", recovery_xpub },
            { "required_ca", required_ca },
        };
        m_subaccounts[subaccount] = sa;

        if (subaccount && m_recovery_pubkeys && !recovery_xpub.empty()) {
            // Add recovery pubkeys for the subaccount
            m_recovery_pubkeys->add_subaccount(subaccount, recovery_xpub);
        }

        return sa;
    }

    uint32_t ga_session::get_next_subaccount(const std::string& sa_type)
    {
        if ((sa_type != "2of2" && sa_type != "2of3" && sa_type != "2of2_no_recovery")
            || (sa_type == "2of2_no_recovery" && !m_net_params.is_liquid())) {
            throw_user_error("Invalid account type");
        }
        locker_t locker(m_mutex);
        const uint32_t subaccount = m_next_subaccount;
        ++m_next_subaccount;
        return subaccount;
    }

    nlohmann::json ga_session::create_subaccount(nlohmann::json details, uint32_t subaccount, const std::string& xpub)
    {
        const auto name = j_strref(details, "name");
        const auto sa_type = j_str_or_empty(details, "type");
        std::string recovery_bip32_xpub = j_str_or_empty(details, "recovery_xpub");

        std::vector<std::string> xpubs{ { xpub } };
        std::vector<std::string> sigs{ { std::string() } };

        GDK_RUNTIME_ASSERT(subaccount < 16384u); // Disallow more than 16k subaccounts

        std::optional<xpub_hdkey> recovery_key;
        if (sa_type == "2of3") {
            xpubs.emplace_back(recovery_bip32_xpub);
            sigs.emplace_back(j_strref(details, "recovery_key_sig"));
            recovery_key = xpub_hdkey(recovery_bip32_xpub);
        }

        const auto recv_id
            = wamp_cast(m_wamp->call("txs.create_subaccount_v2", subaccount, std::string(), sa_type, xpubs, sigs));

        locker_t locker(m_mutex);
        m_user_pubkeys->add_subaccount(subaccount, xpub);
        constexpr uint32_t required_ca = 0;
        auto subaccount_details
            = insert_subaccount(locker, subaccount, sa_type, name, recv_id, recovery_key, required_ca);
        subaccount_details["hidden"] = false;
        subaccount_details["user_path"] = m_user_pubkeys->get_path_to_subaccount(subaccount);

        if (have_writable_client_blob(locker)) {
            const auto signer_xpubs = m_signer->get_cached_bip32_xpubs_json();
            nlohmann::json sa_data = { { "name", name }, { "hidden", false } };
            nlohmann::json subaccounts = { { std::to_string(subaccount), std::move(sa_data) } };
            update_client_blob(
                locker, std::bind(&client_blob::update_subaccounts_data, m_blob.get(), subaccounts, signer_xpubs));
        }
        nlohmann::json ntf
            = { { "event", "subaccount" }, { "subaccount", nlohmann::json::object({ { "pointer", subaccount } }) } };
        for (const auto event_type : { "new", "synced" }) {
            ntf["subaccount"]["event_type"] = event_type;
            emit_notification(ntf, false);
        }
        return subaccount_details;
    }

    std::pair<std::string, bool> ga_session::get_cached_master_blinding_key()
    {
        const bool denied = m_blob->is_master_blinding_key_denied();
        const auto blinding_key_hex = denied ? std::string() : m_blob->get_master_blinding_key();
        return std::make_pair(blinding_key_hex, denied);
    }

    void ga_session::set_cached_master_blinding_key_impl(
        session_impl::locker_t& locker, const std::string& master_blinding_key_hex)
    {
        session_impl::set_cached_master_blinding_key_impl(locker, master_blinding_key_hex);
        if (have_writable_client_blob(locker)) {
            // Note: this update is a no-op if the key is already cached
            update_client_blob(
                locker, std::bind(&client_blob::set_master_blinding_key, m_blob.get(), master_blinding_key_hex));
        }
    }

    void ga_session::encache_signer_xpubs(std::shared_ptr<signer> signer)
    {
        locker_t locker(m_mutex);
        const auto signer_xpubs = signer->get_cached_bip32_xpubs_json();
        m_cache->upsert_key_value("xpubs", nlohmann::json::to_msgpack(signer_xpubs));
        m_cache->save_db();
    }

    void ga_session::load_local_signer_xpubs(session_impl::locker_t& locker, std::shared_ptr<signer> signer)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(signer);
        m_cache->get_key_value("xpubs", { [this, &locker, &signer](const auto& db_blob) {
            if (db_blob.has_value()) {
                try {
                    auto xpubs = nlohmann::json::from_msgpack(db_blob.value().begin(), db_blob.value().end());
                    load_signer_xpubs(locker, xpubs, signer);
                } catch (const std::exception& e) {
                    GDK_LOG(warning) << "Error reading xpubs: " << e.what();
                }
            }
        } });
    }

    void ga_session::change_settings_limits(const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        auto result
            = m_wamp->call("login.change_settings", "tx_limits", mp_cast(details).get(), mp_cast(twofactor_data).get());
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));
        locker_t locker(m_mutex);
        update_spending_limits(locker, details);
    }

    void ga_session::set_pricing_source(
        session_impl::locker_t& locker, const std::string& currency, const std::string& exchange, bool is_login)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        std::optional<std::string> fiat_rate;
        bool ok = false;

        try {
            fiat_rate = wamp_cast_nil(m_wamp->call(locker, "login.set_pricing_source_v2", currency, exchange));
            ok = true;
        } catch (const std::exception& e) {
        }

        if (!ok) {
            // The call to set the pricing source failed.
            std::string error = "Pricing source unavailable";
            if (is_login) {
                GDK_RUNTIME_ASSERT(m_watch_only);
                // Watch-only session setting its override on login.
                // The override is no longer valid, so remove it, leaving the
                // full sessions pricing source in place.
                m_cache->clear_key_value("currency");
                m_cache->clear_key_value("exchange");
                m_cache->save_db();
                error = "Your previous pricing source is no longer available and has been updated to ";
                error += m_fiat_source;
            }
            throw user_error(error);
        }
        m_fiat_source = exchange;
        m_fiat_currency = currency;
        update_fiat_rate(locker, fiat_rate.value_or(std::string()));
        if (m_watch_only) {
            // Watch-only session setting a new pricing source: cache it.
            m_cache->upsert_key_value("currency", ustring_span(currency));
            m_cache->upsert_key_value("exchange", ustring_span(exchange));
            m_cache->save_db();
        }
    }

    static void remove_utxo_proofs(nlohmann::json& utxo, bool mark_unconfidential)
    {
        if (mark_unconfidential) {
            utxo["is_confidential"] = false;
            utxo["is_blinded"] = true;
            j_erase(utxo, "error");
        }
        j_erase(utxo, "range_proof");
        j_erase(utxo, "surj_proof");
    }

    bool ga_session::unblind_utxo(session_impl::locker_t& locker, nlohmann::json& utxo, const std::string& for_txhash,
        unique_pubkeys_and_scripts_t& missing)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        amount::value_type value;

        if (boost::conversion::try_lexical_convert(j_str_or_empty(utxo, "value"), value)) {
            utxo["satoshi"] = value;
            utxo["assetblinder"] = ZEROS;
            utxo["amountblinder"] = ZEROS;
            const auto asset_tag = j_bytesref(utxo, "asset_tag");
            GDK_RUNTIME_ASSERT(asset_tag.at(0) == 0x1);
            utxo["asset_id"] = b2h_rev(gsl::make_span(asset_tag).subspan(1));
            utxo["is_blinded"] = false;
            return false; // Cache not updated
        }

        // 1) get_unspent_outputs UTXOs have txhash/pt_idx and implicitly
        // is_output is true but it is not present.
        // 2) get_transaction tx outputs have for_txhash(passed in)/pt_idx
        // and is_output is true.
        // 3) get_transaction tx inputs have prevtxhash/previdx and is_output
        // is false.
        // Ensure we use the correct tx/vout pair to unblind and encache.
        std::string txhash;
        uint32_t pt_idx = utxo.at("pt_idx");
        if (utxo.contains("prevtxhash")) {
            txhash = utxo.at("prevtxhash");
            pt_idx = utxo.at("previdx");
        } else if (utxo.contains("txhash")) {
            txhash = utxo.at("txhash");
        } else if (utxo.value("is_output", true)) {
            txhash = for_txhash;
        }

        const auto script = j_bytesref(utxo, "script");
        const bool has_address = !j_str_is_empty(utxo, "address");

        if (!txhash.empty()) {
            const auto cached = m_cache->get_liquid_output(h2b(txhash), pt_idx);
            if (!cached.empty()) {
                utxo.update(cached.begin(), cached.end());
                constexpr bool mark_unconfidential = true;
                remove_utxo_proofs(utxo, mark_unconfidential);
                if (has_address) {
                    // We should now be able to make the address confidential
                    const auto blinding_pubkey = m_cache->get_liquid_blinding_pubkey(script);
                    GDK_RUNTIME_ASSERT(!blinding_pubkey.empty());
                    confidentialize_address(m_net_params, utxo, b2h(blinding_pubkey));
                }

                return false; // Cache not updated
            }
        }
        const auto rangeproof = j_bytesref(utxo, "range_proof");
        const auto commitment = j_bytesref(utxo, "commitment");
        const auto nonce_commitment = j_bytesref(utxo, "nonce_commitment");
        const auto asset_tag = j_bytesref(utxo, "asset_tag");

        GDK_RUNTIME_ASSERT(asset_tag[0] == 0xa || asset_tag[0] == 0xb);

        auto nonce = m_cache->get_liquid_blinding_nonce(nonce_commitment, script);
        if (nonce.empty()) {
            utxo["error"] = "missing blinding nonce";
            missing.emplace(std::make_pair(nonce_commitment, script));
            return false; // Cache not updated
        }

        // Make sure we can unblind the asset/amount details
        unblind_t unblinded;
        try {
            unblinded = asset_unblind_with_nonce(nonce, rangeproof, commitment, script, asset_tag);
        } catch (const std::exception&) {
            nonce = get_alternate_blinding_nonce(locker, utxo, nonce_commitment);
            if (!nonce.empty()) {
                // Try the alternate nonce
                try {
                    unblinded = asset_unblind_with_nonce(nonce, rangeproof, commitment, script, asset_tag);
                } catch (const std::exception&) {
                    nonce.clear();
                }
            }
            if (nonce.empty()) {
                utxo["error"] = "failed to unblind utxo";
                return false; // Cache not updated
            }
        }

        // Unblind the asset/amount details
        utxo["satoshi"] = std::get<3>(unblinded);
        // Return in display order
        utxo["assetblinder"] = b2h_rev(std::get<2>(unblinded));
        utxo["amountblinder"] = b2h_rev(std::get<1>(unblinded));
        utxo["asset_id"] = b2h_rev(std::get<0>(unblinded));
        constexpr bool mark_unconfidential = true;
        remove_utxo_proofs(utxo, mark_unconfidential);

        bool updated_blinding_cache = false;
        if (!txhash.empty()) {
            m_cache->insert_liquid_output(h2b(txhash), pt_idx, utxo);
            updated_blinding_cache = true;
        }

        if (has_address) {
            // We should now be able to make the address confidential
            const auto blinding_pubkey = m_cache->get_liquid_blinding_pubkey(script);
            GDK_RUNTIME_ASSERT(!blinding_pubkey.empty());
            confidentialize_address(m_net_params, utxo, b2h(blinding_pubkey));
        }

        return updated_blinding_cache;
    }

    std::vector<unsigned char> ga_session::get_alternate_blinding_nonce(
        session_impl::locker_t& locker, nlohmann::json& utxo, const std::vector<unsigned char>& nonce_commitment)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        if (!m_signer->has_master_blinding_key()) {
            return {}; // Only available through master blinding key
        }

        const auto p = m_subaccounts.find(j_uint32ref(utxo, "subaccount"));
        GDK_USER_ASSERT(p != m_subaccounts.end(), "Unknown subaccount"); // FIXME: res::
        if (j_strref(p->second, "type") != "2of2_no_recovery" || j_uint32ref(p->second, "pointer") > 20u) {
            return {}; // Only used for first 20 2of2_no_recovery addrs
        }

        auto alt_utxo = utxo;
        alt_utxo["pointer"] = 1u; // Alt key is derived from the initial addr
        alt_utxo["address_type"] = "p2wsh"; // Only 2of2_no_recovery supported
        const auto alt_script = output_script_from_utxo(locker, alt_utxo);
        const auto p2sh = scriptpubkey_p2sh_p2wsh_from_bytes(alt_script);
        const auto alt_key = m_signer->get_blinding_key_from_script(p2sh);
        return make_vector(sha256(ecdh(nonce_commitment, alt_key)));
    }

    bool ga_session::cleanup_utxos(session_impl::locker_t& locker, nlohmann::json& utxos, const std::string& for_txhash,
        unique_pubkeys_and_scripts_t& missing)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        const bool is_liquid = m_net_params.is_liquid();
        bool updated_blinding_cache = false;

        // Standardise key names and data types of server provided UTXOs.
        // For Liquid, unblind it if possible. If not, record the pubkey
        // and script needed to generate its blinding nonce in 'missing'.
        for (auto& utxo : utxos) {
            auto address_type_p = utxo.find("address_type");
            if (is_liquid && utxo.value("error", std::string()) == "missing blinding nonce") {
                // UTXO was previously processed but could not be unblinded: try again
                updated_blinding_cache |= unblind_utxo(locker, utxo, for_txhash, missing);
                if (!utxo.contains("error")) {
                    j_erase(utxo, "value"); // Only remove value if we unblinded it
                }
            } else if (address_type_p == utxo.end()) {
                // This UTXO has not been processed yet
                GDK_RUNTIME_ASSERT(j_str_is_empty(utxo, "private_key"));

                // Address type is non-blank for spendable UTXOs
                auto addr_type = address_type_from_script_type(j_uint32ref(utxo, "script_type"));
                if (is_liquid) {
                    if (j_bool(utxo, "is_relevant").value_or(true)) {
                        updated_blinding_cache |= unblind_utxo(locker, utxo, for_txhash, missing);
                    } else {
                        constexpr bool mark_unconfidential = false;
                        remove_utxo_proofs(utxo, mark_unconfidential);
                    }
                } else {
                    // Use lexical conversion as the server returns value as a string
                    amount::value_type value;
                    using boost::conversion::try_lexical_convert;
                    GDK_RUNTIME_ASSERT(try_lexical_convert(j_str_or_empty(utxo, "value"), value));
                    utxo["satoshi"] = value;
                }
                if (!utxo.contains("error")) {
                    j_erase(utxo, "value"); // Only remove value if we unblinded it
                }
                json_add_if_missing(utxo, "subtype", 0u);
                json_add_if_missing(utxo, "is_internal", false);
                utxo["address_type"] = std::move(addr_type);
                j_erase(utxo, "script_type");
            }
        }

        return updated_blinding_cache;
    }

    nlohmann::json ga_session::sync_transactions(uint32_t subaccount, unique_pubkeys_and_scripts_t& missing)
    {
        auto locker_p{ get_multi_call_locker(MC_TX_CACHE, true) };
        auto& locker = *locker_p;

        // Mark for other threads that a tx cache affecting call is running
        m_multi_call_category |= MC_TX_CACHE;
        const auto cleanup = gsl::finally([this]() { m_multi_call_category &= ~MC_TX_CACHE; });

        const auto timestamp = m_cache->get_latest_transaction_timestamp(subaccount);
        GDK_LOG(debug) << "Tx sync(" << subaccount << "): latest timestamp = " << timestamp;

        if (m_synced_subaccounts.count(subaccount)) {
            // We know our cache is up to date, avoid going to the server
            GDK_LOG(debug) << "Tx sync(" << subaccount << "): already synced";
            return { { "list", nlohmann::json::array() }, { "more", false }, { "sync_ts", timestamp } };
        }

        // Get a page of txs from the server if any are newer than our last cached one
        auto result = m_wamp->call(locker, "txs.get_list_v3", subaccount, timestamp);
        nlohmann::json ret = wamp_cast_json(result);
        GDK_LOG(debug) << "Tx sync(" << subaccount << "): server returned " << ret["list"].size()
                       << " txs, more = " << ret["more"];

        auto& txs = ret["list"];
        // TODO: Return rejected txs to the caller
        auto&& filter = [](const auto& tx) -> bool { return tx.contains("rejected") || tx.contains("replaced"); };
        txs.erase(std::remove_if(txs.begin(), txs.end(), filter), txs.end());

        for (auto& tx : txs) {
            // Compute tx vsize from weight
            const auto vsize = Tx::vsize_from_weight(j_uint32ref(tx, "weight"));
            j_rename(tx, "weight", "transaction_weight");
            tx["transaction_vsize"] = vsize;

            // fee_rate is in satoshi/kb, with the best integer accuracy we have
            tx["fee_rate"] = j_amountref(tx, "fee").value() * 1000 / vsize;

            // Clean up and categorize the endpoints. For liquid, this populates
            // 'missing' if any UTXOs require blinding nonces from the signer to unblind.
            cleanup_utxos(locker, j_ref(tx, "eps"), j_strref(tx, "txhash"), missing);
        }

        // Store the timestamp that we started fetching from in order to detect
        // whether the cache was invalidated when we save it.
        ret["sync_ts"] = timestamp;
        return ret;
    }

    void ga_session::store_transactions(uint32_t subaccount, nlohmann::json& txs)
    {
        const bool is_liquid = m_net_params.is_liquid();
        unique_pubkeys_and_scripts_t missing;

        auto locker_p{ get_multi_call_locker(MC_TX_CACHE, true) };
        auto& locker = *locker_p;

        // Mark for other threads that a tx cache affecting call is running
        m_multi_call_category |= MC_TX_CACHE;
        const auto cleanup = gsl::finally([this]() { m_multi_call_category &= ~MC_TX_CACHE; });

        const auto timestamp = m_cache->get_latest_transaction_timestamp(subaccount);
        const bool sync_disrupted = txs["sync_ts"] != timestamp;
        if (sync_disrupted) {
            // Cached tx data was changed while syncing, e.g. a block or tx arrived.
            // Only cache any blinding data/liquid outputs, not the returned txs.
            GDK_LOG(debug) << "Tx sync(" << subaccount << ") disrupted: " << txs["sync_ts"] << " != " << timestamp;
            txs["more"] = true; // Ensure the caller iterates to re-sync
            // Mark the subaccount as not yet up to date
            m_synced_subaccounts.erase(subaccount);

            if (!is_liquid) {
                // Non-liquid sessions have no blinding data to cache.
                // Exit early to allow the caller to continue syncing.
                return;
            }
        }

        for (auto& tx_details : txs["list"]) {
            const std::string txhash = tx_details["txhash"];
            const uint32_t tx_block_height = tx_details["block_height"];

            std::map<std::string, int64_t> totals; /* Note: signed */
            std::map<uint32_t, nlohmann::json> in_map, out_map;
            std::set<std::string> unique_asset_ids;

            if (is_liquid) {
                // Ublind, clean up and categorize the endpoints
                cleanup_utxos(locker, tx_details["eps"], txhash, missing);
            }

            for (auto& ep : tx_details["eps"]) {
                const bool is_tx_output = ep.at("is_output");
                const bool is_relevant = ep.at("is_relevant");

                if (is_relevant && !ep.contains("error")) {
                    const auto asset_id = j_assetref(is_liquid, ep);
                    unique_asset_ids.emplace(asset_id);

                    // Compute the effect of the input/output on the wallets balance
                    // TODO: Figure out what redeemable value for social payments is about
                    const auto satoshi = j_amountref(ep);
                    if (is_tx_output) {
                        totals[asset_id] += satoshi.signed_value();
                        // TODO: validate the server provided address,
                        // or always derive it (and remove from the Green backend)
                        GDK_RUNTIME_ASSERT(!j_str_is_empty(ep, "address"));
                    } else {
                        totals[asset_id] -= satoshi.signed_value();
                    }
                }

                // Note pt_idx on endpoints is the index within the tx, not the previous tx!
                const uint32_t pt_idx = ep["pt_idx"];
                auto& m = is_tx_output ? out_map : in_map;
                GDK_RUNTIME_ASSERT(m.emplace(pt_idx, std::move(ep)).second);
            }

            // Store the endpoints as inputs/outputs in tx index order
            nlohmann::json::array_t inputs, outputs;
            inputs.reserve(in_map.size());
            for (auto& it : in_map) {
                inputs.emplace_back(std::move(it.second));
            }
            tx_details["inputs"] = std::move(inputs);

            outputs.reserve(out_map.size());
            for (auto& it : out_map) {
                outputs.emplace_back(std::move(it.second));
            }
            tx_details["outputs"] = std::move(outputs);
            j_erase(tx_details, "eps");

            if (!is_liquid) {
                GDK_RUNTIME_ASSERT(unique_asset_ids.size() == 1 && *unique_asset_ids.begin() == "btc");
            }

            // TODO: improve the detection of tx type.
            bool seen_positive = false, seen_negative = false;

            for (const auto& asset_id : unique_asset_ids) {
                const auto& total = totals[asset_id];
                seen_positive |= total > 0;
                seen_negative |= total < 0;
                tx_details["satoshi"][asset_id] = total;
            }

            const bool is_confirmed = tx_block_height != 0;
            bool can_rbf = false, can_cpfp = false;

            std::string tx_type;
            if (is_liquid && unique_asset_ids.empty()) {
                // Failed to unblind all relevant inputs and outputs. This
                // might be a spam transaction.
                tx_type = "not unblindable";
            } else if (seen_positive && seen_negative) {
                tx_type = "mixed";
                // FIXME: Allow RBF/CPFP of mixed txs (e.g. swaps)
            } else if (seen_positive) {
                tx_type = "incoming";
                for (auto& ep : tx_details["inputs"]) {
                    if (!j_bool_or_false(ep, "is_relevant")) {
                        std::string addressee = j_str_or_empty(ep, "social_source");
                        if (!addressee.empty()) {
                            ep["addressee"] = std::move(addressee);
                        }
                        j_erase(ep, "social_source");
                    }
                }
                can_cpfp = !is_confirmed;
            } else {
                tx_type = "redeposit";
                for (auto& ep : tx_details["outputs"]) {
                    if (is_liquid && j_str_is_empty(ep, "script")) {
                        continue; // Ignore Liquid fee output
                    }
                    if (!j_bool_or_false(ep, "is_relevant")) {
                        const auto social_destination_p = ep.find("social_destination");
                        if (social_destination_p != ep.end()) {
                            std::string addressee;
                            if (social_destination_p->is_object()) {
                                addressee = (*social_destination_p)["name"];
                            } else {
                                addressee = *social_destination_p;
                            }
                            if (!addressee.empty()) {
                                ep["addressee"] = std::move(addressee);
                            }
                            j_erase(ep, "social_destination");
                        }
                        tx_type = "outgoing"; // We have at least one non-wallet output
                    }
                }
                can_rbf = !is_confirmed && j_bool_or_false(tx_details, "rbf_optin");
            }
            tx_details["type"] = std::move(tx_type);
            tx_details["can_rbf"] = can_rbf;
            tx_details["can_cpfp"] = can_cpfp;

            if (!sync_disrupted) {
                // Insert the tx into the DB cache now that it is cleaned up/unblinded
                const uint64_t tx_timestamp = tx_details.at("created_at_ts");
                GDK_LOG(debug) << "Tx sync(" << subaccount << ") inserting " << txhash << ":" << tx_timestamp;
                m_cache->insert_transaction(subaccount, tx_timestamp, txhash, tx_details);
                txs["sync_ts"] = tx_timestamp;
            }
        }
        if (!sync_disrupted && !txs["more"]) {
            // We have synced all available transactions, mark the subaccount up to date
            m_synced_subaccounts.insert(subaccount);
        }
        // Save the cache to store any updated cached data
        m_cache->save_db(); // No-op if unchanged
    }

    void ga_session::postprocess_transactions(nlohmann::json& tx_list)
    {
        // Set tx memos in the returned txs from the blob cache
        session_impl::postprocess_transactions(tx_list);

        // TODO: Remove SPV verification status in a later release
        for (auto& tx_details : tx_list) {
            tx_details["spv_verified"] = "disabled";
        }
    }

    nlohmann::json ga_session::get_transactions(const nlohmann::json& details)
    {
        const uint32_t subaccount = details.at("subaccount");
        const uint32_t first = details.at("first");
        const uint32_t count = details.at("count");
        nlohmann::json::array_t result;
        result.reserve(std::min(count, 1000u)); // Prevent reallocs for reasonable fetches
        locker_t locker(m_mutex);
        const auto timestamp = m_cache->get_latest_transaction_timestamp(subaccount);
        const bool sync_disrupted = details["sync_ts"] != timestamp;
        if (sync_disrupted) {
            GDK_LOG(debug) << "Tx sync(" << subaccount << ") disrupted before fetch: " << details["sync_ts"]
                           << " != " << timestamp;
            // Note we don't need to update m_synced_subaccounts here as
            // the caller will re-iterate to sync
            return nlohmann::json(false);
        }

        m_cache->get_transactions(subaccount, first, count,
            { [&result](uint64_t /*ts*/, const std::string& /*txhash*/, uint32_t /*block*/, uint32_t /*spent*/,
                  nlohmann::json& tx_json) {
                // TODO: Remove j_erase(transaction_size) when cache version
                // is upgraded beyond 1.3 and clears transactions.
                j_erase(tx_json, "transaction_size");
                tx_json["spv_verified"] = "disabled";
                result.emplace_back(std::move(tx_json));
            } });

        return nlohmann::json(std::move(result));
    }

    bool ga_session::encache_blinding_data(const std::string& pubkey_hex, const std::string& script_hex,
        const std::string& nonce_hex, const std::string& blinding_pubkey_hex)
    {
        const auto pubkey = h2b(pubkey_hex);
        const auto script = h2b(script_hex);
        const auto nonce = h2b(nonce_hex);
        std::vector<unsigned char> blinding_pubkey;

        locker_t locker(m_mutex);
        if (blinding_pubkey_hex.empty()) {
            // No master blinding key: HWW must give us the blinding pubkeys
            GDK_RUNTIME_ASSERT_MSG(m_signer->has_master_blinding_key(), "Invalid get_blinding_nonces reply");
            blinding_pubkey = m_signer->get_blinding_pubkey_from_script(script);
        } else {
            blinding_pubkey = h2b(blinding_pubkey_hex);
        }
        return m_cache->insert_liquid_blinding_data(pubkey, script, nonce, blinding_pubkey);
    }

    void ga_session::encache_new_scriptpubkeys(uint32_t subaccount)
    {
        uint32_t current_last_pointer = 0;
        uint32_t final_last_pointer = 1;
        auto details = nlohmann::json({ { "subaccount", subaccount } });
        {
            locker_t locker(m_mutex);
            final_last_pointer = m_cache->get_latest_scriptpubkey_pointer(subaccount);
        }
        do {
            const nlohmann::json result = get_previous_addresses(details);
            for (auto& address : result.at("list")) {
                const bool allow_unconfidential = true;
                const auto spk = scriptpubkey_from_address(m_net_params, address.at("address"), allow_unconfidential);
                const uint32_t branch = j_uint32(address, "branch").value_or(1);
                const uint32_t pointer = j_uint32ref(address, "pointer");
                const uint32_t subtype = j_uint32_or_zero(address, "subtype");
                const auto& addr_type = j_strref(address, "address_type");
                locker_t locker(m_mutex);
                m_cache->insert_scriptpubkey_data(spk, subaccount, branch, pointer, subtype, addr_type);
            }
            if (result.contains("last_pointer")) {
                details["last_pointer"] = result.at("last_pointer");
                current_last_pointer = details["last_pointer"];
            } else {
                current_last_pointer = 0;
            }
        } while (current_last_pointer > final_last_pointer);

        locker_t locker(m_mutex);
        m_cache->save_db();
    }

    nlohmann::json ga_session::get_scriptpubkey_data(byte_span_t scriptpubkey)
    {
        locker_t locker(m_mutex);
        return m_cache->get_scriptpubkey_data(scriptpubkey);
    }

    nlohmann::json ga_session::get_unspent_outputs(const nlohmann::json& details, unique_pubkeys_and_scripts_t& missing)
    {
        const auto subaccount = j_uint32ref(details, "subaccount");
        const auto num_confs = j_uint32ref(details, "num_confs");
        const auto all_coins = j_bool_or_false(details, "all_coins");
        bool old_watch_only = false;

        auto utxos
            = wamp_cast_json(m_wamp->call("txs.get_all_unspent_outputs", num_confs, subaccount, "any", all_coins));

        locker_t locker(m_mutex);
        old_watch_only = m_watch_only && !m_blob->has_key();
        if (cleanup_utxos(locker, utxos, std::string(), missing)) {
            m_cache->save_db(); // Cache was updated; save it
        }

        // Compute the locktime of our UTXOs locally where we can
        bool need_nlocktime_info = false;
        for (auto& utxo : utxos) {
            if (j_strref(utxo, "address_type") != address_type::csv) {
                // Must get nlocktime info from the server for this UTXO.
                // Liquid doesn't have nlocktimes, we check that once, below.
                need_nlocktime_info = true;
            } else {
                const auto block_height = j_uint32ref(utxo, "block_height");
                if (block_height != 0) {
                    // CSV nlocktime is relative to the block the tx confirmed in
                    const auto csv_blocks = j_uint32ref(utxo, "subtype");
                    GDK_RUNTIME_ASSERT(csv_blocks != 0);
                    utxo["expiry_height"] = block_height + csv_blocks;
                }
            }
        }

        if (need_nlocktime_info && !m_net_params.is_liquid()) {
            // For non-CSV UTXOs, use nlocktime data provided by the server
            const auto nlocktimes = update_nlocktime_info(locker);
            if (nlocktimes && !nlocktimes->empty()) {
                for (auto& utxo : utxos) {
                    const auto vout = j_uint32ref(utxo, "pt_idx");
                    const std::string k{ j_strref(utxo, "txhash") + ":" + std::to_string(vout) };
                    if (const auto it = nlocktimes->find(k); it != nlocktimes->end()) {
                        utxo["expiry_height"] = j_uint32ref(it->second, "nlocktime_at");
                    }
                }
            }
        }
        if (!old_watch_only) {
            // Old (non client blob) watch only sessions cannot generate prevout_script
            for (auto& utxo : utxos) {
                if (!utxo.contains("prevout_script")) {
                    utxo["prevout_script"] = b2h(output_script_from_utxo(locker, utxo));
                }
            }
        }
        return utxos;
    }

    void ga_session::process_unspent_outputs(nlohmann::json& utxos)
    {
        const bool is_liquid = m_net_params.is_liquid();
        if (is_liquid) {
            // Reprocess to unblind any UTXOS we now have the nonces for
            unique_pubkeys_and_scripts_t missing;
            locker_t locker(m_mutex);
            if (cleanup_utxos(locker, utxos, std::string(), missing)) {
                m_cache->save_db(); // Cache was updated; save it
            }
        }

        // Return the UTXOs grouped by asset id
        // FIXME: Move the results from utxos instead of copying
        nlohmann::json asset_utxos;
        for (const auto& utxo : utxos) {
            if (utxo.contains("error")) {
                asset_utxos["error"].emplace_back(utxo);
            } else {
                const auto utxo_asset_id = j_assetref(is_liquid, utxo);
                asset_utxos[utxo_asset_id].emplace_back(utxo);
            }
        }
        utxos.swap(asset_utxos);
    }

    // Idempotent
    nlohmann::json ga_session::set_unspent_outputs_status(
        const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        auto result = m_wamp->call("vault.set_utxo_status", mp_cast(details).get(), mp_cast(twofactor_data).get());
        // Nuke cached UTXOs as their user_status may be out of date.
        remove_cached_utxos(std::vector<uint32_t>());
        return wamp_cast_json(result);
    }

    // Idempotent
    Tx ga_session::get_raw_transaction_details(const std::string& txhash_hex) const
    {
        try {
            std::vector<unsigned char> tx_bin;
            locker_t locker(m_mutex);
            // First, try the local cache
            m_cache->get_transaction_data(txhash_hex, { [&tx_bin](const auto& db_blob) {
                if (db_blob.has_value()) {
                    tx_bin.assign(db_blob.value().begin(), db_blob.value().end());
                }
            } });
            if (!tx_bin.empty()) {
                GDK_LOG(debug) << "Tx cache using cached " << txhash_hex;
            } else {
                // Not found, ask the server
                auto server_tx_hex = wamp_cast(m_wamp->call(locker, "txs.get_raw_output", txhash_hex));
                if (server_tx_hex.empty()) {
                    throw user_error("Transaction not found");
                }
                tx_bin = h2b(server_tx_hex);
                // Cache the result
                m_cache->insert_transaction_data(txhash_hex, tx_bin);
            }
            return Tx(tx_bin, m_net_params.is_liquid());
        } catch (const std::exception& e) {
            GDK_LOG(warning) << "Error fetching " << txhash_hex << " : " << e.what();
            throw user_error("Transaction not found");
        }
    }

    void ga_session::update_address_info(nlohmann::json& address, bool is_historic)
    {
        bool old_watch_only;
        uint32_t csv_blocks;
        {
            locker_t locker(m_mutex);
            // Old (non client blob) watch only sessions cannot validate addrs
            old_watch_only = m_watch_only && !m_blob->has_key();
            csv_blocks = m_csv_blocks;
        }

        j_rename(address, "ad", "address"); // Returned by wamp call get_my_addresses
        json_add_if_missing(address, "subtype", 0, true); // Convert null subtype to 0
        j_rename(address, "addr_type", "address_type");
        j_erase(address, "script_type");

        // Ensure the the server returned a script
        const auto server_script = j_bytesref(address, "script");
        // Verify the server returned script matches what we generate
        // locally from the UTXO details (and thus that the address
        // is valid). Skip this for old watch only sessions which don't
        // have a client blob and so can't verify.
        const bool verify_script = !old_watch_only;
        const auto derived_address = get_address_from_utxo(*this, address, verify_script);

        if (!address.contains("address")) {
            address["address"] = derived_address;
        } else {
            // The server returned an address; It must match the address
            // generated from the script (which we verified above)
            GDK_RUNTIME_ASSERT(address["address"] == derived_address);
        }

        if (j_strref(address, "address_type") == address_type::csv) {
            // Make sure the csv value used is in our csv buckets. If it
            // isn't, coins held in such scripts may not be recoverable.
            const auto addr_csv_blocks = get_csv_blocks_from_csv_script(server_script);
            GDK_RUNTIME_ASSERT(m_net_params.is_valid_csv_value(addr_csv_blocks));
            if (!is_historic) {
                // For new addresses, ensure that the csvtime is the users
                // current csv_blocks setting.
                GDK_RUNTIME_ASSERT(addr_csv_blocks == csv_blocks);
            }
        }

        constexpr bool allow_unconfidential = true;
        address["scriptpubkey"] = b2h(scriptpubkey_from_address(m_net_params, derived_address, allow_unconfidential));

        if (m_net_params.is_liquid()) {
            // Mark the address as non-confidential. It will be converted to
            // a confidential address later by asking the sessions signer to do so.
            address["is_confidential"] = false;
        }
        utxo_add_paths(*this, address);
    }

    nlohmann::json ga_session::get_previous_addresses(const nlohmann::json& details)
    {
        const uint32_t subaccount = details.at("subaccount");
        const bool get_newest = !details.contains("last_pointer") || details["last_pointer"].is_null();
        const uint32_t last_pointer = j_uint32_or_zero(details, "last_pointer");
        if (!get_newest && last_pointer < 2) {
            // Prevent a server call if the user iterates until empty results
            return { { "list", nlohmann::json::array() } };
        }

        // Fetch the list of previous addresses from the server
        auto addresses = wamp_cast_json(m_wamp->call("addressbook.get_my_addresses", subaccount, last_pointer));
        uint32_t seen_pointer = 0;

        for (auto& address : addresses) {
            address["subaccount"] = subaccount;
            update_address_info(address, true);
            j_rename(address, "num_tx", "tx_count");
            seen_pointer = address["pointer"];
        }

        if (seen_pointer < 2) {
            return nlohmann::json{ { "list", addresses } };
        }
        return nlohmann::json{ { "last_pointer", seen_pointer }, { "list", addresses } };
    }

    nlohmann::json ga_session::get_receive_address(const nlohmann::json& details)
    {
        using namespace address_type;
        const uint32_t subaccount = details.at("subaccount");
        auto addr_type = j_str_or_empty(details, "address_type");
        if (addr_type.empty()) {
            addr_type = get_default_address_type(subaccount);
        }

        GDK_RUNTIME_ASSERT_MSG(addr_type == p2sh || addr_type == p2wsh || addr_type == csv, "Unknown address type");

        constexpr bool return_pointer = true;
        auto address = wamp_cast_json(m_wamp->call("vault.fund", subaccount, return_pointer, addr_type));
        update_address_info(address, false);
        GDK_RUNTIME_ASSERT(j_strref(address, "address_type") == addr_type);
        return address;
    }

    // Idempotent
    nlohmann::json ga_session::get_available_currencies() const
    {
        return wamp_cast_json(m_wamp->call("login.available_currencies"));
    }

    // Note: Current design is to always enable RBF if the server supports
    // it, perhaps allowing disabling for individual txs or only for BIP 70
    bool ga_session::is_rbf_enabled() const
    {
        locker_t locker(m_mutex);
        return !m_net_params.is_liquid() && j_bool(m_login_data, "rbf").value_or(true);
    }

    nlohmann::json ga_session::get_appearance() const
    {
        locker_t locker(m_mutex);
        return m_login_data.at("appearance");
    }

    bool ga_session::subaccount_allows_csv(uint32_t subaccount) const
    {
        locker_t locker(m_mutex);
        const auto p = m_subaccounts.find(subaccount);
        GDK_USER_ASSERT(p != m_subaccounts.end(), "Unknown subaccount"); // FIXME: res::
        return p->second.at("type") == "2of2"; // Only Green 2of2 subaccounts allow CSV
    }

    const std::string& ga_session::get_default_address_type(uint32_t subaccount) const
    {
        const auto appearance = get_appearance();
        if (j_bool_or_false(appearance, "use_csv") && subaccount_allows_csv(subaccount)) {
            return address_type::csv;
        }
        if (j_bool_or_false(appearance, "use_segwit")) {
            return address_type::p2wsh;
        }
        return address_type::p2sh;
    }

    nlohmann::json ga_session::get_twofactor_config(bool reset_cached)
    {
        ensure_full_session();

        locker_t locker(m_mutex);
        return get_twofactor_config(locker, reset_cached);
    }

    nlohmann::json ga_session::get_twofactor_config(locker_t& locker, bool reset_cached)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        if (m_twofactor_config.is_null() || reset_cached) {
            auto config = wamp_cast_json(m_wamp->call(locker, "twofactor.get_config"));
            set_twofactor_config(locker, config);
        }
        auto ret = m_twofactor_config;
        ret["limits"] = get_spending_limits(locker);
        return ret;
    }

    void append_2fa_config(const std::string& name, const std::string& enabled_key, const std::string& confirmed_key,
        const std::string& data_key, const nlohmann::json& config, nlohmann::json& out)
    {
        if (config.contains(enabled_key)) {
            out[name] = nlohmann::json{
                { "enabled", config[enabled_key] },
                { "confirmed", config[confirmed_key] },
                { "data", data_key.empty() ? std::string() : std::string(config[data_key]) },
            };
            out["all_methods"].push_back(name);
        }
    }

    void ga_session::set_twofactor_config(locker_t& locker, const nlohmann::json& config_)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        // Make non-const copy for gauth hack
        // FIXME: when gauth is fixed
        nlohmann::json config = config_;

        const bool gauth_enabled = config["gauth"];
        if (gauth_enabled) {
            config["gauth_url"] = MASKED_GAUTH_SEED;
        }

        nlohmann::json twofactor_config = {
            { "all_methods", nlohmann::json::array_t() },
            { "twofactor_reset", get_twofactor_reset_status(locker, m_login_data) },
        };
        append_2fa_config("email", "email", "email_confirmed", "email_addr", config, twofactor_config);
        append_2fa_config("sms", "sms", "sms", "sms_number", config, twofactor_config);
        append_2fa_config("phone", "phone", "phone", "phone_number", config, twofactor_config);
        append_2fa_config("gauth", "gauth", "gauth", "gauth_url", config, twofactor_config);
        append_2fa_config("telegram", "telegram", "telegram", "", config, twofactor_config);

        std::swap(m_twofactor_config, twofactor_config);
        set_enabled_twofactor_methods(locker);
    }

    void ga_session::set_enabled_twofactor_methods(locker_t& locker)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        const auto& all_methods = j_arrayref(m_twofactor_config, "all_methods");
        nlohmann::json::array_t enabled_methods;
        enabled_methods.reserve(all_methods.size());
        for (const auto& m : all_methods) {
            if (j_bool_or_false(m_twofactor_config[m], "enabled")) {
                enabled_methods.emplace_back(m);
            }
        }
        m_twofactor_config["any_enabled"] = !enabled_methods.empty();
        m_twofactor_config["enabled_methods"] = std::move(enabled_methods);
    }

    std::vector<std::string> ga_session::get_enabled_twofactor_methods()
    {
        locker_t locker(m_mutex);
        return get_twofactor_config(locker)["enabled_methods"];
    }

    void ga_session::set_email(const std::string& email, const nlohmann::json& twofactor_data)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        m_wamp->call(locker, "twofactor.set_email", email, mp_cast(twofactor_data).get());
        // FIXME: update data only after activate?
        m_twofactor_config["email"]["data"] = email;
    }

    void ga_session::activate_email(const std::string& code)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        m_wamp->call(locker, "twofactor.activate_email", code);
        m_twofactor_config["email"]["confirmed"] = true;
    }

    nlohmann::json ga_session::init_enable_twofactor(
        const std::string& method, const std::string& data, const nlohmann::json& twofactor_data)
    {
        const std::string api_method = "twofactor.init_enable_" + method;

        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        auto result = m_wamp->call(locker, api_method, data, mp_cast(twofactor_data).get());
        m_twofactor_config[method]["data"] = data;

        return wamp_cast_json(result);
    }

    void ga_session::enable_twofactor(const std::string& method, const std::string& code)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        auto config = wamp_cast_json(m_wamp->call(locker, "twofactor.enable_" + method, code));
        if (!config.contains("gauth_url")) {
            // Copy over the existing gauth value until gauth is sorted out
            // TODO: Fix gauth so the user passes the secret
            config["gauth_url"] = j_str(m_twofactor_config["gauth"], "data").value_or(MASKED_GAUTH_SEED);
        }
        set_twofactor_config(locker, config);
    }

    void ga_session::enable_gauth(const std::string& code, const nlohmann::json& twofactor_data)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        auto config
            = wamp_cast_json(m_wamp->call(locker, "twofactor.enable_gauth", code, mp_cast(twofactor_data).get()));
        set_twofactor_config(locker, config);
    }

    void ga_session::disable_twofactor(const std::string& method, const nlohmann::json& twofactor_data)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        m_wamp->call(locker, "twofactor.disable_" + method, mp_cast(twofactor_data).get());

        // Update our local 2fa config
        auto& config = m_twofactor_config[method];
        config["enabled"] = false;
        // If the call succeeds it means the method was previously enabled, hence
        // for email the email address is still confirmed even though 2fa is disabled.
        const bool confirmed = method == "email";
        config["confirmed"] = confirmed;
        set_enabled_twofactor_methods(locker);
    }

    // Idempotent
    nlohmann::json ga_session::auth_handler_request_code(
        const std::string& method, const std::string& action, const nlohmann::json& twofactor_data)
    {
        auto result = m_wamp->call("twofactor.request_" + method, action, mp_cast(twofactor_data).get());
        return wamp_cast_json(result);
    }

    // Idempotent
    std::string ga_session::auth_handler_request_proxy_code(
        const std::string& action, const nlohmann::json& twofactor_data)
    {
        auto result = m_wamp->call("twofactor.request_proxy", action, mp_cast(twofactor_data).get());
        return wamp_cast_json(result);
    }

    // Idempotent
    nlohmann::json ga_session::request_twofactor_reset(const std::string& email)
    {
        return wamp_cast_json(m_wamp->call("twofactor.request_reset", email));
    }

    // Idempotent
    nlohmann::json ga_session::request_undo_twofactor_reset(const std::string& email)
    {
        return wamp_cast_json(m_wamp->call("twofactor.request_undo_reset", email));
    }

    nlohmann::json ga_session::set_twofactor_reset_config(const nlohmann::json& config)
    {
        // Verify the server isn't providing any unexpected fields
        GDK_RUNTIME_ASSERT(config.size() == 3u && config.contains("reset_2fa_active")
            && config.contains("reset_2fa_days_remaining") && config.contains("reset_2fa_disputed"));

        locker_t locker(m_mutex);

        // Copy the servers results into login_data
        m_login_data.update(config);

        const nlohmann::json reset_status = { { "twofactor_reset", get_twofactor_reset_status(locker, m_login_data) } };
        if (!m_twofactor_config.is_null()) {
            // Update cached twofactor config with our new reset status
            m_twofactor_config.update(reset_status);
        }
        return reset_status;
    }

    nlohmann::json ga_session::confirm_twofactor_reset(
        const std::string& email, bool is_dispute, const nlohmann::json& twofactor_data)
    {
        auto result = m_wamp->call("twofactor.confirm_reset", email, is_dispute, mp_cast(twofactor_data).get());
        return set_twofactor_reset_config(wamp_cast_json(result));
    }

    nlohmann::json ga_session::confirm_undo_twofactor_reset(
        const std::string& email, const nlohmann::json& twofactor_data)
    {
        auto result = m_wamp->call("twofactor.confirm_undo_reset", email, mp_cast(twofactor_data).get());
        return set_twofactor_reset_config(wamp_cast_json(result));
    }

    nlohmann::json ga_session::cancel_twofactor_reset(const nlohmann::json& twofactor_data)
    {
        auto result = m_wamp->call("twofactor.cancel_reset", mp_cast(twofactor_data).get());
        return set_twofactor_reset_config(wamp_cast_json(result));
    }

    // Idempotent
    nlohmann::json ga_session::encrypt_with_pin(const nlohmann::json& details)
    {
        ensure_full_session();

        const std::string pin = details.at("pin");
        const nlohmann::json& plaintext = details.at("plaintext");
        const std::string device_id = j_str(details, "device_id").value_or(b2h(get_random_bytes<8>()));

        GDK_RUNTIME_ASSERT(pin.length() >= 4);
        GDK_RUNTIME_ASSERT(!device_id.empty() && device_id.length() <= 100);

        // Ask the server to create a new PIN identifier and PIN password
        constexpr bool return_password = true;
        const std::string pin_info = wamp_cast(m_wamp->call("pin.set_pin_login", pin, device_id, return_password));

        std::vector<std::string> id_and_password;
        boost::algorithm::split(id_and_password, pin_info, boost::is_any_of(";"));
        GDK_RUNTIME_ASSERT(id_and_password.size() == 2u);
        const auto& password = id_and_password.back();

        // Encrypt the users mnemonic and seed using a key dervied from the
        // PIN password and a randomly generated salt.
        // Note the use of base64 here is to remain binary compatible with
        // old GreenBits installs.
        const auto salt = get_random_bytes<16>();
        const auto salt_b64 = base64_from_bytes(salt);
        const auto key = pbkdf2_hmac_sha512_256(ustring_span(password), ustring_span(salt_b64));

        // FIXME: secure string
        const std::string json = plaintext.dump();

        return { { "pin_identifier", id_and_password.front() }, { "salt", salt_b64 },
            { "encrypted_data", aes_cbc_encrypt_to_hex(key, ustring_span(json)) } };
    }

    // Idempotent
    nlohmann::json ga_session::decrypt_with_pin(const nlohmann::json& details)
    {
        constexpr bool is_login = false;
        return decrypt_with_pin_impl(details, is_login);
    }

    // Idempotent
    void ga_session::disable_all_pin_logins()
    {
        ensure_full_session();
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(m_wamp->call("pin.remove_all_pin_logins")));
    }

    // Idempotent
    std::vector<unsigned char> ga_session::get_pin_password(const std::string& pin, const std::string& pin_identifier)
    {
        std::string password = wamp_cast(m_wamp->call("pin.get_password", pin, pin_identifier));
        return std::vector<unsigned char>(password.begin(), password.end());
    }

    nlohmann::json ga_session::service_sign_transaction(const nlohmann::json& details,
        const nlohmann::json& twofactor_data, std::vector<std::vector<unsigned char>>& old_scripts)
    {
        constexpr bool is_send = false;
        return sign_or_send_tx(details, twofactor_data, is_send, old_scripts);
    }

    nlohmann::json ga_session::send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        constexpr bool is_send = true;
        std::vector<std::vector<unsigned char>> old_scripts;
        return sign_or_send_tx(details, twofactor_data, is_send, old_scripts);
    }

    nlohmann::json ga_session::sign_or_send_tx(const nlohmann::json& details, const nlohmann::json& twofactor_data,
        bool is_send, std::vector<std::vector<unsigned char>>& old_scripts)
    {
        GDK_RUNTIME_ASSERT(j_str_is_empty(details, "error"));
        // We must have a tx, the server will ensure it has been signed by the user
        GDK_RUNTIME_ASSERT(details.contains("transaction"));

        nlohmann::json result = details;

        // Check memo is storable, if we are sending and have one
        const std::string memo = is_send ? j_str_or_empty(result, "memo") : std::string();
        check_tx_memo(memo);

        // FIXME: test weight and return error in create_transaction, not here
        const auto& tx_hex = j_strref(result, "transaction");
        const size_t MAX_TX_WEIGHT = 400000;
        const Tx unsigned_tx(tx_hex, m_net_params.is_liquid());
        constexpr bool with_discount = false;
        GDK_RUNTIME_ASSERT(unsigned_tx.get_weight(with_discount) < MAX_TX_WEIGHT);

        nlohmann::json private_data;
        if (auto p = result.find("blinding_nonces"); p != result.end()) {
            private_data["blinding_nonces"] = *p;
        }

        const auto mp_2fa = mp_cast(twofactor_data);
        const auto mp_pd = mp_cast(private_data);
        const char* handler = is_send ? "vault.send_raw_tx" : "vault.sign_raw_tx";
        auto tx_details = wamp_cast_json(m_wamp->call(handler, tx_hex, mp_2fa.get(), mp_pd.get()));

        const amount::value_type decrease = tx_details.at("limit_decrease");
        const auto txhash_hex = tx_details["txhash"];
        result["txhash"] = txhash_hex;
        purge_tx_notification(txhash_hex);

        // Update the details with the server signed transaction, since it
        // may be a slightly different size once signed
        Tx tx(j_strref(tx_details, "tx"), m_net_params.is_liquid());
        if (!old_scripts.empty()) {
            // Partial signing (signing of only some inputs):
            // Restore the original input scriptSigs, which were swapped out
            // for redeem scripts to allow the backend to check segwit-ness
            for (size_t i = 0; i < old_scripts.size(); ++i) {
                if (!old_scripts.at(i).empty()) {
                    tx.set_input_script(i, old_scripts.at(i));
                }
            }
        }
        update_tx_size_info(m_net_params, tx, result);

        // TODO: get outputs/change subaccounts also, for multi-account spends
        const auto subaccounts = get_tx_subaccounts(details);
        remove_cached_utxos({ subaccounts.begin(), subaccounts.end() });

        locker_t locker(m_mutex);
        for (auto subaccount : subaccounts) {
            m_synced_subaccounts.erase(subaccount);
        }

        if (is_send) {
            // Cache the raw tx data
            m_cache->insert_transaction_data(txhash_hex, tx.to_bytes());

            if (!memo.empty() && have_writable_client_blob(locker)) {
                update_client_blob(locker, std::bind(&client_blob::set_tx_memo, m_blob.get(), txhash_hex, memo));
            }
        }

        if (decrease != 0) {
            update_spending_limits(locker, tx_details["limits"]);
        }

        m_cache->save_db();
        return result;
    }

    nlohmann::json ga_session::broadcast_transaction(const nlohmann::json& details)
    {
        const auto& tx_hex = j_strref(details, "transaction");
        auto txhash_hex = wamp_cast(m_wamp->call("vault.broadcast_raw_tx", tx_hex));
        purge_tx_notification(txhash_hex);
        auto result = details;
        locker_t locker(m_mutex);
        if (have_writable_client_blob(locker)) {
            if (auto memo = j_str_or_empty(details, "memo"); !memo.empty()) {
                update_client_blob(locker, std::bind(&client_blob::set_tx_memo, m_blob.get(), txhash_hex, memo));
            }
        }
        result["txhash"] = std::move(txhash_hex);
        return result;
    }

    void ga_session::send_nlocktimes()
    {
        ensure_full_session();
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(m_wamp->call("txs.send_nlocktime")));
        remove_cached_utxos({});
        // Clear cached UTXOs and nlocktimes, the backend may have generated new ones
        locker_t locker(m_mutex);
        m_nlocktimes.reset();
    }

    void ga_session::set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        const auto csv_blocks = j_uint32ref(locktime_details, "value");
        GDK_RUNTIME_ASSERT(m_net_params.is_valid_csv_value(csv_blocks));

        locker_t locker(m_mutex);
        // This not only saves a server round trip in case of bad value, but
        // also ensures that the value is recoverable.
        auto result = m_wamp->call(locker, "login.set_csvtime", csv_blocks, mp_cast(twofactor_data).get());
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));
        m_csv_blocks = csv_blocks;
    }

    void ga_session::set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        const auto nlocktime = j_uint32ref(locktime_details, "value");
        auto result = m_wamp->call("login.set_nlocktime", nlocktime, mp_cast(twofactor_data).get());
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));

        locker_t locker(m_mutex);
        m_nlocktime = nlocktime;
    }

} // namespace green
