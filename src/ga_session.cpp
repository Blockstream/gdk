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

#include "autobahn_wrapper.hpp"
#include "boost_wrapper.hpp"
#include "exception.hpp"
#include "ga_cache.hpp"
#include "ga_session.hpp"
#include "ga_strings.hpp"
#include "ga_tx.hpp"
#include "http_client.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include "utils.hpp"
#include "version.h"
#include "wamp_transport.hpp"
#include "xpub_hdkey.hpp"

#define TX_CACHE_LEVEL log_level::debug

using namespace std::literals;
namespace asio = boost::asio;

namespace ga {
namespace sdk {

    namespace {
        static const std::string USER_AGENT_CAPS("[v2,sw,csv,csv_opt]");
        static const std::string USER_AGENT_CAPS_NO_CSV("[v2,sw]");

        static const std::string MASKED_GAUTH_SEED("***");
        static const uint32_t DEFAULT_MIN_FEE = 1000; // 1 satoshi/byte
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

        // TODO: too slow. lacks validation.
        static std::array<unsigned char, SHA256_LEN> uint256_to_base256(const std::string& input)
        {
            constexpr size_t base = 256;

            std::array<unsigned char, SHA256_LEN> repr{};
            size_t i = repr.size() - 1;
            for (boost::multiprecision::checked_uint256_t num(input); num; num = num / base, --i) {
                repr[i] = static_cast<unsigned char>(num % base);
            }

            return repr;
        }

        static bool ignore_tx_notification(const nlohmann::json& details)
        {
            for (const auto& item : details.items()) {
                const std::string key = item.key();
                if (std::find(TX_NTFY_FIELDS.begin(), TX_NTFY_FIELDS.end(), key) == TX_NTFY_FIELDS.end()) {
                    GDK_LOG_SEV(log_level::info) << "Ignoring tx notification: unknown field " << item.key();
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
            });
            clean_notifications_settings.update(clean["notifications_settings"]);
            clean["notifications_settings"] = clean_notifications_settings;
            GDK_RUNTIME_ASSERT(clean["notifications_settings"]["email_incoming"].is_boolean());
            GDK_RUNTIME_ASSERT(clean["notifications_settings"]["email_outgoing"].is_boolean());

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

        std::string get_user_agent(bool supports_csv, const std::string& version)
        {
            constexpr auto max_len = 64;
            const auto& caps = supports_csv ? USER_AGENT_CAPS : USER_AGENT_CAPS_NO_CSV;
            auto user_agent = caps + version;
            if (user_agent.size() > max_len) {
                GDK_LOG_SEV(log_level::warning)
                    << "Truncating user agent string, exceeds max length (" << max_len << ")";
                user_agent = user_agent.substr(0, max_len);
            }
            return user_agent;
        }

        static inline void check_tx_memo(const std::string& memo)
        {
            GDK_RUNTIME_ASSERT_MSG(memo.size() <= 1024, "Transaction memo too long");
        }

        static nlohmann::json get_spv_params(const network_parameters& net_params, const nlohmann::json& proxy_settings)
        {
            auto np = net_params.get_json();
            np.update(proxy_settings);
            np.erase("wamp_cert_pins"); // WMP certs are huge & unused by SPV, remove them
            np.erase("wamp_cert_roots");
            return { { "network", std::move(np) } };
        }

        // Get cached xpubs from a signer as a cacheable json format
        static nlohmann::json get_signer_xpubs_json(std::shared_ptr<signer> signer)
        {
            const auto paths_and_xpubs = signer->get_cached_bip32_xpubs();
            nlohmann::json xpubs_json;
            for (auto& item : paths_and_xpubs) {
                // Note that we cache the values inverted as the master key is empty
                xpubs_json.emplace(item.second, item.first);
            }
            return xpubs_json;
        }
    } // namespace

    ga_session::ga_session(network_parameters&& net_params)
        : session_impl(std::move(net_params))
        , m_spv_enabled(m_net_params.is_spv_enabled())
        , m_blob()
        , m_blob_hmac()
        , m_blob_outdated(false)
        , m_min_fee_rate(DEFAULT_MIN_FEE)
        , m_earliest_block_time(0)
        , m_next_subaccount(0)
        , m_fee_estimates_ts(std::chrono::system_clock::now())
        , m_system_message_id(0)
        , m_system_message_ack_id(0)
        , m_watch_only(true)
        , m_tx_last_notification(std::chrono::system_clock::now())
        , m_last_block_notification()
        , m_multi_call_category(0)
        , m_cache(std::make_shared<cache>(m_net_params, m_net_params.network()))
        , m_user_agent(std::string(GDK_COMMIT) + " " + m_net_params.user_agent())
        , m_wamp(new wamp_transport(m_net_params,
              std::bind(&ga_session::emit_notification, this, std::placeholders::_1, std::placeholders::_2)))
        , m_spv_thread_done(false)
        , m_spv_thread_stop(false)
    {
        m_fee_estimates.assign(NUM_FEE_ESTIMATES, m_min_fee_rate);
    }

    ga_session::~ga_session()
    {
        m_notify = false;
        no_std_exception_escape([this] { reset_all_session_data(true); });
        no_std_exception_escape([this] {
            locker_t locker(m_mutex);
            constexpr bool do_start = false;
            download_headers_ctl(locker, do_start);
        });
    }

    void ga_session::connect()
    {
        const auto proxy = session_impl::connect_tor();
        m_wamp->connect(proxy);
    }

    void ga_session::reconnect() { m_wamp->reconnect(); }

    void ga_session::reconnect_hint(const nlohmann::json& hint)
    {
        session_impl::reconnect_hint(hint);
        const auto proxy_settings = get_proxy_settings();
        const auto& proxy = proxy_settings.at("proxy");
        const auto hint_p = proxy.find("hint");
        if (hint_p != proxy.end() && *hint_p != "connect") {
            // Stop any outstanding header sync when disconnecting. Leave
            // resuming until after the session is authed and we know what
            // the current block is.
            locker_t locker(m_mutex);
            constexpr bool do_start = false;
            download_headers_ctl(locker, do_start);
        }
        m_wamp->reconnect_hint(hint, proxy);
    }

    void ga_session::disconnect() { m_wamp->disconnect(); }

    void ga_session::emit_notification(nlohmann::json details, bool async)
    {
        if (m_notify) {
            if (async) {
                m_wamp->post([this, details] { emit_notification(details, false); });
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
            for (const auto& v : nlocktime_json.at("list")) {
                const uint32_t vout = v.at("output_n");
                const std::string k{ json_get_value(v, "txhash") + ":" + std::to_string(vout) };
                m_nlocktimes->emplace(std::make_pair(k, v));
            }
        }

        return m_nlocktimes;
    }

    nlohmann::json ga_session::validate_asset_domain_name(const nlohmann::json& params)
    {
        boost::format format_str{ "Authorize linking the domain name %1% to the Liquid asset %2%\n" };
        boost::format target_str{ "/.well-known/liquid-asset-proof-%1%" };

        nlohmann::json result;
        try {
            const std::string domain_name = params.at("domain");
            const std::string asset_id = params.at("asset_id");
            const std::string final_target = (target_str % asset_id).str();
            const std::string url = domain_name + final_target;
            result = http_request({ { "method", "GET" }, { "urls", { url } } });
            if (!json_get_value(result, "error").empty()) {
                return result;
            }
            const std::string body_r = result.at("body");
            GDK_RUNTIME_ASSERT_MSG(
                body_r == (format_str % domain_name % asset_id).str(), "found domain name with proof mismatch");
        } catch (const std::exception& ex) {
            result["error"] = ex.what();
        }

        return result;
    }

    std::pair<std::string, std::string> ga_session::sign_challenge(
        session_impl::locker_t& locker, const std::string& challenge)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(m_signer != nullptr);

        auto path_bytes = get_random_bytes<8>();

        std::vector<uint32_t> path(4);
        adjacent_transform(std::begin(path_bytes), std::end(path_bytes), std::begin(path),
            [](auto first, auto second) { return uint32_t((first << 8) + second); });

        const auto challenge_hash = uint256_to_base256(challenge);

        return { sig_to_der_hex(m_signer->sign_hash(path, challenge_hash)), b2h(path_bytes) };
    }

    void ga_session::set_fee_estimates(session_impl::locker_t& locker, const nlohmann::json& fee_estimates)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_LOG_SEV(log_level::debug) << "Set fee estimates " << fee_estimates.dump();

        // Convert server estimates into an array of NUM_FEE_ESTIMATES estimates
        // ordered by block, with the minimum allowable fee at position 0
        std::map<uint32_t, uint32_t> ordered_estimates;
        for (const auto& e : fee_estimates) {
            const auto& fee_rate = e["feerate"];
            double btc_per_k;
            if (fee_rate.is_string()) {
                const std::string fee_rate_str = fee_rate;
                btc_per_k = boost::lexical_cast<double>(fee_rate_str);
            } else {
                btc_per_k = fee_rate;
            }
            if (btc_per_k > 0) {
                const uint32_t actual_block = e["blocks"];
                if (actual_block > 0 && actual_block <= NUM_FEE_ESTIMATES - 1) {
                    const long long satoshi_per_k = std::lround(btc_per_k * amount::coin_value);
                    const long long uint32_t_max = std::numeric_limits<uint32_t>::max();
                    if (satoshi_per_k >= DEFAULT_MIN_FEE && satoshi_per_k <= uint32_t_max) {
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
                new_estimates[i] = e.second;
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

    nlohmann::json ga_session::register_user(const std::string& master_pub_key_hex,
        const std::string& master_chain_code_hex, const std::string& gait_path_hex, bool supports_csv)
    {
        const auto user_agent = get_user_agent(supports_csv, m_user_agent);
        auto result
            = m_wamp->call("login.register", master_pub_key_hex, master_chain_code_hex, user_agent, gait_path_hex);
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));
        return session_impl::register_user(master_pub_key_hex, master_chain_code_hex, gait_path_hex, supports_csv);
    }

    std::string ga_session::get_challenge(const pub_key_t& public_key)
    {
        const auto address = get_address_from_public_key(m_net_params, public_key, address_type::p2pkh);
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
        const std::string& root_bip32_xpub, bool watch_only, bool is_initial_login)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(m_signer != nullptr);

        nlohmann::json old_settings;
        if (!is_initial_login) {
            GDK_RUNTIME_ASSERT(m_watch_only == watch_only);
            old_settings = get_settings(locker);
        }

        const auto old_reset_status = get_twofactor_reset_status(locker, m_login_data);

        // Swap current login data with new; for relogin 'login_data' holds the old values
        m_login_data.swap(login_data);

        // Parse gait_path into a derivation path
        decltype(m_gait_path) gait_path;
        const auto gait_path_bytes = h2b(m_login_data["gait_path"]);
        GDK_RUNTIME_ASSERT(gait_path_bytes.size() == gait_path.size() * 2);
        adjacent_transform(gait_path_bytes.begin(), gait_path_bytes.end(), gait_path.begin(),
            [](auto first, auto second) { return uint32_t((first << 8u) + second); });
        if (is_initial_login) {
            m_gait_path = gait_path;
        } else {
            GDK_RUNTIME_ASSERT(m_gait_path == gait_path);
        }

        if (!m_ga_pubkeys) {
            // Create our GA and recovery pubkey collections
            m_ga_pubkeys = std::make_unique<ga_pubkeys>(m_net_params, m_gait_path);
            m_recovery_pubkeys = std::make_unique<ga_user_pubkeys>(m_net_params);
        }

        const uint32_t min_fee_rate = m_login_data["min_fee"];
        if (min_fee_rate != m_min_fee_rate) {
            m_min_fee_rate = min_fee_rate;
            m_fee_estimates.assign(NUM_FEE_ESTIMATES, m_min_fee_rate);
        }
        m_fiat_source = m_login_data["exchange"];
        m_fiat_currency = m_login_data["fiat_currency"];
        update_fiat_rate(locker, json_get_value(m_login_data, "fiat_exchange"));

        m_subaccounts.clear();
        m_next_subaccount = 0;
        for (const auto& sa : m_login_data["subaccounts"]) {
            const uint32_t subaccount = sa["pointer"];
            std::string type = sa["type"];
            if (type == "simple") {
                type = "2of2";
            }
            const std::string recovery_chain_code = json_get_value(sa, "2of3_backup_chaincode");
            const std::string recovery_pub_key = json_get_value(sa, "2of3_backup_pubkey");
            const std::string recovery_xpub_sig = json_get_value(sa, "2of3_backup_xpub_sig");
            std::string recovery_xpub;
            // TODO: fail if *any* 2of3 subaccount has missing or invalid
            //       signature of the corresponding backup/recovery key.
            if (!recovery_xpub_sig.empty() && !root_bip32_xpub.empty()) {
                recovery_xpub = json_get_value(sa, "2of3_backup_xpub");
                GDK_RUNTIME_ASSERT(make_xpub(recovery_xpub) == make_xpub(recovery_chain_code, recovery_pub_key));
                const auto message = format_recovery_key_message(recovery_xpub, subaccount);
                const auto message_hash = format_bitcoin_message_hash(ustring_span(message));
                auto parent = bip32_public_key_from_bip32_xpub(root_bip32_xpub);
                ext_key derived = bip32_public_key_from_parent_path(*parent, signer::LOGIN_PATH);
                pub_key_t login_pubkey;
                memcpy(login_pubkey.begin(), derived.pub_key, sizeof(derived.pub_key));
                GDK_RUNTIME_ASSERT(ec_sig_verify(login_pubkey, message_hash, h2b(recovery_xpub_sig)));
            }

            // Get the subaccount name. Use the server provided value if
            // its present (i.e. no client blob enabled yet, or watch-only)
            const std::string svr_sa_name = json_get_value(sa, "name");
            const std::string blob_sa_name = m_blob.get_subaccount_name(subaccount);
            const std::string& sa_name = svr_sa_name.empty() ? blob_sa_name : svr_sa_name;
            const bool is_hidden = m_blob.get_subaccount_hidden(subaccount);
            insert_subaccount(locker, subaccount, sa_name, sa["receiving_id"], recovery_pub_key, recovery_chain_code,
                recovery_xpub, type, sa.value("required_ca", 0), is_hidden);

            if (subaccount > m_next_subaccount) {
                m_next_subaccount = subaccount;
            }
        }
        ++m_next_subaccount;

        // Insert the main account so callers can treat all accounts equally
        const std::string sa_name = m_blob.get_subaccount_name(0);
        constexpr uint32_t required_ca = 0;
        const bool is_hidden = m_blob.get_subaccount_hidden(0);
        insert_subaccount(locker, 0, sa_name, m_login_data["receiving_id"], std::string(), std::string(), std::string(),
            "2of2", required_ca, is_hidden);

        m_system_message_id = json_get_value(m_login_data, "next_system_message_id", 0);
        m_system_message_ack_id = 0;
        m_system_message_ack = std::string();
        m_watch_only = watch_only;

        const auto p = m_login_data.find("limits");
        update_spending_limits(locker, p == m_login_data.end() ? nlohmann::json::object() : *p);

        auto& appearance = m_login_data["appearance"];
        cleanup_appearance_settings(locker, appearance);

        m_earliest_block_time = m_login_data["earliest_key_creation_time"];

        // Compute wallet identifier for callers to use if they wish.
        const auto wallet_hash_id
            = get_wallet_hash_id(m_net_params, m_login_data["chain_code"], m_login_data["public_key"]);
        if (!is_initial_login) {
            GDK_RUNTIME_ASSERT(login_data.at("wallet_hash_id") == wallet_hash_id);
        }
        m_login_data["wallet_hash_id"] = wallet_hash_id;

        // Check that csv blocks used are recoverable and provided by the server
        const auto net_csv_buckets = m_net_params.csv_buckets();
        for (uint32_t bucket : m_login_data["csv_times"]) {
            if (std::find(net_csv_buckets.begin(), net_csv_buckets.end(), bucket) != net_csv_buckets.end()) {
                m_csv_buckets.insert(m_csv_buckets.end(), bucket);
            }
        }
        GDK_RUNTIME_ASSERT(m_csv_buckets.size() > 0);
        m_csv_blocks = m_login_data["csv_blocks"];
        GDK_RUNTIME_ASSERT(std::find(m_csv_buckets.begin(), m_csv_buckets.end(), m_csv_blocks) != m_csv_buckets.end());
        if (!m_watch_only) {
            m_nlocktime = m_login_data["nlocktime_blocks"];
        }

        set_fee_estimates(locker, m_login_data["fee_estimates"]);

        // Notify the caller of their settings / 2fa reset status
        auto settings = get_settings(locker);
        const bool must_notify_settings = old_settings != settings;

        auto reset_status = get_twofactor_reset_status(locker, m_login_data);
        const bool must_notify_reset = is_initial_login || old_reset_status != reset_status;

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

        subscribe_all(locker);

        // Notify the caller of their current block
        nlohmann::json block_json
            = { { "block_height", m_login_data.at("block_height") }, { "block_hash", m_login_data.at("block_hash") },
                  { "diverged_count", 0 }, { "previous_hash", m_login_data.at("prev_block_hash") } };

        auto post_login_data = get_post_login_data();
        on_new_block(locker, block_json, !is_initial_login); // Unlocks 'locker'
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
            GDK_LOG_SEV(log_level::error)
                << "failed to update fiat rate from string '" << rate_str << "': " << e.what();
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
        return amount(m_min_fee_rate);
    }

    amount ga_session::get_default_fee_rate() const
    {
        locker_t locker(m_mutex);
        const uint32_t block = json_get_value(m_login_data["appearance"], "required_num_blocks", 0u);
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
        GDK_RUNTIME_ASSERT(new_is_fiat == (details.find("fiat") != details.end()));

        if (current_is_fiat != new_is_fiat) {
            return false;
        }

        const amount::value_type current_total = m_limits_data["total"];
        if (new_is_fiat) {
            return amount::get_fiat_cents(details["fiat"]) <= current_total;
        }
        return convert_amount(locker, details)["satoshi"] <= current_total;
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
            m_wamp->post([this, subaccounts, details] { on_new_transaction(subaccounts, details); });
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
                GDK_LOG_SEV(log_level::debug) << "eliding notification:" << json_str;
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
                GDK_LOG_SEV(TX_CACHE_LEVEL) << "Tx sync(" << subaccount << "): new tx " << txhash_hex;
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
                details.erase("value");
            } else {
                // TODO: figure out what type is for liquid
            }
            unique_unlock unlocker(locker);
            remove_cached_utxos(subaccounts);
            emit_notification({ { "event", "transaction" }, { "transaction", std::move(details) } }, false);
        });
    }

    void ga_session::on_new_block(nlohmann::json details, bool is_relogin)
    {
        auto locker_p{ get_multi_call_locker(MC_TX_CACHE, false) };
        auto& locker = *locker_p;

        if (!locker.owns_lock()) {
            // Try again: 'post' this to allow the competing thread to proceed.
            m_wamp->post([this, details, is_relogin] { on_new_block(details, is_relogin); });
            return;
        }
        on_new_block(locker, details, is_relogin);
    }

    void ga_session::on_new_block(locker_t& locker, nlohmann::json details, bool is_relogin)
    {
        no_std_exception_escape([&]() {
            GDK_RUNTIME_ASSERT(locker.owns_lock());

            details["initial_timestamp"] = m_earliest_block_time;
            json_rename_key(details, "count", "block_height");
            details.erase("diverged_count");

            auto& last = m_last_block_notification;
            bool treat_as_reorg = false;
            bool may_have_missed_tx = false;

            if (last.empty()) {
                // First login for this session.
                GDK_LOG_SEV(TX_CACHE_LEVEL) << "Tx sync: first login";
                treat_as_reorg = true;
            } else if (is_relogin && last != details) {
                // Re-login and we have missed a block or a reorg while logged out
                GDK_LOG_SEV(TX_CACHE_LEVEL) << "Tx sync: re-login, reorg or missed block";
                // If the current block isn't the next sequentially from our last,
                // treat this as a reorg since we can't differentiate reorgs from
                // multiple missed blocks.
                treat_as_reorg = details["previous_hash"] != last["block_hash"];
                may_have_missed_tx = true;
            } else if (details["previous_hash"] != last["block_hash"]) {
                // Missed a block or encountered a reorg while logged in
                GDK_LOG_SEV(TX_CACHE_LEVEL) << "Tx sync: reorg or missed block";
                treat_as_reorg = true;
                may_have_missed_tx = true;
            } else {
                // Received the next sequential block while logged in,
                // or re-login and the block hasn't changed.
                // (happy path, continue below to delete mempool txs only)
                GDK_LOG_SEV(TX_CACHE_LEVEL) << "Tx sync: new n+1 block";
            }

            GDK_LOG_SEV(TX_CACHE_LEVEL) << "Tx sync: on new block" << (treat_as_reorg ? " (treat_as_reorg)" : "")
                                        << (may_have_missed_tx ? " (may_have_missed_tx)" : "");

            std::vector<uint32_t> modified_subaccounts;
            uint32_t reorg_block = 0;
            if (treat_as_reorg) {
                // Calculate the block to reorg from
                const uint32_t last_seen_block_height = m_cache->get_latest_block();
                const uint32_t num_reorg_blocks = std::min(m_net_params.get_max_reorg_blocks(), last_seen_block_height);
                reorg_block = last_seen_block_height - num_reorg_blocks;
                GDK_LOG_SEV(TX_CACHE_LEVEL)
                    << "Tx sync: removing " << num_reorg_blocks << " blocks from cache tip " << last_seen_block_height;

                // We can't trust the SPV state of any txs younger than the
                // max reorg depth, so clear them.
                m_spv_verified_txs.clear();
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
                    GDK_LOG_SEV(TX_CACHE_LEVEL) << "Tx sync(" << sa.first << "): marking unsynced";
                    m_synced_subaccounts.erase(sa.first);
                    modified_subaccounts.push_back(sa.first);
                }
            }

            last = details;
            m_cache->set_latest_block(last["block_height"]);
            m_cache->save_db();

            // Start syncing headers for SPV (if enabled)
            constexpr bool do_start = true;
            download_headers_ctl(locker, do_start);

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
            GDK_LOG_SEV(log_level::warning) << "Ignoring irrelevant ticker update";
        }
    }

    void ga_session::push_appearance_to_server(session_impl::locker_t& locker) const
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        const auto appearance = mp_cast(m_login_data["appearance"]);
        m_wamp->call(locker, "login.set_appearance", appearance.get());
    }

    nlohmann::json ga_session::authenticate(const std::string& sig_der_hex, const std::string& path_hex,
        const std::string& root_bip32_xpub, std::shared_ptr<signer> signer)
    {
        const bool is_initial_login = set_signer(signer);

        locker_t locker(m_mutex);

        constexpr bool minimal = true; // Don't return balance/nlocktime info
        const std::string id; // Device id, no longer used
        const auto user_agent = get_user_agent(m_signer->supports_arbitrary_scripts(), m_user_agent);

        auto result = m_wamp->call(locker, "login.authenticate", sig_der_hex, minimal, path_hex, id, user_agent);
        nlohmann::json login_data = wamp_cast_json(result);

        if (login_data.is_boolean()) {
            // Login failed
            locker.unlock();
            reset_all_session_data(false);
            throw login_error(res::id_login_failed);
        } else if (!is_initial_login) {
            // Re-login. Discard all cached data which may be out of date
            reset_cached_session_data(locker);
        }

        const bool reset_2fa_active = json_get_value(login_data, "reset_2fa_active", false);
        const std::string server_hmac = login_data["client_blob_hmac"];
        bool is_blob_on_server = !client_blob::is_zero_hmac(server_hmac);

        if (!reset_2fa_active && !is_blob_on_server && m_blob_hmac.empty()) {
            // No client blob: create one, save it to the server and cache it,
            // but only if the wallet isn't locked for a two factor reset.
            // Subaccount names
            const nlohmann::json empty;
            for (const auto& sa : login_data["subaccounts"]) {
                m_blob.set_subaccount_name(sa["pointer"], json_get_value(sa, "name"), empty);
            }
            // Tx memos
            nlohmann::json tx_memos = wamp_cast_json(m_wamp->call(locker, "txs.get_memos"));
            for (const auto& m : tx_memos["bip70"].items()) {
                m_blob.set_tx_memo(m.key(), m.value());
            }
            for (const auto& m : tx_memos["memos"].items()) {
                m_blob.set_tx_memo(m.key(), m.value());
            }

            m_blob.set_user_version(1); // Initial version

            // If this save fails due to a race, m_blob_hmac will be empty below
            save_client_blob(locker, server_hmac);
            // Our blob was enabled, either by us or another login we raced with
            is_blob_on_server = true;

            // Delete all cached txs since they may have memos embedded
            for (const auto& sa : login_data["subaccounts"]) {
                m_cache->delete_transactions(sa["pointer"]);
            }
        }

        get_cached_client_blob(server_hmac);

        if (is_blob_on_server) {
            // The server has a blob for this wallet. If we haven't got an
            // up to date copy of it loaded yet, do so.
            if (!is_initial_login && m_blob_hmac != server_hmac) {
                // Re-login, and our blob has been updated on the server: re-load below
                m_blob_hmac.clear();
            }
            if (m_blob_hmac.empty()) {
                // No cached blob, or our cached blob is out of date:
                // Load the latest blob from the server and cache it
                load_client_blob(locker, true);
            }
            GDK_RUNTIME_ASSERT(!m_blob_hmac.empty()); // Must have a client blob from this point
        }

        if (is_initial_login) {
            m_cache->update_to_latest_minor_version();
        }
        m_cache->save_db();

        constexpr bool watch_only = false;
        return on_post_login(locker, login_data, root_bip32_xpub, watch_only, is_initial_login);
    }

    void ga_session::subscribe_all(session_impl::locker_t& locker)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        const std::string receiving_id = m_login_data["receiving_id"];

        unique_unlock unlocker(locker);
        const bool is_initial = true;
        m_wamp->subscribe(
            "com.greenaddress.tickers", [this](nlohmann::json event) { on_new_tickers(event); }, is_initial);

        m_wamp->subscribe("com.greenaddress.cbs.wallet_" + receiving_id, [this](nlohmann::json event) {
            const uint64_t seq = event.at("sequence");
            if (seq != 0) {
                // Ignore client blobs whose sequence numbers we don't understand
                GDK_LOG_SEV(log_level::warning) << "Unexpected client blob sequence " << seq;
                return;
            }
            locker_t notify_locker(m_mutex);
            // Check the hmac as we will be notified of our own changes
            // when more than one session is logged in at a time.
            if (m_blob_hmac != json_get_value(event, "hmac")) {
                // Another session has updated our client blob, mark it dirty.
                m_blob_outdated = true;
            }
        });

        m_wamp->subscribe("com.greenaddress.txs.wallet_" + receiving_id, [this](nlohmann::json event) {
            if (!ignore_tx_notification(event)) {
                std::vector<uint32_t> subaccounts = cleanup_tx_notification(event);
                on_new_transaction(subaccounts, event);
            }
        });

        m_wamp->subscribe("com.greenaddress.blocks", [this](nlohmann::json event) { on_new_block(event, false); });
    }

    void ga_session::get_cached_client_blob(const std::string& server_hmac)
    {
        if (m_blob_hmac.empty()) {
            // Load our client blob from from the cache if we have one
            std::string db_hmac;
            if (m_watch_only) {
                m_cache->get_key_value("client_blob_hmac", { [&db_hmac](const auto& db_blob) {
                    if (db_blob) {
                        db_hmac.assign(db_blob->begin(), db_blob->end());
                    }
                } });
            }
            m_cache->get_key_value("client_blob", { [this, &db_hmac, &server_hmac](const auto& db_blob) {
                if (db_blob) {
                    GDK_RUNTIME_ASSERT(m_watch_only || m_blob_hmac_key != boost::none);
                    if (!m_watch_only) {
                        db_hmac = client_blob::compute_hmac(m_blob_hmac_key.get(), *db_blob);
                    }
                    if (db_hmac == server_hmac) {
                        // Cached blob is current, load it
                        m_blob.load(*m_blob_aes_key, *db_blob);
                        m_blob_hmac = server_hmac;
                    }
                }
            } });
        }
    }

    void ga_session::load_client_blob(session_impl::locker_t& locker, bool encache)
    {
        // Load the latest blob from the server
        GDK_LOG_SEV(log_level::info) << "Fetching client blob from server";
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        auto ret = wamp_cast_json(m_wamp->call(locker, "login.get_client_blob", 0));
        const auto server_blob = base64_to_bytes(ret["blob"]);
        if (!m_watch_only) {
            // Verify the servers hmac
            auto server_hmac = client_blob::compute_hmac(*m_blob_hmac_key, server_blob);
            GDK_RUNTIME_ASSERT_MSG(server_hmac == ret["hmac"], "Bad server client blob");
        }
        m_blob.load(*m_blob_aes_key, server_blob);

        if (encache) {
            encache_client_blob(locker, server_blob, ret["hmac"]);
        }
        m_blob_hmac = ret["hmac"];
        m_blob_outdated = false; // Blob is now current with the servers view
    }

    bool ga_session::save_client_blob(session_impl::locker_t& locker, const std::string& old_hmac)
    {
        // Generate our encrypted blob + hmac, store on the server, cache locally
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(m_blob_aes_key != boost::none);
        GDK_RUNTIME_ASSERT(m_blob_hmac_key != boost::none);

        const auto saved{ m_blob.save(*m_blob_aes_key, *m_blob_hmac_key) };
        auto blob_b64{ base64_string_from_bytes(saved.first) };

        auto result = m_wamp->call(locker, "login.set_client_blob", blob_b64.get(), 0, saved.second, old_hmac);
        blob_b64.reset();
        if (!wamp_cast<bool>(result)) {
            // Raced with another update on the server, caller should try again
            GDK_LOG_SEV(log_level::info) << "Save client blob race, retrying";
            return false;
        }
        // Blob has been saved on the server, cache it locally
        encache_client_blob(locker, saved.first, saved.second);
        m_blob_hmac = saved.second;
        m_blob_outdated = false; // Blob is now current with the servers view
        return true;
    }

    void ga_session::encache_client_blob(
        session_impl::locker_t& locker, const std::vector<unsigned char>& data, const std::string& hmac)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        m_cache->upsert_key_value("client_blob", data);
        if (m_watch_only) {
            m_cache->upsert_key_value("client_blob_hmac", ustring_span(hmac));
        }
        m_cache->save_db();
    }

    template <typename T> static bool set_optional_member(boost::optional<T>& member, T&& new_value)
    {
        // Allow changing the value only if it is not already set
        GDK_RUNTIME_ASSERT(member == boost::none || member == new_value);
        if (member == boost::none) {
            member.emplace(std::move(new_value));
            return true;
        }
        return false;
    }

    void ga_session::set_local_encryption_keys(const pub_key_t& public_key, std::shared_ptr<signer> signer)
    {
        locker_t locker(m_mutex);
        set_local_encryption_keys_impl(locker, public_key, signer);
    }

    void ga_session::set_local_encryption_keys_impl(
        locker_t& locker, const pub_key_t& public_key, std::shared_ptr<signer> signer)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        if (!set_optional_member(m_local_encryption_key, pbkdf2_hmac_sha512(public_key, signer::PASSWORD_SALT))) {
            // Already set, we are re-logging in with the same credentials
            return;
        }
        if (!signer->is_watch_only()) {
            // Watch only sessions get an encrypted m_blob_aes_key from the server,
            // but don't ever get m_blob_hmac_key (they can read the blob, but
            // not save it to the server or produce a valid hmac for it).
            const auto tmp_key = pbkdf2_hmac_sha512(public_key, signer::BLOB_SALT);
            const auto tmp_span = gsl::make_span(tmp_key);
            set_optional_member(m_blob_aes_key, sha256(tmp_span.subspan(SHA256_LEN)));
            set_optional_member(m_blob_hmac_key, make_byte_array<SHA256_LEN>(tmp_span.subspan(SHA256_LEN, SHA256_LEN)));
        }
        m_cache->load_db(m_local_encryption_key.get(), signer);
        // Save the cache in case we carried forward data from a previous version
        m_cache->save_db(); // No-op if unchanged
        load_signer_xpubs(locker, signer);
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
            m_local_encryption_key = boost::none;
            m_blob.reset();
            m_blob_hmac.clear();
            m_blob_aes_key = boost::none;
            m_blob_hmac_key = boost::none;
            m_blob_outdated = false; // Blob will be reloaded if needed when login succeeds
            swap_with_default(m_limits_data);
            swap_with_default(m_twofactor_config);
            swap_with_default(m_subaccounts);
            m_ga_pubkeys.reset();
            m_user_pubkeys.reset();
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

    nlohmann::json ga_session::get_settings()
    {
        locker_t locker(m_mutex);
        return get_settings(locker);
    }

    nlohmann::json ga_session::get_settings(session_impl::locker_t& locker)
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

    nlohmann::json ga_session::get_post_login_data()
    {
        return nlohmann::json{ { "wallet_hash_id", m_login_data["wallet_hash_id"] } };
    }

    void ga_session::change_settings(const nlohmann::json& settings)
    {
        locker_t locker(m_mutex);

        nlohmann::json appearance = m_login_data["appearance"];
        remap_appearance_settings(locker, settings, appearance, true);
        cleanup_appearance_settings(locker, appearance);
        if (appearance != m_login_data["appearance"]) {
            m_login_data["appearance"] = appearance;
            push_appearance_to_server(locker);
        }

        const auto pricing_p = settings.find("pricing");
        if (pricing_p != settings.end()) {
            const std::string currency = pricing_p->value("currency", m_fiat_currency);
            const std::string exchange = pricing_p->value("exchange", m_fiat_source);
            if (currency != m_fiat_currency || exchange != m_fiat_source) {
                change_settings_pricing_source(locker, currency, exchange);
            }
        }
    }

    // Re-map settings that are erroneously inside "appearance" to the top level
    // For historic reasons certain settings have been put under appearance and the server
    // still expects to find them there, but logically they don't belong there at all so
    // a more consistent scheme is presented via the gdk
    void ga_session::remap_appearance_settings(
        session_impl::locker_t& locker, const nlohmann::json& src_json, nlohmann::json& dst_json, bool from_settings)
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

    std::string ga_session::mnemonic_from_pin_data(const nlohmann::json& pin_data)
    {
        try {
            // FIXME: clear password after use
            const auto& pin = pin_data.at("pin");
            const auto& data = pin_data.at("pin_data");
            const auto password = get_pin_password(pin, data.at("pin_identifier"));
            const std::string salt = data.at("salt");
            const auto key = pbkdf2_hmac_sha512_256(password, ustring_span(salt));

            // FIXME: clear data after use
            const auto plaintext = aes_cbc_decrypt_from_hex(key, data.at("encrypted_data"));
            const auto decrypted = nlohmann::json::parse(plaintext.begin(), plaintext.end());
            return decrypted.at("mnemonic");
        } catch (const autobahn::call_error& e) {
            GDK_LOG_SEV(log_level::warning) << "pin login failed:" << e.what();
            reset_all_session_data(false);
            throw login_error(res::id_invalid_pin);
        }
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
        const bool is_initial_login = set_signer(signer);

        locker_t locker(m_mutex);

        const bool is_liquid = m_net_params.is_liquid();
        const auto& credentials = m_signer->get_credentials();
        const std::string username = credentials.at("username");
        const std::string password = credentials.at("password");
        std::map<std::string, std::string> args;
        const auto user_agent = get_user_agent(true, m_user_agent);

        // First, try using client blob
        const auto entropy = get_wo_entropy(username, password);
        const auto u_p = get_wo_credentials(entropy);
        auto login_data = authenticate_wo(locker, u_p.first, u_p.second, user_agent, true);
        if (login_data.empty()) {
            // Client blob login failed: try a non-blob watch only login
            if (is_liquid) {
                // Liquid doesn't support non-blob watch only
                throw user_error(res::id_user_not_found_or_invalid);
            }
            login_data = authenticate_wo(locker, username, password, user_agent, false);
        }

        if (!is_initial_login) {
            // Re-login. Discard all cached data which may be out of date
            reset_cached_session_data(locker);
        }

        const auto encryption_key = get_wo_local_encryption_key(entropy, login_data.at("cache_password"));

        set_local_encryption_keys_impl(locker, encryption_key, signer);
        const std::string wo_blob_key_hex = json_get_value(login_data, "wo_blob_key");
        if (!wo_blob_key_hex.empty()) {
            auto decrypted_key = decrypt_wo_blob_key(entropy, wo_blob_key_hex);
            set_optional_member(m_blob_aes_key, std::move(decrypted_key));
        }

        const std::string server_hmac = login_data["client_blob_hmac"];
        const bool is_blob_on_server = !client_blob::is_zero_hmac(server_hmac);
        if (is_blob_on_server) {
            get_cached_client_blob(server_hmac);
        }

        if (is_blob_on_server && m_blob_aes_key != boost::none) {
            // The server has a blob for this wallet. If we haven't got an
            // up to date copy of it loaded yet, do so.
            if (!is_initial_login && m_blob_hmac != server_hmac) {
                // Re-login, and our blob has been updated on the server: re-load below
                m_blob_hmac.clear();
            }
            if (m_blob_hmac.empty()) {
                // No cached blob, or our cached blob is out of date:
                // Load the latest blob from the server and cache it
                load_client_blob(locker, true);
            }
            GDK_RUNTIME_ASSERT(!m_blob_hmac.empty()); // Must have a client blob from this point
        }

        std::string root_bip32_xpub;
        if (!m_blob_hmac.empty()) {
            // Load any locally cached xpubs, then from the client blob.
            // If the client blob values differ from the cached values,
            // cache_bip32_xpub will throw.
            load_signer_xpubs(locker, m_signer);
            const auto blob_xpubs = m_blob.get_xpubs();
            for (auto& item : blob_xpubs.items()) {
                // Inverted: See encache_signer_xpubs()
                m_signer->cache_bip32_xpub(item.value(), item.key());
            }
            root_bip32_xpub = m_signer->get_bip32_xpub({});
            GDK_RUNTIME_ASSERT(!root_bip32_xpub.empty());
        }

        if (is_liquid) {
            std::string blinding_key_hex;
            bool denied;
            std::tie(blinding_key_hex, denied) = get_cached_master_blinding_key();
            GDK_RUNTIME_ASSERT(!blinding_key_hex.empty() && !denied);
            m_signer->set_master_blinding_key(blinding_key_hex);
        }

        constexpr bool watch_only = true;
        auto ret = on_post_login(locker, login_data, root_bip32_xpub, watch_only, is_initial_login);

        // Note that locker is unlocked at this point
        if (m_blob_aes_key != boost::none) {
            const auto subaccount_pointers = get_subaccount_pointers();
            std::vector<std::string> bip32_xpubs;
            bip32_xpubs.reserve(subaccount_pointers.size());
            for (const auto& pointer : subaccount_pointers) {
                bip32_xpubs.emplace_back(m_signer->get_bip32_xpub(get_subaccount_root_path(pointer)));
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
        GDK_RUNTIME_ASSERT(bip32_xpubs.size() == m_subaccounts.size());

        for (size_t i = 0; i < pointers.size(); ++i) {
            auto xpub = make_xpub(bip32_xpubs.at(i));
            const auto pointer = pointers.at(i);
            if (pointer == 0) {
                // Main account
                if (m_user_pubkeys) {
                    m_user_pubkeys->add_subaccount(pointer, xpub);
                } else {
                    m_user_pubkeys = std::make_unique<ga_user_pubkeys>(m_net_params, std::move(xpub));
                }
            } else {
                // Subaccount
                GDK_RUNTIME_ASSERT(m_user_pubkeys.get()); // Subaccount 0 must be first in 'pointers'
                m_user_pubkeys->add_subaccount(pointer, xpub);
            }
        }
    }

    nlohmann::json ga_session::get_fee_estimates()
    {
        const auto now = std::chrono::system_clock::now();

        locker_t locker(m_mutex);

        if (now < m_fee_estimates_ts || now - m_fee_estimates_ts > 120s) {
            // Time adjusted or more than 2 minutes old: Update
            auto fee_estimates = m_wamp->call(locker, "login.get_fee_estimates");
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
        return amount::convert_fiat_cents(fiat_cents, m_fiat_currency, m_fiat_rate);
    }

    void ga_session::ensure_full_session()
    {
        if (is_watch_only()) {
            // TODO: have a better error, and map this error when returned from the server
            throw user_error("Authentication required");
        }
    }

    bool ga_session::set_wo_credentials(const std::string& username, const std::string& password)
    {
        ensure_full_session();
        GDK_RUNTIME_ASSERT(username.empty() == password.empty());
        if (!username.empty() && username.size() < 8u) {
            throw user_error("Watch-only username must be at least 8 characters long");
        }
        if (!password.empty() && password.size() < 8u) {
            throw user_error("Watch-only password must be at least 8 characters long");
        }

        locker_t locker(m_mutex);
        if (m_blob_aes_key == boost::none) {
            // The wallet doesn't have a client blob: can only happen
            // when a 2FA reset is in progress and the wallet was
            // created before client blobs were enabled.
            throw user_error(res::id_twofactor_reset_in_progress);
        }

        if (m_net_params.is_liquid()) {
            GDK_RUNTIME_ASSERT_MSG(
                m_signer->has_master_blinding_key(), "Master blinding key must be exported to enable watch-only");
        }

        // Set watch only data in the client blob. Blanks the username if disabling.
        const auto signer_xpubs = get_signer_xpubs_json(m_signer);
        update_blob(locker, std::bind(&client_blob::set_wo_data, &m_blob, username, signer_xpubs));

        std::pair<std::string, std::string> u_p{ username, password };
        std::string wo_blob_key_hex;

        if (!username.empty()) {
            // Enabling watch only login.
            // Derive the username/password to use, encrypt the client blob key for upload
            const auto entropy = get_wo_entropy(username, password);
            u_p = get_wo_credentials(entropy);
            wo_blob_key_hex = encrypt_wo_blob_key(entropy, m_blob_aes_key.get());
        }
        locker.unlock();
        return wamp_cast<bool>(m_wamp->call("addressbook.sync_custom", u_p.first, u_p.second, wo_blob_key_hex));
    }

    std::string ga_session::get_wo_username()
    {
        locker_t locker(m_mutex);
        if (m_blob_aes_key != boost::none) {
            // Client blob watch only; return from the client blob,
            // since the server doesn't know our real username.
            const auto username = m_blob.get_wo_username();
            if (m_watch_only || m_net_params.is_liquid() || !username.empty()) {
                return username;
            }
            // If the username is blank, attempt to fetch from the
            // server, we have a non-client blob watch only (or no
            // watch only set up).
        }
        locker.unlock();
        const auto result = wamp_cast_json(m_wamp->call("addressbook.get_sync_status"));
        return json_get_value(result, "username");
    }

    // Idempotent
    bool ga_session::remove_account(const nlohmann::json& twofactor_data)
    {
        return wamp_cast<bool>(m_wamp->call("login.remove_account", mp_cast(twofactor_data).get()));
    }

    nlohmann::json ga_session::get_subaccounts()
    {
        // TODO: implement refreshing for multisig
        locker_t locker(m_mutex);
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

    nlohmann::json ga_session::get_subaccount(uint32_t subaccount)
    {
        locker_t locker(m_mutex);
        const auto p = m_subaccounts.find(subaccount);
        GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");
        return p->second;
    }

    void ga_session::rename_subaccount(uint32_t subaccount, const std::string& new_name)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT_MSG(!is_twofactor_reset_active(locker), "Wallet is locked");

        const auto p = m_subaccounts.find(subaccount);
        GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");
        const std::string old_name = json_get_value(p->second, "name");
        if (old_name != new_name) {
            nlohmann::json empty;
            update_blob(locker, std::bind(&client_blob::set_subaccount_name, &m_blob, subaccount, new_name, empty));
            // Look up our subaccount again as iterators may have been invalidated
            m_subaccounts.find(subaccount)->second["name"] = new_name;
        }
    }

    void ga_session::set_subaccount_hidden(uint32_t subaccount, bool is_hidden)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT_MSG(!is_twofactor_reset_active(locker), "Wallet is locked");

        const auto p = m_subaccounts.find(subaccount);
        GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");
        const bool old_hidden = json_get_value(p->second, "hidden", false);
        if (old_hidden != is_hidden) {
            update_blob(locker, std::bind(&client_blob::set_subaccount_hidden, &m_blob, subaccount, is_hidden));
            // Look up our subaccount again as iterators may have been invalidated
            m_subaccounts.find(subaccount)->second["hidden"] = is_hidden;
        }
    }

    nlohmann::json ga_session::insert_subaccount(session_impl::locker_t& locker, uint32_t subaccount,
        const std::string& name, const std::string& receiving_id, const std::string& recovery_pub_key,
        const std::string& recovery_chain_code, const std::string& recovery_xpub, const std::string& type,
        uint32_t required_ca, bool is_hidden)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(m_signer != nullptr);

        GDK_RUNTIME_ASSERT(m_subaccounts.find(subaccount) == m_subaccounts.end());
        GDK_RUNTIME_ASSERT(type == "2of2" || type == "2of3" || type == "2of2_no_recovery");

        // FIXME: replace "pointer" with "subaccount"; pointer should only be used
        // for the final path element in a derivation
        const auto policy_asset = m_net_params.is_liquid() ? m_net_params.policy_asset() : std::string("btc");
        nlohmann::json sa = { { "name", name }, { "pointer", subaccount }, { "receiving_id", receiving_id },
            { "type", type }, { "recovery_pub_key", recovery_pub_key }, { "recovery_chain_code", recovery_chain_code },
            { "recovery_xpub", recovery_xpub }, { "required_ca", required_ca }, { "hidden", is_hidden } };
        m_subaccounts[subaccount] = sa;

        if (subaccount != 0) {
            // Add user and recovery pubkeys for the subaccount
            if (m_user_pubkeys && !m_user_pubkeys->have_subaccount(subaccount)) {
                const std::vector<uint32_t> path{ harden(3), harden(subaccount) };
                // TODO: Investigate whether this code path can ever execute
                m_user_pubkeys->add_subaccount(subaccount, make_xpub(m_signer->get_bip32_xpub(path)));
            }

            if (m_recovery_pubkeys != nullptr && !recovery_chain_code.empty()) {
                m_recovery_pubkeys->add_subaccount(subaccount, make_xpub(recovery_chain_code, recovery_pub_key));
            }
        }

        return sa;
    }

    uint32_t ga_session::get_next_subaccount(const std::string& type)
    {
        if ((type != "2of2" && type != "2of3" && type != "2of2_no_recovery")
            || (type == "2of2_no_recovery" && !m_net_params.is_liquid())) {
            throw user_error("Invalid account type");
        }
        locker_t locker(m_mutex);
        const uint32_t subaccount = m_next_subaccount;
        ++m_next_subaccount;
        return subaccount;
    }

    nlohmann::json ga_session::create_subaccount(
        const nlohmann::json& details, uint32_t subaccount, const std::string& xpub)
    {
        const std::string name = details.at("name");
        const std::string type = details.at("type");
        std::string recovery_bip32_xpub = json_get_value(details, "recovery_xpub");
        std::string recovery_pub_key;
        std::string recovery_chain_code;

        std::vector<std::string> xpubs{ { xpub } };
        std::vector<std::string> sigs{ { std::string() } };

        GDK_RUNTIME_ASSERT(subaccount < 16384u); // Disallow more than 16k subaccounts

        if (type == "2of3") {
            xpubs.emplace_back(recovery_bip32_xpub);
            sigs.emplace_back(details.at("recovery_key_sig"));

            const xpub_t recovery_xpub = make_xpub(recovery_bip32_xpub);
            recovery_chain_code = b2h(recovery_xpub.first);
            recovery_pub_key = b2h(recovery_xpub.second);
        }

        const auto recv_id
            = wamp_cast(m_wamp->call("txs.create_subaccount_v2", subaccount, std::string(), type, xpubs, sigs));

        locker_t locker(m_mutex);
        m_user_pubkeys->add_subaccount(subaccount, make_xpub(xpub));
        constexpr uint32_t required_ca = 0;
        constexpr bool is_hidden = false;
        nlohmann::json subaccount_details = insert_subaccount(locker, subaccount, name, recv_id, recovery_pub_key,
            recovery_chain_code, recovery_bip32_xpub, type, required_ca, is_hidden);

        if (type == "2of3") {
            subaccount_details["recovery_xpub"] = recovery_bip32_xpub;
        }
        const auto signer_xpubs = get_signer_xpubs_json(m_signer);
        update_blob(locker, std::bind(&client_blob::set_subaccount_name, &m_blob, subaccount, name, signer_xpubs));
        return subaccount_details;
    }

    void ga_session::update_blob(locker_t& locker, std::function<bool()> update_fn)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(!m_watch_only);

        while (true) {
            if (!m_blob_outdated) {
                // Our blob is current with the server; try to update
                if (!update_fn()) {
                    // The update was a no-op; nothing to do
                    return;
                }
                if (save_client_blob(locker, m_blob_hmac)) {
                    break;
                }
            }
            // Our blob was known to be outdated, or saving to the server failed:
            // Re-load the up-to-date blob from the server and re-try
            load_client_blob(locker, false);
        }
    }

    std::pair<std::string, bool> ga_session::get_cached_master_blinding_key()
    {
        const bool denied = m_blob.is_master_blinding_key_denied();
        const auto blinding_key_hex = denied ? std::string() : m_blob.get_master_blinding_key();
        return std::make_pair(blinding_key_hex, denied);
    }

    void ga_session::set_cached_master_blinding_key(const std::string& master_blinding_key_hex)
    {
        session_impl::set_cached_master_blinding_key(master_blinding_key_hex);
        // Note: this update is a no-op if the key is already cached
        locker_t locker(m_mutex);
        update_blob(locker, std::bind(&client_blob::set_master_blinding_key, &m_blob, master_blinding_key_hex));
    }

    void ga_session::encache_signer_xpubs(std::shared_ptr<signer> signer)
    {
        locker_t locker(m_mutex);
        const auto signer_xpubs = get_signer_xpubs_json(signer);
        m_cache->upsert_key_value("xpubs", nlohmann::json::to_msgpack(signer_xpubs));
        m_cache->save_db();
    }

    void ga_session::load_signer_xpubs(session_impl::locker_t& locker, std::shared_ptr<signer> signer)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(signer.get());
        m_cache->get_key_value("xpubs", { [&signer](const auto& db_blob) {
            if (db_blob) {
                try {
                    auto cached = nlohmann::json::from_msgpack(db_blob.get().begin(), db_blob.get().end());
                    for (auto& item : cached.items()) {
                        // Inverted: See encache_signer_xpubs()
                        signer->cache_bip32_xpub(item.value(), item.key());
                    }
                    GDK_LOG_SEV(log_level::debug) << "Loaded " << cached.size() << " cached xpubs";
                } catch (const std::exception& e) {
                    GDK_LOG_SEV(log_level::warning) << "Error reading xpubs: " << e.what();
                }
            }
        } });
    }

    // Idempotent
    template <typename T>
    void ga_session::change_settings(const std::string& key, const T& value, const nlohmann::json& twofactor_data)
    {
        auto result = m_wamp->call("login.change_settings", key, value, mp_cast(twofactor_data).get());
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));
    }

    void ga_session::change_settings_limits(const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        change_settings("tx_limits", mp_cast(details).get(), twofactor_data);
        locker_t locker(m_mutex);
        update_spending_limits(locker, details);
    }

    void ga_session::change_settings_pricing_source(const std::string& currency, const std::string& exchange)
    {
        locker_t locker(m_mutex);
        return change_settings_pricing_source(locker, currency, exchange);
    }

    void ga_session::change_settings_pricing_source(
        session_impl::locker_t& locker, const std::string& currency, const std::string& exchange)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        auto fiat_rate = wamp_cast_nil(m_wamp->call(locker, "login.set_pricing_source_v2", currency, exchange));

        m_fiat_source = exchange;
        m_fiat_currency = currency;
        update_fiat_rate(locker, fiat_rate.get_value_or(std::string()));
    }

    static void remove_utxo_proofs(nlohmann::json& utxo, bool mark_unblinded)
    {
        if (mark_unblinded) {
            utxo["confidential"] = true;
            utxo.erase("error");
        }
        utxo.erase("range_proof");
        utxo.erase("surj_proof");
    }

    bool ga_session::unblind_utxo(session_impl::locker_t& locker, nlohmann::json& utxo, const std::string& for_txhash,
        unique_pubkeys_and_scripts_t& missing)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        amount::value_type value;

        if (boost::conversion::try_lexical_convert(json_get_value(utxo, "value"), value)) {
            utxo["satoshi"] = value;
            utxo["assetblinder"] = ZEROS;
            utxo["amountblinder"] = ZEROS;
            const auto asset_tag = h2b(utxo.value("asset_tag", m_net_params.policy_asset()));
            GDK_RUNTIME_ASSERT(asset_tag[0] == 0x1);
            utxo["asset_id"] = b2h_rev(gsl::make_span(asset_tag).subspan(1));
            utxo["confidential"] = false;
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

        const auto script = h2b(utxo.at("script"));
        const bool has_address = !json_get_value(utxo, "address").empty();

        if (!txhash.empty()) {
            const auto cached = m_cache->get_liquid_output(h2b(txhash), pt_idx);
            if (!cached.empty()) {
                utxo.update(cached.begin(), cached.end());
                constexpr bool mark_unblinded = true;
                remove_utxo_proofs(utxo, mark_unblinded);
                if (has_address) {
                    // We should now be able to blind the address
                    const auto blinding_pubkey = m_cache->get_liquid_blinding_pubkey(script);
                    GDK_RUNTIME_ASSERT(!blinding_pubkey.empty());
                    blind_address(m_net_params, utxo, b2h(blinding_pubkey));
                }

                return false; // Cache not updated
            }
        }
        const auto rangeproof = h2b(utxo.at("range_proof"));
        const auto commitment = h2b(utxo.at("commitment"));
        const auto nonce_commitment = h2b(utxo.at("nonce_commitment"));
        const auto asset_tag = h2b(utxo.at("asset_tag"));

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
        } catch (const std::exception& ex) {
            nonce = get_alternate_blinding_nonce(locker, utxo, nonce_commitment);
            if (!nonce.empty()) {
                // Try the alternate nonce
                try {
                    unblinded = asset_unblind_with_nonce(nonce, rangeproof, commitment, script, asset_tag);
                } catch (const std::exception& ex) {
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
        constexpr bool mark_unblinded = true;
        remove_utxo_proofs(utxo, mark_unblinded);

        bool updated_blinding_cache = false;
        if (!txhash.empty()) {
            m_cache->insert_liquid_output(h2b(txhash), pt_idx, utxo);
            updated_blinding_cache = true;
        }

        if (has_address) {
            // We should now be able to blind the address
            const auto blinding_pubkey = m_cache->get_liquid_blinding_pubkey(script);
            GDK_RUNTIME_ASSERT(!blinding_pubkey.empty());
            blind_address(m_net_params, utxo, b2h(blinding_pubkey));
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

        const auto p = m_subaccounts.find(utxo.at("subaccount"));
        GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");
        if (p->second.at("type") != "2of2_no_recovery" || p->second.at("pointer") > 20u) {
            return {}; // Only used for first 20 2of2_no_recovery addrs
        }

        auto alt_utxo = utxo;
        alt_utxo["pointer"] = 1u; // Alt key is derived from the initial addr
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
            const bool is_external = !json_get_value(utxo, "private_key").empty();

            auto address_type_p = utxo.find("address_type");
            if (is_liquid && utxo.value("error", std::string()) == "missing blinding nonce") {
                // UTXO was previously processed but could not be unblinded: try again
                updated_blinding_cache |= unblind_utxo(locker, utxo, for_txhash, missing);
                if (!utxo.contains("error")) {
                    utxo.erase("value"); // Only remove value if we unblinded it
                }
            } else if (address_type_p == utxo.end()) {
                // This UTXO has not been processed yet
                const script_type utxo_script_type = utxo["script_type"];

                // Address type is non-blank for spendable UTXOs
                std::string addr_type;
                switch (utxo_script_type) {
                case script_type::ga_p2sh_p2wsh_csv_fortified_out:
                case script_type::ga_redeem_p2sh_p2wsh_csv_fortified:
                    addr_type = address_type::csv;
                    break;
                case script_type::ga_p2sh_p2wsh_fortified_out:
                case script_type::ga_redeem_p2sh_p2wsh_fortified:
                    addr_type = address_type::p2wsh;
                    break;
                case script_type::ga_p2sh_fortified_out:
                case script_type::ga_redeem_p2sh_fortified:
                    addr_type = address_type::p2sh;
                    break;
                case script_type::ga_pubkey_hash_out:
                    if (is_external) {
                        // UTXO generated by sweeping, so its spendable
                        addr_type = address_type::p2pkh;
                    }
                    break;
                }

                if (is_external) {
                    json_rename_key(utxo, "tx_hash", "txhash");
                    json_rename_key(utxo, "tx_pos", "pt_idx");
                    utxo["satoshi"] = json_get_value<amount::value_type>(utxo, "value");
                } else {
                    if (is_liquid) {
                        if (json_get_value(utxo, "is_relevant", true)) {
                            updated_blinding_cache |= unblind_utxo(locker, utxo, for_txhash, missing);
                        } else {
                            constexpr bool mark_unblinded = false;
                            remove_utxo_proofs(utxo, mark_unblinded);
                        }
                    } else {
                        amount::value_type value;
                        GDK_RUNTIME_ASSERT(
                            boost::conversion::try_lexical_convert(json_get_value(utxo, "value"), value));
                        utxo["satoshi"] = value;
                    }
                }
                if (!utxo.contains("error")) {
                    utxo.erase("value"); // Only remove value if we unblinded it
                }
                utxo.erase("ga_asset_id");
                auto block_height = utxo.find("block_height");
                if (block_height != utxo.end() && block_height->is_null()) {
                    *block_height = 0;
                }
                json_add_if_missing(utxo, "subtype", 0u);
                json_add_if_missing(utxo, "is_internal", false);
                utxo["address_type"] = addr_type;
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
        GDK_LOG_SEV(TX_CACHE_LEVEL) << "Tx sync(" << subaccount << "): latest timestamp = " << timestamp;

        if (m_synced_subaccounts.count(subaccount)) {
            // We know our cache is up to date, avoid going to the server
            GDK_LOG_SEV(TX_CACHE_LEVEL) << "Tx sync(" << subaccount << "): already synced";
            return { { "list", nlohmann::json::array() }, { "more", false }, { "sync_ts", timestamp } };
        }

        // Get a page of txs from the server if any are newer than our last cached one
        auto result = m_wamp->call(locker, "txs.get_list_v3", subaccount, timestamp);
        nlohmann::json ret = wamp_cast_json(result);
        GDK_LOG_SEV(TX_CACHE_LEVEL) << "Tx sync(" << subaccount << "): server returned " << ret["list"].size()
                                    << " txs, more = " << ret["more"];

        auto& txs = ret["list"];
        // TODO: Return rejected txs to the caller
        auto&& filter = [](const auto& tx) -> bool { return tx.contains("rejected") || tx.contains("replaced"); };
        txs.erase(std::remove_if(txs.begin(), txs.end(), filter), txs.end());

        for (auto& tx : txs) {
            tx.erase("created_at"); // TODO: Remove once the server stops returning this

            // Compute the tx weight and fee rate
            const uint32_t tx_vsize = tx.at("transaction_vsize");
            tx["transaction_weight"] = tx_vsize * 4;
            // fee_rate is in satoshi/kb, with the best integer accuracy we have
            tx["fee_rate"] = tx.at("fee").get<amount::value_type>() * 1000 / tx_vsize;
            tx["user_signed"] = true;
            tx["server_signed"] = true;

            // Clean up and categorize the endpoints. For liquid, this populates
            // 'missing' if any UTXOs require blinding nonces from the signer to unblind.
            cleanup_utxos(locker, tx.at("eps"), tx.at("txhash"), missing);
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
            GDK_LOG_SEV(TX_CACHE_LEVEL) << "Tx sync(" << subaccount << ") disrupted: " << txs["sync_ts"]
                                        << " != " << timestamp;
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

            std::map<std::string, amount> received, spent;
            std::map<uint32_t, nlohmann::json> in_map, out_map;
            std::set<std::string> unique_asset_ids;

            if (is_liquid) {
                // Ublind, clean up and categorize the endpoints
                cleanup_utxos(locker, tx_details["eps"], txhash, missing);
            }

            for (auto& ep : tx_details["eps"]) {
                const bool is_tx_output = ep.at("is_output");
                const bool is_relevant = ep.at("is_relevant");

                if (is_relevant && ep.find("error") == ep.end()) {
                    const auto asset_id = asset_id_from_json(m_net_params, ep);
                    unique_asset_ids.emplace(asset_id);

                    // Compute the effect of the input/output on the wallets balance
                    // TODO: Figure out what redeemable value for social payments is about
                    const amount::value_type satoshi = ep.at("satoshi");

                    auto& which_balance = is_tx_output ? received[asset_id] : spent[asset_id];
                    which_balance += satoshi;
                }

                ep["addressee"] = std::string(); // default here, set below where needed

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
            tx_details.erase("eps");

            GDK_RUNTIME_ASSERT(is_liquid || (unique_asset_ids.size() == 1 && *unique_asset_ids.begin() == "btc"));

            // TODO: improve the detection of tx type.
            bool net_positive = false;
            bool net_positive_set = false;
            for (const auto& asset_id : unique_asset_ids) {
                const auto net_received = received[asset_id];
                const auto net_spent = spent[asset_id];
                const auto asset_net_positive = net_received > net_spent;
                if (net_positive_set) {
                    GDK_RUNTIME_ASSERT_MSG(net_positive == asset_net_positive, "Ambiguous tx direction");
                } else {
                    net_positive = asset_net_positive;
                    net_positive_set = true;
                }
                const amount total = net_positive ? net_received - net_spent : net_spent - net_received;
                tx_details["satoshi"][asset_id] = total.value();
            }

            const bool is_confirmed = tx_block_height != 0;

            std::vector<std::string> addressees;
            if (is_liquid && unique_asset_ids.empty()) {
                // Failed to unblind all relevant inputs and outputs. This
                // might be a spam transaction.
                tx_details["type"] = "not unblindable";
                tx_details["can_rbf"] = false;
                tx_details["can_cpfp"] = false;
            } else if (net_positive) {
                for (auto& ep : tx_details["inputs"]) {
                    std::string addressee;
                    if (!json_get_value(ep, "is_relevant", false)) {
                        // Add unique addressees that aren't ourselves
                        addressee = json_get_value(ep, "social_source");
                        if (addressee.empty()) {
                            addressee = json_get_value(ep, "address");
                        }
                        if (std::find(std::begin(addressees), std::end(addressees), addressee)
                            == std::end(addressees)) {
                            addressees.emplace_back(addressee);
                        }
                        ep["addressee"] = addressee;
                    }
                }
                tx_details["type"] = "incoming";
                tx_details["can_rbf"] = false;
                tx_details["can_cpfp"] = !is_confirmed;
            } else {
                for (auto& ep : tx_details["outputs"]) {
                    if (is_liquid && json_get_value(ep, "script").empty()) {
                        continue;
                    }
                    std::string addressee;
                    if (!json_get_value(ep, "is_relevant", false)) {
                        // Add unique addressees that aren't ourselves
                        const auto social_destination_p = ep.find("social_destination");
                        if (social_destination_p != ep.end()) {
                            if (social_destination_p->is_object()) {
                                addressee = (*social_destination_p)["name"];
                            } else {
                                addressee = *social_destination_p;
                            }
                        } else {
                            addressee = ep["address"];
                        }

                        if (std::find(std::begin(addressees), std::end(addressees), addressee)
                            == std::end(addressees)) {
                            addressees.emplace_back(addressee);
                        }
                        ep["addressee"] = addressee;
                    }
                }
                tx_details["type"] = addressees.empty() ? "redeposit" : "outgoing";
                tx_details["can_rbf"] = !is_confirmed && json_get_value(tx_details, "rbf_optin", false);
                tx_details["can_cpfp"] = false;
            }

            tx_details["addressees"] = addressees;

            if (!sync_disrupted) {
                // Insert the tx into the DB cache now that it is cleaned up/unblinded
                const uint64_t tx_timestamp = tx_details.at("created_at_ts");
                GDK_LOG_SEV(TX_CACHE_LEVEL)
                    << "Tx sync(" << subaccount << ") inserting " << txhash << ":" << tx_timestamp;
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
        locker_t locker(m_mutex);
        if (m_blob_outdated) {
            load_client_blob(locker, true);
        }
        for (auto& tx_details : tx_list) {
            // Get the tx memo. Use the server provided value if
            // its present (i.e. no client blob enabled yet, or watch-only)
            const std::string svr_memo = json_get_value(tx_details, "memo");
            const std::string blob_memo = m_blob.get_tx_memo(tx_details["txhash"]);
            tx_details["memo"] = svr_memo.empty() ? blob_memo : svr_memo;
        }

        // Update SPV status
        const uint32_t current_block = m_last_block_notification["block_height"];
        const uint32_t num_reorg_blocks = std::min(m_net_params.get_max_reorg_blocks(), current_block);
        const uint32_t reorg_block = current_block - num_reorg_blocks;
        bool are_downloading = false;

        nlohmann::json spv_params;
        if (m_spv_enabled) {
            spv_params = get_spv_params(m_net_params, get_proxy_settings());
        }

        for (auto& tx_details : tx_list) {
            const uint32_t tx_block_height = tx_details["block_height"];
            auto& spv_verified = tx_details["spv_verified"];

            if (tx_block_height && tx_block_height < reorg_block && spv_verified == "verified") {
                continue; // Verified and committed beyond our reorg depth
            }
            if (!m_spv_enabled) {
                spv_verified = "disabled";
                continue; // Not already verified and SPV is disabled
            }
            if (!tx_block_height) {
                spv_verified = "unconfirmed";
                continue; // Need to be confirmed before we can verify
            }

            const std::string txhash_hex = tx_details["txhash"];
            spv_params["txid"] = txhash_hex;
            spv_params["height"] = tx_block_height;

            std::string spv_status;
            if (m_spv_verified_txs.count(txhash_hex)) {
                GDK_LOG_SEV(log_level::debug) << txhash_hex << " cached as verified";
                spv_status = "verified"; // Previously verified
            } else {
                spv_status = spv_get_status_string(spv_verify_tx(spv_params));
                GDK_LOG_SEV(log_level::debug) << txhash_hex << " status " << spv_status;
            }
            if (!are_downloading && spv_status == "in_progress") {
                // Start syncing headers for SPV if we aren't already doing it
                constexpr bool do_start = true;
                download_headers_ctl(locker, do_start);
                are_downloading = true;
            }
            if (spv_status == "verified") {
                if (tx_block_height < reorg_block) {
                    // Verified and committed beyond our reorg depth, update the cache
                    m_cache->set_transaction_spv_verified(txhash_hex);
                } else {
                    // Not committed beyond reorg depth: cache in memory only
                    m_spv_verified_txs.insert(txhash_hex);
                }
            }
            spv_verified = std::move(spv_status);
        }
        m_cache->save_db(); // No-op if unchanged
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
            GDK_LOG_SEV(TX_CACHE_LEVEL) << "Tx sync(" << subaccount
                                        << ") disrupted before fetch: " << details["sync_ts"] << " != " << timestamp;
            // Note we don't need to update m_synced_subaccounts here as
            // the caller will re-iterate to sync
            return nlohmann::json(false);
        }

        m_cache->get_transactions(subaccount, first, count,
            { [&result](uint64_t /*ts*/, const std::string& /*txhash*/, uint32_t /*block*/, uint32_t /*spent*/,
                  uint32_t spv_status, nlohmann::json& tx_json) {
                tx_json["spv_verified"] = spv_get_status_string(spv_status);
                result.emplace_back(std::move(tx_json));
            } });

        return nlohmann::json(std::move(result));
    }

    amount ga_session::get_dust_threshold() const
    {
        locker_t locker(m_mutex);
        const amount::value_type v = m_login_data.at("dust");
        return amount(v);
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

    void ga_session::encache_scriptpubkey_data(byte_span_t scriptpubkey, uint32_t subaccount, uint32_t branch,
        uint32_t pointer, uint32_t subtype, uint32_t script_type)
    {
        locker_t locker(m_mutex);
        m_cache->insert_scriptpubkey_data(scriptpubkey, subaccount, branch, pointer, subtype, script_type);
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
                const auto scriptpubkey = scriptpubkey_from_address(m_net_params, address.at("address"), false);
                const uint32_t branch = json_get_value(address, "branch", 1);
                const uint32_t pointer = address.at("pointer");
                const uint32_t subtype = json_get_value(address, "subtype", 0);
                const uint32_t script_type = address.at("script_type");
                encache_scriptpubkey_data(scriptpubkey, subaccount, branch, pointer, subtype, script_type);
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

    nlohmann::json ga_session::psbt_get_details(const nlohmann::json& details)
    {
        const bool is_liquid = m_net_params.is_liquid();
        const std::string tx_hex = psbt_extract_tx(details.at("psbt"));
        const auto flags = tx_flags(is_liquid);
        wally_tx_ptr tx = tx_from_hex(tx_hex, flags);

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

    nlohmann::json ga_session::get_unspent_outputs(const nlohmann::json& details, unique_pubkeys_and_scripts_t& missing)
    {
        const uint32_t subaccount = details.at("subaccount");
        const uint32_t num_confs = details.at("num_confs");
        const bool all_coins = json_get_value(details, "all_coins", false);

        auto utxos
            = wamp_cast_json(m_wamp->call("txs.get_all_unspent_outputs", num_confs, subaccount, "any", all_coins));
        locker_t locker(m_mutex);
        if (cleanup_utxos(locker, utxos, std::string(), missing)) {
            m_cache->save_db(); // Cache was updated; save it
        }

        // Compute the locktime of our UTXOs locally where we can
        bool need_nlocktime_info = false;
        for (auto& utxo : utxos) {
            if (utxo["address_type"] != address_type::csv) {
                // We must get the nlocktime information from the server for this UTXO
                need_nlocktime_info = true;
            } else {
                const uint32_t block_height = utxo["block_height"];
                if (block_height != 0) {
                    // CSV nlocktime is relative to the block the tx confirmed in
                    const uint32_t csv_blocks = utxo["subtype"];
                    GDK_RUNTIME_ASSERT(csv_blocks != 0);
                    utxo["expiry_height"] = block_height + csv_blocks;
                }
            }
        }

        if (need_nlocktime_info) {
            // For non-CSV UTXOs, use nlocktime data provided by the server
            const auto nlocktimes = update_nlocktime_info(locker);
            if (nlocktimes && !nlocktimes->empty()) {
                for (auto& utxo : utxos) {
                    const uint32_t vout = utxo.at("pt_idx");
                    const std::string k{ json_get_value(utxo, "txhash") + ":" + std::to_string(vout) };
                    const auto it = nlocktimes->find(k);
                    if (it != nlocktimes->end()) {
                        utxo["expiry_height"] = it->second.at("nlocktime_at");
                    }
                }
            }
        }
        return utxos;
    }

    void ga_session::process_unspent_outputs(nlohmann::json& utxos)
    {
        if (m_net_params.is_liquid()) {
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
                const auto utxo_asset_id = asset_id_from_json(m_net_params, utxo);
                asset_utxos[utxo_asset_id].emplace_back(utxo);
            }
        }

        // Sort the UTXOs such that the oldest are first, with the default
        // UTXO selection strategy this reduces the number of re-deposits
        // users have to do by recycling UTXOs that are closer to expiry.
        // This also reduces the chance of spending unconfirmed outputs by
        // pushing them to the end of the selection array.
        std::for_each(std::begin(asset_utxos), std::end(asset_utxos), [](nlohmann::json& utxos) {
            std::sort(std::begin(utxos), std::end(utxos), [](const nlohmann::json& lhs, const nlohmann::json& rhs) {
                const uint32_t lbh = lhs["block_height"];
                const uint32_t rbh = rhs["block_height"];
                if (lbh == 0) {
                    return false;
                }
                if (rbh == 0) {
                    return true;
                }
                return lbh < rbh;
            });
        });

        utxos.swap(asset_utxos);
    }

    // Idempotent
    nlohmann::json ga_session::get_unspent_outputs_for_private_key(
        const std::string& private_key, const std::string& password, uint32_t unused)
    {
        // Unused will be used in the future to support specifying the address type if
        // it can't be determined from the private_key format
        GDK_RUNTIME_ASSERT(unused == 0);

        std::vector<unsigned char> private_key_bytes;
        bool compressed;
        std::tie(private_key_bytes, compressed)
            = to_private_key_bytes(private_key, password, m_net_params.is_main_net());
        auto public_key_bytes = ec_public_key_from_private_key(gsl::make_span(private_key_bytes));
        if (!compressed) {
            public_key_bytes = ec_public_key_decompress(public_key_bytes);
        }
        const auto script_bytes = scriptpubkey_p2pkh_from_hash160(hash160(public_key_bytes));
        const auto script_hash_hex = electrum_script_hash_hex(script_bytes);

        auto utxos = wamp_cast_json(m_wamp->call("vault.get_utxos_for_script_hash", script_hash_hex));
        for (auto& utxo : utxos) {
            utxo["private_key"] = b2h(private_key_bytes);
            utxo["compressed"] = compressed;
            utxo["public_key"] = b2h(public_key_bytes);
            utxo["prevout_script"] = b2h(script_bytes);
            utxo["script_type"] = script_type::ga_pubkey_hash_out;
        }

        unique_pubkeys_and_scripts_t missing; // Always empty for sweeping
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!cleanup_utxos(locker, utxos, std::string(), missing)); // Should never do unblinding
        return utxos;
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
    wally_tx_ptr ga_session::get_raw_transaction_details(const std::string& txhash_hex) const
    {
        try {
            wally_tx_ptr tx;
            const auto flags = tx_flags(m_net_params.is_liquid());
            locker_t locker(m_mutex);
            // First, try the local cache
            m_cache->get_transaction_data(txhash_hex, { [&tx, flags](const auto& db_blob) {
                if (db_blob) {
                    tx = tx_from_bin(db_blob.get(), flags);
                }
            } });
            if (tx) {
                GDK_LOG_SEV(TX_CACHE_LEVEL) << "Tx cache using cached " << txhash_hex;
            } else {
                // If not found, ask the server
                const std::string tx_data = wamp_cast(m_wamp->call(locker, "txs.get_raw_output", txhash_hex));
                tx = tx_from_hex(tx_data, flags);
                // Cache the result
                m_cache->insert_transaction_data(txhash_hex, h2b(tx_data));
            }
            return tx;
        } catch (const std::exception& e) {
            GDK_LOG_SEV(log_level::warning) << "Error fetching " << txhash_hex << " : " << e.what();
            throw user_error("Transaction not found");
        }
    }

    nlohmann::json ga_session::get_transaction_details(const std::string& txhash_hex) const
    {
        const auto tx = get_raw_transaction_details(txhash_hex);
        nlohmann::json ret = { { "txhash", txhash_hex } };
        update_tx_size_info(m_net_params, tx, ret);
        return ret;
    }

    static script_type set_addr_script_type(nlohmann::json& address, const std::string& addr_type)
    {
        // Add the script type, to allow addresses to be used interchangeably with utxos
        script_type addr_script_type;
        if (addr_type == address_type::csv) {
            addr_script_type = script_type::ga_p2sh_p2wsh_csv_fortified_out;
        } else if (addr_type == address_type::p2wsh) {
            addr_script_type = script_type::ga_p2sh_p2wsh_fortified_out;
        } else {
            addr_script_type = script_type::ga_p2sh_fortified_out;
        }
        address["script_type"] = addr_script_type;
        return addr_script_type;
    }

    void ga_session::update_address_info(nlohmann::json& address, bool is_historic)
    {
        bool old_watch_only;
        uint32_t csv_blocks;
        std::vector<uint32_t> csv_buckets;
        {
            locker_t locker(m_mutex);
            // Old (non client blob) watch only sessions cannot validate addrs
            old_watch_only = m_watch_only && m_blob_aes_key == boost::none;
            csv_blocks = m_csv_blocks;
            csv_buckets = is_historic ? m_csv_buckets : std::vector<uint32_t>();
        }

        json_rename_key(address, "ad", "address"); // Returned by wamp call get_my_addresses
        json_add_if_missing(address, "subtype", 0, true); // Convert null subtype to 0
        json_rename_key(address, "addr_type", "address_type");

        const std::string addr_type = address["address_type"];
        const script_type addr_script_type = set_addr_script_type(address, addr_type);

        // Compute the address from the script the server returned
        const auto server_script = h2b(address.at("script"));
        const auto server_address = get_address_from_script(m_net_params, server_script, addr_type);

        if (!old_watch_only) {
            // Verify the server returned script matches what we generate
            // locally from the UTXO details (and thus that the address
            // is valid)
            GDK_RUNTIME_ASSERT(server_script == output_script_from_utxo(address));
        }

        if (!address.contains("address")) {
            address["address"] = server_address;
        } else {
            // The server returned an address; It must match the address
            // generated from the script (which we verified above)
            GDK_RUNTIME_ASSERT(address["address"] == server_address);
        }

        address["user_path"] = get_subaccount_full_path(address["subaccount"], address["pointer"], false);

        if (addr_type == address_type::csv) {
            // Make sure the csv value used is in our csv buckets. If isn't,
            // coins held in such scripts may not be recoverable.
            uint32_t addr_csv_blocks = get_csv_blocks_from_csv_redeem_script(server_script);
            if (is_historic) {
                // For historic addresses only check csvtime is in our bucket
                // list, since the user may have changed their settings.
                GDK_RUNTIME_ASSERT(
                    std::find(csv_buckets.begin(), csv_buckets.end(), addr_csv_blocks) != csv_buckets.end());
            } else {
                // For new addresses, ensure that the csvtime is the users
                // current csv_blocks setting. This also ensures it is
                // one of the bucket values as a side effect.
                GDK_RUNTIME_ASSERT(addr_csv_blocks == csv_blocks);
            }
        }

        if (m_net_params.is_liquid()) {
            // we treat the script as a segwit wrapped script, which is the only supported type on Liquid at the moment
            GDK_RUNTIME_ASSERT(addr_script_type == script_type::ga_p2sh_p2wsh_csv_fortified_out
                || addr_script_type == script_type::ga_p2sh_p2wsh_fortified_out);

            address["blinding_script"] = b2h(scriptpubkey_p2sh_p2wsh_from_bytes(server_script));
            // The blinding key will be added later once fetched from the sessions signer
        }
    }

    nlohmann::json ga_session::get_previous_addresses(const nlohmann::json& details)
    {
        const uint32_t subaccount = json_get_value(details, "subaccount", 0);
        const bool get_newest = !details.contains("last_pointer") || details["last_pointer"].is_null();
        const uint32_t last_pointer = json_get_value(details, "last_pointer", 0);
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
            json_rename_key(address, "num_tx", "tx_count");
            seen_pointer = address["pointer"];
        }

        if (seen_pointer < 2) {
            return nlohmann::json{ { "list", addresses } };
        }
        return nlohmann::json{ { "last_pointer", seen_pointer }, { "list", addresses } };
    }

    nlohmann::json ga_session::get_receive_address(const nlohmann::json& details)
    {
        const uint32_t subaccount = details.value("subaccount", 0);
        const std::string addr_type_ = details.value("address_type", std::string{});

        const std::string addr_type = addr_type_.empty() ? get_default_address_type(subaccount) : addr_type_;
        GDK_RUNTIME_ASSERT_MSG(
            addr_type == address_type::p2sh || addr_type == address_type::p2wsh || addr_type == address_type::csv,
            "Unknown address type");

        constexpr bool return_pointer = true;
        auto address = wamp_cast_json(m_wamp->call("vault.fund", subaccount, return_pointer, addr_type));
        update_address_info(address, false);
        GDK_RUNTIME_ASSERT(address["address_type"] == addr_type);
        return address;
    }

    // Idempotent
    nlohmann::json ga_session::get_available_currencies() const
    {
        return wamp_cast_json(m_wamp->call("login.available_currencies"));
    }

#if 1
    // Note: Current design is to always enable RBF if the server supports
    // it, perhaps allowing disabling for individual txs or only for BIP 70
    bool ga_session::is_rbf_enabled() const
    {
        locker_t locker(m_mutex);
        return !m_net_params.is_liquid() && json_get_value(m_login_data, "rbf", true);
    }
#else
    bool ga_session::is_rbf_enabled() const
    {
        locker_t locker(m_mutex);
        return m_login_data["rbf"] && json_get_value(m_login_data["appearance"], "replace_by_fee", false);
    }
#endif

    bool ga_session::is_watch_only() const
    {
        locker_t locker(m_mutex);
        return m_watch_only;
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
        GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");
        return p->second.at("type") == "2of2"; // Only Green 2of2 subaccounts allow CSV
    }

    const std::string& ga_session::get_default_address_type(uint32_t subaccount) const
    {
        const auto appearance = get_appearance();
        if (json_get_value(appearance, "use_csv", false) && subaccount_allows_csv(subaccount)) {
            return address_type::csv;
        }
        if (json_get_value(appearance, "use_segwit", false)) {
            return address_type::p2wsh;
        }
        return address_type::p2sh;
    }

    bool ga_session::is_twofactor_reset_active(session_impl::locker_t& locker)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        return json_get_value(m_login_data, "reset_2fa_active", false);
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
            const auto config = wamp_cast_json(m_wamp->call(locker, "twofactor.get_config"));
            set_twofactor_config(locker, config);
        }
        nlohmann::json ret = m_twofactor_config;

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
            { "all_methods", std::vector<std::string>() },
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

        std::vector<std::string> enabled_methods;
        const std::vector<std::string> all_methods = m_twofactor_config["all_methods"];
        enabled_methods.reserve(all_methods.size());
        for (const auto& m : all_methods) {
            if (json_get_value(m_twofactor_config[m], "enabled", false)) {
                enabled_methods.emplace_back(m);
            }
        }
        m_twofactor_config["enabled_methods"] = enabled_methods;
        m_twofactor_config["any_enabled"] = !enabled_methods.empty();
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
        if (!config.is_boolean()) {
            if (!config.contains("gauth_url")) {
                // Copy over the existing gauth value until gauth is sorted out
                // TODO: Fix gauth so the user passes the secret
                config["gauth_url"] = json_get_value(m_twofactor_config["gauth"], "data", MASKED_GAUTH_SEED);
            }
            set_twofactor_config(locker, config);
        } else {
            // FIXME: Remove when all backends are updated
            m_twofactor_config[method] = { { "enabled", true }, { "confirmed", true }, { "data", std::string() } };
            set_enabled_twofactor_methods(locker);
        }
    }

    void ga_session::enable_gauth(const std::string& code, const nlohmann::json& twofactor_data)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        const auto config
            = wamp_cast_json(m_wamp->call(locker, "twofactor.enable_gauth", code, mp_cast(twofactor_data).get()));
        if (!config.is_boolean()) {
            set_twofactor_config(locker, config);
        } else {
            // FIXME: Remove when all backends are updated
            m_twofactor_config["gauth"] = { { "enabled", true }, { "confirmed", true }, { "data", MASKED_GAUTH_SEED } };
            set_enabled_twofactor_methods(locker);
        }
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
    nlohmann::json ga_session::set_pin(
        const std::string& mnemonic, const std::string& pin, const std::string& device_id)
    {
        ensure_full_session();

        GDK_RUNTIME_ASSERT(pin.length() >= 4);
        GDK_RUNTIME_ASSERT(!device_id.empty() && device_id.length() <= 100);

        // FIXME: secure_array
        const auto seed = bip39_mnemonic_to_seed(mnemonic);

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
        const std::string json = nlohmann::json({ { "mnemonic", mnemonic }, { "seed", b2h(seed) } }).dump();

        return { { "pin_identifier", id_and_password.front() }, { "salt", salt_b64 },
            { "encrypted_data", aes_cbc_encrypt_to_hex(key, ustring_span(json)) } };
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

    // Post-login idempotent
    ga_pubkeys& ga_session::get_ga_pubkeys()
    {
        GDK_RUNTIME_ASSERT(m_ga_pubkeys != nullptr);
        return *m_ga_pubkeys;
    }

    // Post-login idempotent
    user_pubkeys& ga_session::get_recovery_pubkeys()
    {
        GDK_RUNTIME_ASSERT_MSG(m_recovery_pubkeys != nullptr, "Cannot derive keys in watch-only mode");
        return *m_recovery_pubkeys;
    }

    std::vector<uint32_t> ga_session::get_subaccount_root_path(uint32_t subaccount)
    {
        if (m_user_pubkeys) {
            locker_t locker(m_mutex);
            return m_user_pubkeys->get_subaccount_root_path(subaccount);
        }
        return ga_user_pubkeys::get_ga_subaccount_root_path(subaccount);
    }

    std::vector<uint32_t> ga_session::get_subaccount_full_path(uint32_t subaccount, uint32_t pointer, bool is_internal)
    {
        if (m_user_pubkeys) {
            locker_t locker(m_mutex);
            return m_user_pubkeys->get_subaccount_full_path(subaccount, pointer, is_internal);
        }
        return ga_user_pubkeys::get_ga_subaccount_full_path(subaccount, pointer, is_internal);
    }

    bool ga_session::has_recovery_pubkeys_subaccount(uint32_t subaccount)
    {
        locker_t locker(m_mutex);
        return get_recovery_pubkeys().have_subaccount(subaccount);
    }

    std::string ga_session::get_service_xpub(uint32_t subaccount)
    {
        locker_t locker(m_mutex);
        return get_ga_pubkeys().get_subaccount(subaccount).to_base58();
    }

    std::string ga_session::get_recovery_xpub(uint32_t subaccount)
    {
        locker_t locker(m_mutex);
        return get_recovery_pubkeys().get_subaccount(subaccount).to_base58();
    }

    std::vector<unsigned char> ga_session::output_script_from_utxo(const nlohmann::json& utxo)
    {
        locker_t locker(m_mutex);
        return output_script_from_utxo(locker, utxo);
    }

    std::vector<unsigned char> ga_session::output_script_from_utxo(locker_t& locker, const nlohmann::json& utxo)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        return ::ga::sdk::output_script_from_utxo(
            m_net_params, get_ga_pubkeys(), get_user_pubkeys(), get_recovery_pubkeys(), utxo);
    }

    std::vector<pub_key_t> ga_session::pubkeys_from_utxo(const nlohmann::json& utxo)
    {
        const uint32_t subaccount = utxo.at("subaccount");
        const uint32_t pointer = utxo.at("pointer");
        locker_t locker(m_mutex);
        // TODO: consider returning the recovery key (2of3) as well
        return std::vector<pub_key_t>(
            { get_ga_pubkeys().derive(subaccount, pointer), get_user_pubkeys().derive(subaccount, pointer) });
    }

    nlohmann::json ga_session::create_transaction(const nlohmann::json& details)
    {
        try {
            return create_ga_transaction(*this, details);
        } catch (const user_error& e) {
            return nlohmann::json({ { "error", e.what() } });
        }
    }

    nlohmann::json ga_session::user_sign_transaction(const nlohmann::json& details)
    {
        return sign_ga_transaction(*this, details);
    }

    nlohmann::json ga_session::psbt_sign(const nlohmann::json& details)
    {
        nlohmann::json result = details;
        std::string tx_hex = psbt_extract_tx(details.at("psbt"));
        const auto flags = tx_flags(m_net_params.is_liquid());
        wally_tx_ptr tx = tx_from_hex(tx_hex, flags);
        const nlohmann::json tx_details = { { "transaction", std::move(tx_hex) } };

        // Clear utxos and fill it with the ones that will be signed
        std::vector<nlohmann::json> inputs;
        inputs.reserve(tx->num_inputs);
        bool requires_signatures = false;
        for (size_t i = 0; i < tx->num_inputs; ++i) {
            const std::string txhash_hex = b2h_rev(tx->inputs[i].txhash);
            const uint32_t vout = tx->inputs[i].index;
            auto input_utxo = nlohmann::json::object();
            for (auto& utxo : result.at("utxos")) {
                if (!utxo.empty() && utxo.at("txhash") == txhash_hex && utxo.at("pt_idx") == vout) {
                    // TODO: remove this once get_unspent_outputs populates prevout_script
                    utxo["prevout_script"] = b2h(output_script_from_utxo(utxo));
                    input_utxo = std::move(utxo);
                    requires_signatures = true;
                    break;
                }
            }
            inputs.emplace_back(input_utxo);
        }

        result["utxos"].clear();
        if (!requires_signatures) {
            return result;
        }

        // FIXME: refactor to use HWW path
        const auto signatures = sign_ga_transaction(*this, tx_details, inputs).first;

        size_t i = 0;
        const bool is_low_r = get_signer()->supports_low_r();
        for (const auto& utxo : inputs) {
            if (!utxo.empty()) {
                add_input_signature(tx, i, utxo, signatures.at(i), is_low_r);
            }
            ++i;
        }

        // FIXME: handle existing 2FA
        const nlohmann::json twofactor_data = nlohmann::json::object();

        nlohmann::json private_data;
        if (result.contains("blinding_nonces")) {
            private_data["blinding_nonces"] = std::move(result["blinding_nonces"]);
            result.erase("blinding_nonces");
        }

        auto ret = wamp_cast_json(m_wamp->call(
            "vault.sign_raw_tx", tx_to_hex(tx, flags), mp_cast(twofactor_data).get(), mp_cast(private_data).get()));

        result["psbt"] = psbt_merge_tx(details.at("psbt"), ret.at("tx"));
        for (const auto& utxo : inputs) {
            if (!utxo.empty()) {
                result["utxos"].emplace_back(std::move(utxo));
            }
        }
        return result;
    }

    nlohmann::json ga_session::service_sign_transaction(
        const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        constexpr bool is_send = false;
        return sign_or_send_tx(details, twofactor_data, is_send);
    }

    nlohmann::json ga_session::send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        constexpr bool is_send = true;
        return sign_or_send_tx(details, twofactor_data, is_send);
    }

    nlohmann::json ga_session::sign_or_send_tx(
        const nlohmann::json& details, const nlohmann::json& twofactor_data, bool is_send)
    {
        GDK_RUNTIME_ASSERT(json_get_value(details, "error").empty());
        // We must have a tx and it must be signed by the user
        GDK_RUNTIME_ASSERT(details.find("transaction") != details.end());
        GDK_RUNTIME_ASSERT_MSG(json_get_value(details, "user_signed", false), "Tx must be signed before sending");

        nlohmann::json result = details;

        // Check memo is storable, if we are sending and have one
        const std::string memo = is_send ? json_get_value(result, "memo") : std::string();
        check_tx_memo(memo);

        // FIXME: test weight and return error in create_transaction, not here
        const std::string tx_hex = result.at("transaction");
        const size_t MAX_TX_WEIGHT = 400000;
        const uint32_t flags = tx_flags(m_net_params.is_liquid());
        const auto unsigned_tx = tx_from_hex(tx_hex, flags);
        GDK_RUNTIME_ASSERT(tx_get_weight(unsigned_tx) < MAX_TX_WEIGHT);

        nlohmann::json private_data;
        // FIXME: social_destination/social_destination_type/payreq if BIP70

        const auto blinding_nonces_p = result.find("blinding_nonces");
        if (blinding_nonces_p != result.end()) {
            private_data["blinding_nonces"] = *blinding_nonces_p;
        }

        const auto mp_2fa = mp_cast(twofactor_data);
        const auto mp_pd = mp_cast(private_data);
        nlohmann::json tx_details;
        // TODO: Merge these calls when the servers are updated
        if (is_send) {
            constexpr bool return_tx = true;
            tx_details
                = wamp_cast_json(m_wamp->call("vault.send_raw_tx", tx_hex, mp_2fa.get(), mp_pd.get(), return_tx));
        } else {
            tx_details = wamp_cast_json(m_wamp->call("vault.sign_raw_tx", tx_hex, mp_2fa.get(), mp_pd.get()));
        }

        const amount::value_type decrease = tx_details.at("limit_decrease");
        const auto txhash_hex = tx_details["txhash"];
        result["txhash"] = txhash_hex;
        // Update the details with the server signed transaction, since it
        // may be a slightly different size once signed
        const auto tx = tx_from_hex(tx_details["tx"], flags);
        update_tx_size_info(m_net_params, tx, result);
        result["server_signed"] = true;

        std::vector<uint32_t> subaccounts; // TODO: Handle multi-account spends
        subaccounts.push_back(details.at("subaccount"));
        remove_cached_utxos(subaccounts);

        locker_t locker(m_mutex);
        for (auto subaccount : subaccounts) {
            m_synced_subaccounts.erase(subaccount);
        }

        if (is_send) {
            // Cache the raw tx data
            m_cache->insert_transaction_data(txhash_hex, tx_to_bytes(tx));

            if (!memo.empty()) {
                update_blob(locker, std::bind(&client_blob::set_tx_memo, &m_blob, txhash_hex, memo));
            }
        }

        if (decrease != 0) {
            update_spending_limits(locker, tx_details["limits"]);
        }

        m_cache->save_db();
        return result;
    }

    // Idempotent
    std::string ga_session::broadcast_transaction(const std::string& tx_hex)
    {
        return wamp_cast(m_wamp->call("vault.broadcast_raw_tx", tx_hex));
    }

    // Idempotent
    void ga_session::send_nlocktimes()
    {
        ensure_full_session();
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(m_wamp->call("txs.send_nlocktime")));
    }

    void ga_session::set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        const uint32_t value = locktime_details.at("value");
        locker_t locker(m_mutex);
        // This not only saves a server round trip in case of bad value, but
        // also ensures that the value is recoverable.
        GDK_RUNTIME_ASSERT(std::find(m_csv_buckets.begin(), m_csv_buckets.end(), value) != m_csv_buckets.end());
        auto result = m_wamp->call(locker, "login.set_csvtime", value, mp_cast(twofactor_data).get());
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));

        m_csv_blocks = value;
    }

    void ga_session::set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        const uint32_t value = locktime_details.at("value");
        auto result = m_wamp->call("login.set_nlocktime", value, mp_cast(twofactor_data).get());
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));

        locker_t locker(m_mutex);
        m_nlocktime = value;
    }

    void ga_session::set_transaction_memo(const std::string& txhash_hex, const std::string& memo)
    {
        ensure_full_session();
        check_tx_memo(memo);
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT_MSG(!is_twofactor_reset_active(locker), "Wallet is locked");
        update_blob(locker, std::bind(&client_blob::set_tx_memo, &m_blob, txhash_hex, memo));
    }

    void ga_session::download_headers_ctl(session_impl::locker_t& locker, bool do_start)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        if (!m_spv_enabled || m_net_params.is_liquid()) {
            return; // SPV is not enabled or we are on Liquid: nothing to do
        }

        if (m_spv_thread) {
            // A thread downloading headers already exists
            if (!m_spv_thread_done) {
                // Thread is still running
                if (do_start) {
                    // Let the existing thread continue running
                    return;
                }
                // Ask and wait for the thread to die
                m_spv_thread_stop = true;
                while (!m_spv_thread_done) {
                    unique_unlock unlocker(locker);
                    std::this_thread::sleep_for(100ms);
                }
            }
            // Thread is finished, join and delete it
            m_spv_thread->join();
            m_spv_thread.reset();
        }

        m_spv_thread_done = false;
        m_spv_thread_stop = false;

        if (do_start) {
            // Start up a new sync thread
            GDK_RUNTIME_ASSERT(!m_spv_thread);
            m_spv_thread.reset(new std::thread([this] { download_headers_thread_fn(); }));
        }
    }

    void ga_session::download_headers_thread_fn()
    {
        const auto spv_params = get_spv_params(m_net_params, get_proxy_settings());
        uint32_t last_fetched_height = 0;

        // Loop downloading block headers until we are caught up, then exit
        GDK_LOG_SEV(log_level::info) << "spv_download_headers: starting sync";
        for (;;) {
            try {
                uint32_t block_height;
                {
                    locker_t locker(m_mutex);
                    if (m_spv_thread_stop) {
                        GDK_LOG_SEV(log_level::info) << "spv_download_headers: exit requested";
                        break; // We have been asked to terminate; do so
                    }
                    block_height = m_last_block_notification["block_height"];
                }
                const auto ret = rust_call("spv_download_headers", spv_params);
                const auto fetched_height = ret.at("height");
                GDK_LOG_SEV(log_level::debug) << "spv_download_headers:" << fetched_height << '/' << block_height;
                if (fetched_height == block_height) {
                    break; // Caught up, exit
                }
                // Use a short delay for initial header loading, longer
                // if we are waiting for the current block.
                const auto delay_ms = fetched_height == last_fetched_height ? 1000ms : 50ms;
                last_fetched_height = fetched_height;
                std::this_thread::sleep_for(delay_ms);
            } catch (const std::exception& e) {
                GDK_LOG_SEV(log_level::warning) << "spv_download_headers exception:" << e.what();
                break; // Exception, exit
            }
        }
        locker_t locker(m_mutex);
        m_spv_thread_done = true;
    }

} // namespace sdk
} // namespace ga
