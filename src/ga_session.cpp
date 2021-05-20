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

#include "boost_wrapper.hpp"
#include "session.hpp"

#include "autobahn_wrapper.hpp"
#include "boost_wrapper.hpp"
#include "exception.hpp"
#ifdef BUILD_GDK_RUST
#include "ga_rust.hpp"
#endif
#include "ga_session.hpp"
#include "ga_strings.hpp"
#include "ga_tor.hpp"
#include "ga_tx.hpp"
#include "http_client.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "signer.hpp"
#include "transaction_utils.hpp"
#include "tx_list_cache.hpp"
#include "version.h"
#include "xpub_hdkey.hpp"

namespace asio = boost::asio;

namespace ga {
namespace sdk {
    struct websocket_rng_type {
        uint32_t operator()() const;
    };

    struct websocketpp_gdk_config : public websocketpp::config::asio_client {
        using alog_type = websocket_boost_logger;
        using elog_type = websocket_boost_logger;

#ifdef NDEBUG
        static const websocketpp::log::level alog_level = websocketpp::log::alevel::app;
        static const websocketpp::log::level elog_level = websocketpp::log::elevel::info;
#else
        static const websocketpp::log::level alog_level = websocketpp::log::alevel::devel;
        static const websocketpp::log::level elog_level = websocketpp::log::elevel::devel;
#endif
        using rng_type = websocket_rng_type;

        static const long timeout_pong = 20000; // in ms

        struct transport_config : public websocketpp::config::asio_client::transport_config {
            using alog_type = websocket_boost_logger;
            using elog_type = websocket_boost_logger;
        };
        using transport_type = websocketpp::transport::asio::endpoint<websocketpp_gdk_config::transport_config>;
    };

    struct websocketpp_gdk_tls_config : public websocketpp::config::asio_tls_client {
        using alog_type = websocket_boost_logger;
        using elog_type = websocket_boost_logger;
#ifdef NDEBUG
        static const websocketpp::log::level alog_level = websocketpp::log::alevel::app;
        static const websocketpp::log::level elog_level = websocketpp::log::elevel::info;
#else
        static const websocketpp::log::level alog_level = websocketpp::log::alevel::devel;
        static const websocketpp::log::level elog_level = websocketpp::log::elevel::devel;
#endif
        using rng_type = websocket_rng_type;

        static const long timeout_pong = 20000; // in ms

        struct transport_config : public websocketpp::config::asio_tls_client::transport_config {
            using alog_type = websocket_boost_logger;
            using elog_type = websocket_boost_logger;
        };
        using transport_type = websocketpp::transport::asio::endpoint<websocketpp_gdk_tls_config::transport_config>;
    };

    using transport = autobahn::wamp_websocketpp_websocket_transport<websocketpp_gdk_config>;
    using transport_tls = autobahn::wamp_websocketpp_websocket_transport<websocketpp_gdk_tls_config>;

    struct flag_type {
        flag_type() { m_flag.second = m_flag.first.get_future(); }

        void set() { m_flag.first.set_value(); }

        std::future_status wait(std::chrono::seconds secs = 0s) const { return m_flag.second.wait_for(secs); }

        std::pair<std::promise<void>, std::future<void>> m_flag;
    };

    struct network_control_context {
        bool set_reconnect(bool reconnect)
        {
            bool r = m_reconnect_flag;
            if (r && reconnect) {
                return false;
            }
            return m_reconnect_flag.compare_exchange_strong(r, reconnect);
        }

        bool reconnecting() const { return m_reconnect_flag; }

        void reset_exit() { m_exit_flag = flag_type{}; }
        void set_exit() { m_exit_flag.set(); }
        bool retrying(std::chrono::seconds secs) const { return m_exit_flag.wait(secs) != std::future_status::ready; }

        void set_enabled(bool v) { m_enabled = v; }
        bool is_enabled() const { return m_enabled; }

        void reset() { reset_exit(); }

    private:
        flag_type m_exit_flag;
        std::atomic_bool m_reconnect_flag{ false };
        std::atomic_bool m_enabled{ true };
    };

    gdk_logger_t& websocket_boost_logger::m_log = gdk_logger::get();

    namespace {
        static const std::string SOCKS5("socks5://");
        static const std::string USER_AGENT_CAPS("[v2,sw,csv,csv_opt]");
        static const std::string USER_AGENT_CAPS_NO_CSV("[v2,sw]");
        // TODO: The server should return these
        static const std::vector<std::string> ALL_2FA_METHODS = { { "email" }, { "sms" }, { "phone" }, { "gauth" } };

        static const std::string MASKED_GAUTH_SEED("***");
        static const uint32_t DEFAULT_MIN_FEE = 1000; // 1 satoshi/byte
        static const uint32_t NUM_FEE_ESTIMATES = 25; // Min fee followed by blocks 1-24

        // networking defaults
        static const uint32_t DEFAULT_PING = 20; // ping message interval in seconds
        static const uint32_t DEFAULT_KEEPIDLE = 1; // tcp heartbeat frequency in seconds
        static const uint32_t DEFAULT_KEEPINTERVAL = 1; // tcp heartbeat frequency in seconds
        static const uint32_t DEFAULT_KEEPCNT = 2; // tcp unanswered heartbeats
        static const uint32_t DEFAULT_DISCONNECT_WAIT = 2; // maximum wait time on disconnect in seconds
        static const uint32_t DEFAULT_THREADPOOL_SIZE = 4; // Number of asio pool threads

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

        template <typename T> static nlohmann::json wamp_cast_json(const T& result)
        {
            if (!result.number_of_arguments()) {
                return nlohmann::json();
            }
            const auto obj = result.template argument<msgpack::object>(0);
            std::stringstream ss;
            ss << obj;
            return nlohmann::json::parse(ss.str());
        }

        template <typename T = std::string> inline T wamp_cast(const autobahn::wamp_call_result& result)
        {
            return result.template argument<T>(0);
        }

        template <typename T = std::string>
        inline boost::optional<T> wamp_cast_nil(const autobahn::wamp_call_result& result)
        {
            if (result.template argument<msgpack::object>(0).is_nil()) {
                return boost::none;
            }
            return result.template argument<T>(0);
        }

        class exponential_backoff {
        public:
            explicit exponential_backoff(std::chrono::seconds limit = 300s)
                : m_limit(limit)
            {
            }

            std::chrono::seconds backoff(uint32_t n)
            {
                m_elapsed += m_waiting;
                const auto v
                    = std::min(static_cast<uint32_t>(m_limit.count()), uint32_t{ 1 } << std::min(n, uint32_t{ 31 }));
                std::random_device rd;
                std::uniform_int_distribution<uint32_t> d(v / 2, v);
                m_waiting = std::chrono::seconds(d(rd));
                return m_waiting;
            }

            bool limit_reached() const { return m_elapsed >= m_limit; }
            std::chrono::seconds elapsed() const { return m_elapsed; }
            std::chrono::seconds waiting() const { return m_waiting; }

        private:
            const std::chrono::seconds m_limit;
            std::chrono::seconds m_elapsed{ 0s };
            std::chrono::seconds m_waiting{ 0s };
        };

        static nlohmann::json get_fees_as_json(const autobahn::wamp_event& event)
        {
            const auto obj = event.argument<msgpack::object>(0);
            std::stringstream ss;
            ss << obj;
            std::string fee_json = ss.str();
            // TODO: Remove this once the server is fixed to use string keys
            fee_json.reserve(fee_json.size() + 6 * 2); // 6 pairs of quotes
            boost::algorithm::replace_first(fee_json, "1:", "\"1\":");
            boost::algorithm::replace_first(fee_json, "2:", "\"2\":");
            boost::algorithm::replace_first(fee_json, "3:", "\"3\":");
            boost::algorithm::replace_first(fee_json, "6:", "\"6\":");
            boost::algorithm::replace_first(fee_json, "12:", "\"12\":");
            boost::algorithm::replace_first(fee_json, "24:", "\"24\":");
            return nlohmann::json::parse(fee_json);
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

        inline auto sig_to_der_hex(const ecdsa_sig_t& signature) { return b2h(ec_sig_to_der(signature)); }

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
        static void cleanup_appearance_settings(const ga_session::locker_t& locker, nlohmann::json& appearance)
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

        static std::string socksify(const std::string& proxy)
        {
            const std::string trimmed = boost::algorithm::trim_copy(proxy);
            if (!proxy.empty() && !boost::algorithm::starts_with(trimmed, SOCKS5)) {
                return SOCKS5 + trimmed;
            }
            return trimmed;
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
    } // namespace

    uint32_t websocket_rng_type::operator()() const
    {
        uint32_t b;
        get_random_bytes(sizeof(b), &b, sizeof(b));
        return b;
    }

    struct event_loop_controller {
        explicit event_loop_controller(boost::asio::io_context& io)
            : m_work_guard(boost::asio::make_work_guard(io))
        {
            m_run_thread = std::thread([&] { io.run(); });
        }

        void reset()
        {
            no_std_exception_escape([this] {
                m_work_guard.reset();
                m_run_thread.join();
            });
        }

        std::thread m_run_thread;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_work_guard;
    };

    ga_session::ga_session(const nlohmann::json& net_params)
        : m_net_params(network_parameters{ network_parameters::get(net_params.at("name")) })
        , m_proxy(socksify(net_params.value("proxy", std::string{})))
        , m_use_tor(net_params.value("use_tor", false))
        , m_has_network_proxy(!m_proxy.empty())
        , m_is_tls_connection(boost::algorithm::starts_with(m_net_params.get_connection_string(m_use_tor), "wss://"))
        , m_io()
        , m_controller(new event_loop_controller(m_io))
        , m_ping_timer(m_io)
        , m_network_control(new network_control_context())
        , m_pool(DEFAULT_THREADPOOL_SIZE)
        , m_notification_handler(nullptr)
        , m_notification_context(nullptr)
        , m_blob()
        , m_blob_hmac()
        , m_blob_outdated(false)
        , m_min_fee_rate(DEFAULT_MIN_FEE)
        , m_earliest_block_time(0)
        , m_next_subaccount(0)
        , m_block_height(0)
        , m_system_message_id(0)
        , m_system_message_ack_id(0)
        , m_watch_only(true)
        , m_is_locked(false)
        , m_tx_last_notification(std::chrono::system_clock::now())
        , m_multi_call_category(0)
        , m_cache(m_net_params, net_params.at("name"))
        , m_user_agent(std::string(GDK_COMMIT) + " " + net_params.value("user_agent", ""))
        , m_electrum_url(
              net_params.value("electrum_url", network_parameters::get(net_params.at("name")).at("electrum_url")))
        , m_electrum_tls(net_params.value("tls", network_parameters::get(net_params.at("name")).at("tls")))
        , m_spv_enabled(
              net_params.value("spv_enabled", network_parameters::get(net_params.at("name")).at("spv_enabled")))
        , m_wamp_call_options()
        , m_wamp_call_prefix("com.greenaddress.")
    {
        constexpr uint32_t wamp_timeout_secs = 10;
        m_wamp_call_options.set_timeout(std::chrono::seconds(wamp_timeout_secs));

        const auto log_level = net_params.value("log_level", "none");
        m_log_level = log_level == "none"
            ? logging_levels::none
            : log_level == "info" ? logging_levels::info
                                  : log_level == "debug" ? logging_levels::debug : logging_levels::none;
        boost::log::core::get()->set_filter(
            log_level::severity >= (m_log_level == logging_levels::debug
                                           ? log_level::severity_level::debug
                                           : m_log_level == logging_levels::info ? log_level::severity_level::info
                                                                                 : log_level::severity_level::fatal));
        m_fee_estimates.assign(NUM_FEE_ESTIMATES, m_min_fee_rate);
        make_client();
    }

    ga_session::~ga_session()
    {
        no_std_exception_escape([this] {
            reset();
            m_controller->reset();
        });
    }

    bool ga_session::is_connected() const { return m_transport && m_transport->is_connected(); }

    std::string ga_session::get_tor_socks5()
    {
        return m_tor_ctrl ? m_tor_ctrl->wait_for_socks5(DEFAULT_TOR_SOCKS_WAIT, nullptr) : std::string{};
    }

    void ga_session::tor_sleep_hint(const std::string& hint)
    {
        if (m_tor_ctrl) {
            m_tor_ctrl->tor_sleep_hint(hint);
        }
    }

    void ga_session::unsubscribe()
    {
        const auto subscriptions = [this] {
            locker_t locker(m_mutex);
            const auto subscriptions = m_subscriptions;
            m_subscriptions.clear();
            return subscriptions;
        }();

        for (const auto& sub : subscriptions) {
            no_std_exception_escape([this, &sub] {
                const auto status
                    = m_session->unsubscribe(sub).wait_for(boost::chrono::seconds(DEFAULT_DISCONNECT_WAIT));
                if (status != boost::future_status::ready) {
                    GDK_LOG_SEV(log_level::info) << "future not ready on unsubscribe";
                }
            });
        }
    }

    void ga_session::set_socket_options()
    {
        auto set_option = [this](auto option) {
            if (m_is_tls_connection) {
                GDK_RUNTIME_ASSERT(std::static_pointer_cast<transport_tls>(m_transport)->set_socket_option(option));
            } else {
                GDK_RUNTIME_ASSERT(std::static_pointer_cast<transport>(m_transport)->set_socket_option(option));
            }
        };

        boost::asio::ip::tcp::no_delay no_delay(true);
        set_option(no_delay);
        boost::asio::socket_base::keep_alive keep_alive(true);
        set_option(keep_alive);

#if defined __APPLE__
        using tcp_keep_alive = boost::asio::detail::socket_option::integer<IPPROTO_TCP, TCP_KEEPALIVE>;
        set_option(tcp_keep_alive{ DEFAULT_KEEPIDLE });
#elif __linux__ || __ANDROID__ || __FreeBSD__
        using keep_idle = boost::asio::detail::socket_option::integer<IPPROTO_TCP, TCP_KEEPIDLE>;
        set_option(keep_idle{ DEFAULT_KEEPIDLE });
#endif
#ifndef __WIN64
        using keep_interval = boost::asio::detail::socket_option::integer<IPPROTO_TCP, TCP_KEEPINTVL>;
        set_option(keep_interval{ DEFAULT_KEEPINTERVAL });
        using keep_count = boost::asio::detail::socket_option::integer<IPPROTO_TCP, TCP_KEEPCNT>;
        set_option(keep_count{ DEFAULT_KEEPCNT });
#endif
    }

    void ga_session::connect()
    {
        m_session = std::make_shared<autobahn::wamp_session>(m_io, m_log_level == logging_levels::debug);

        make_transport();
        m_transport->connect().get();
        m_session->start().get();
        m_session->join("realm1").get();
        set_socket_options();
        start_ping_timer();
    }

    void ga_session::make_client()
    {
        if (!m_is_tls_connection) {
            m_client = std::make_unique<client>();
            boost::get<std::unique_ptr<client>>(m_client)->init_asio(&m_io);
            return;
        }

        m_client = std::make_unique<client_tls>();
        boost::get<std::unique_ptr<client_tls>>(m_client)->init_asio(&m_io);
        const auto host_name = websocketpp::uri(m_net_params.gait_wamp_url()).get_host();

        boost::get<std::unique_ptr<client_tls>>(m_client)->set_tls_init_handler(
            [this, host_name](const websocketpp::connection_hdl) {
                return tls_init_handler_impl(
                    host_name, m_net_params.gait_wamp_cert_roots(), m_net_params.gait_wamp_cert_pins());
            });
    }

    void ga_session::make_transport()
    {
        if (m_use_tor && !m_has_network_proxy) {
            m_tor_ctrl = tor_controller::get_shared_ref();
            m_proxy
                = m_tor_ctrl->wait_for_socks5(DEFAULT_TOR_SOCKS_WAIT, [&](std::shared_ptr<tor_bootstrap_phase> phase) {
                      emit_notification("tor",
                          { { "tag", phase->tag }, { "summary", phase->summary }, { "progress", phase->progress } });
                  });
            if (m_proxy.empty()) {
                m_tor_ctrl->tor_sleep_hint("wakeup");
            }
            GDK_RUNTIME_ASSERT(!m_proxy.empty());
            GDK_LOG_SEV(log_level::info) << "tor_socks address " << m_proxy;
        }

        const auto server = m_net_params.get_connection_string(m_use_tor);
        std::string proxy_details;
        if (!m_proxy.empty()) {
            proxy_details = std::string(" through proxy ") + m_proxy;
        }
        GDK_LOG_SEV(log_level::info) << "Connecting using version " << GDK_COMMIT << " to " << server << proxy_details;
        const bool is_debug_enabled = m_log_level == logging_levels::debug;
        if (m_is_tls_connection) {
            auto& clnt = *boost::get<std::unique_ptr<client_tls>>(m_client);
            clnt.set_pong_timeout_handler(m_heartbeat_handler);
            m_transport = std::make_shared<transport_tls>(clnt, server, m_proxy, is_debug_enabled);
        } else {
            auto& clnt = *boost::get<std::unique_ptr<client>>(m_client);
            clnt.set_pong_timeout_handler(m_heartbeat_handler);
            m_transport = std::make_shared<transport>(clnt, server, m_proxy, is_debug_enabled);
        }
        m_transport->attach(std::static_pointer_cast<autobahn::wamp_transport_handler>(m_session));
    }

    void ga_session::disconnect_transport() const
    {
        if (m_transport) {
            no_std_exception_escape([&] {
                const auto status = m_transport->disconnect().wait_for(boost::chrono::seconds(DEFAULT_DISCONNECT_WAIT));
                if (status != boost::future_status::ready) {
                    GDK_LOG_SEV(log_level::info) << "future not ready on disconnect";
                }
            });
            no_std_exception_escape([&] { m_transport->detach(); });
        }
    }

    bool ga_session::ping() const
    {
        bool expect_pong = false;
        no_std_exception_escape([this, &expect_pong] {
            if (is_connected()) {
                if (m_is_tls_connection) {
                    expect_pong = std::static_pointer_cast<transport_tls>(m_transport)->ping(std::string());
                } else {
                    expect_pong = std::static_pointer_cast<transport>(m_transport)->ping(std::string());
                }
            }
        });
        return expect_pong;
    }

    context_ptr ga_session::tls_init_handler_impl(
        const std::string& host_name, const std::vector<std::string>& roots, const std::vector<std::string>& pins)
    {
        const context_ptr ctx = std::make_shared<boost::asio::ssl::context>(boost::asio::ssl::context::tls);
        ctx->set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2
            | boost::asio::ssl::context::no_sslv3 | boost::asio::ssl::context::no_tlsv1
            | boost::asio::ssl::context::no_tlsv1_1 | boost::asio::ssl::context::single_dh_use);
        ctx->set_verify_mode(
            boost::asio::ssl::context::verify_peer | boost::asio::ssl::context::verify_fail_if_no_peer_cert);
        // attempt to load system roots
        ctx->set_default_verify_paths();
        for (const auto& root : roots) {
            if (root.empty()) {
                // TODO: at the moment looks like the roots/pins are empty strings when absent
                break;
            }
            // add network provided root
            const boost::asio::const_buffer root_const_buff(root.c_str(), root.size());
            ctx->add_certificate_authority(root_const_buff);
        }
        if (pins.empty() || pins[0].empty()) {
            // no pins for this network, just do rfc2818 validation
            ctx->set_verify_callback(asio::ssl::rfc2818_verification{ host_name });
            return ctx;
        }

        ctx->set_verify_callback([pins, host_name](bool preverified, boost::asio::ssl::verify_context& ctx) {
            if (!preverified) {
                return false;
            }

            // on top of rfc2818, enforce pin if this is the last cert in the chain
            const int depth = X509_STORE_CTX_get_error_depth(ctx.native_handle());
            const bool is_leaf_cert = depth == 0;
            if (is_leaf_cert) {
                typedef std::unique_ptr<STACK_OF(X509), void (*)(STACK_OF(X509)*)> X509_stack_ptr;
                auto free_x509_stack = [](STACK_OF(X509) * chain) { sk_X509_pop_free(chain, X509_free); };
                X509_stack_ptr chain(X509_STORE_CTX_get1_chain(ctx.native_handle()), free_x509_stack);

                std::array<unsigned char, SHA256_LEN> sha256_digest_buf;
                unsigned int written = 0;
                const int chain_length = sk_X509_num(chain.get());
                bool found_pin = false;
                for (int idx = 0; idx < chain_length; ++idx) {
                    const auto cert = sk_X509_value(chain.get(), idx);
                    if (X509_digest(cert, EVP_sha256(), sha256_digest_buf.data(), &written) == 0
                        || written != sha256_digest_buf.size()) {
                        GDK_LOG_SEV(log_level::error) << "X509_digest failed certificate idx " << idx;
                        return false;
                    }
                    const auto hex_digest = b2h(sha256_digest_buf);
                    if (std::find(pins.begin(), pins.end(), hex_digest) != pins.end()) {
                        found_pin = true;
                        break;
                    }
                }

                if (!found_pin) {
                    GDK_LOG_SEV(log_level::error) << "No pinned certificate found, failing ssl verification";
                    return false;
                }
            }

            return asio::ssl::rfc2818_verification{ host_name }(true, ctx);
        });

        return ctx;
    }

    autobahn::wamp_call_result ga_session::wamp_process_call(boost::future<autobahn::wamp_call_result>& fn) const
    {
        const auto ms = boost::chrono::milliseconds(m_wamp_call_options.timeout().count());
        for (;;) {
            const auto status = fn.wait_for(ms);
            if (status == boost::future_status::timeout && !is_connected()) {
                throw timeout_error{};
            }
            if (status == boost::future_status::ready) {
                break;
            }
        }
        return fn.get();
    }

    void ga_session::ping_timer_handler(const boost::system::error_code& ec)
    {
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }

        if (!ping()) {
            GDK_RUNTIME_ASSERT(m_ping_fail_handler != nullptr);
            m_ping_fail_handler();
        }

        m_ping_timer.expires_from_now(boost::posix_time::seconds(DEFAULT_PING));
        m_ping_timer.async_wait(boost::bind(&ga_session::ping_timer_handler, this, ::_1));
    }

    void ga_session::set_heartbeat_timeout_handler(heartbeat_t handler) { m_heartbeat_handler = std::move(handler); }

    void ga_session::set_ping_fail_handler(ping_fail_t handler) { m_ping_fail_handler = std::move(handler); }

    void ga_session::emit_notification(std::string event, nlohmann::json details)
    {
        asio::post(m_pool, [this, event, details] {
            locker_t locker(m_mutex);
            if (m_notification_handler != nullptr) {
                call_notification_handler(locker, new nlohmann::json({ { "event", event }, { event, details } }));
            }
        });
    }

    void ga_session::try_reconnect()
    {
        GDK_LOG_NAMED_SCOPE("try_reconnect");

        if (!m_network_control->is_enabled()) {
            GDK_LOG_SEV(log_level::info) << "reconnect is disabled. backing off...";
            return;
        }

        if (is_connected()) {
            GDK_LOG_SEV(log_level::info) << "attempting to reconnect but transport still connected. backing off...";
            emit_notification(
                "network", { { "connected", true }, { "login_required", false }, { "heartbeat_timeout", true } });
            return;
        }

        if (!m_network_control->set_reconnect(true)) {
            GDK_LOG_SEV(log_level::info) << "reconnect in progress. backing off...";
            return;
        }

        m_ping_timer.cancel();
        m_network_control->reset();

        boost::asio::post(m_pool, [this] {
            const auto thread_id = std::this_thread::get_id();

            GDK_LOG_SEV(log_level::info) << "reconnect thread " << std::hex << thread_id << " started.";

            exponential_backoff bo;
            uint32_t n = 0;
            for (;;) {
                const auto backoff_time = bo.backoff(n++);
                nlohmann::json network_status = { { "connected", false }, { "elapsed", bo.elapsed().count() },
                    { "waiting", bo.waiting().count() }, { "limit", bo.limit_reached() } };
                emit_notification("network", network_status);

                if (!m_network_control->retrying(backoff_time)) {
                    GDK_LOG_SEV(log_level::info)
                        << "reconnect thread " << std::hex << thread_id << " exiting on request.";
                    break;
                }

                if (reconnect()) {
                    GDK_LOG_SEV(log_level::info)
                        << "reconnect thread " << std::hex << thread_id << " exiting on reconnect.";
                    break;
                }
            }

            m_network_control->set_reconnect(false);

            if (!is_connected()) {
                start_ping_timer();
            }
        });
    }

    void ga_session::stop_reconnect()
    {
        if (m_network_control->reconnecting()) {
            m_network_control->set_exit();
        }
    }

    void ga_session::reconnect_hint(bool enable, bool restart)
    {
        m_network_control->set_enabled(enable);
        if (restart) {
            stop_reconnect();
        }
    }

    bool ga_session::reconnect()
    {
        try {
            disconnect();
            connect();

            const bool logged_in = !m_mnemonic.empty() && login_from_cached(m_mnemonic);
            if (!logged_in) {
                on_failed_login();
            }
            emit_notification(
                "network", { { "connected", true }, { "login_required", !logged_in }, { "heartbeat_timeout", false } });

            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    void ga_session::start_ping_timer()
    {
        GDK_LOG_SEV(log_level::debug) << "starting ping timer...";
        m_ping_timer.expires_from_now(boost::posix_time::seconds(DEFAULT_PING));
        m_ping_timer.async_wait(boost::bind(&ga_session::ping_timer_handler, this, ::_1));
    }

    void ga_session::disconnect()
    {
        {
            locker_t locker(m_mutex);

            if (m_notification_handler != nullptr) {
                const nlohmann::json details{ { "connected", false } };
                call_notification_handler(
                    locker, new nlohmann::json({ { "event", "session" }, { "session", details } }));
            }

            m_signer.reset();
            m_local_encryption_key = boost::none;
            m_blob_aes_key = boost::none;
            m_blob_hmac_key = boost::none;
            m_blob_hmac.clear();
            m_blob.reset();
            m_blob_outdated = false;
            m_tx_list_caches.purge_all();
            // FIXME: securely destroy all held data
            // TODO: pass in whether we are disconnecting in order to reconnect,
            //       and if so, only securely destroy data not needed to re-login
            //       (e.g. leave m_mnemonic alone).
        }

        m_ping_timer.cancel();

        if (m_session) {
            no_std_exception_escape([this] {
                const auto status = m_session->leave().wait_for(boost::chrono::seconds(DEFAULT_DISCONNECT_WAIT));
                if (status != boost::future_status::ready) {
                    GDK_LOG_SEV(log_level::info) << "future not ready on leave session";
                }
            });
            no_std_exception_escape([this] {
                const auto status = m_session->stop().wait_for(boost::chrono::seconds(DEFAULT_DISCONNECT_WAIT));
                if (status != boost::future_status::ready) {
                    GDK_LOG_SEV(log_level::info) << "future not ready on stop session";
                }
            });
        }
        disconnect_transport();
    }

    nlohmann::json ga_session::http_request(nlohmann::json params)
    {
        nlohmann::json result;
        try {
            params.update(select_url(params["urls"], m_use_tor));
            json_add_if_missing(params, "proxy", socksify(m_proxy));

            auto root_certificates = m_net_params.gait_wamp_cert_roots();

            // The caller can specify a set of custom root certiifcates to add
            // to the default network roots
            const auto custom_roots_p = params.find("root_certificates");
            if (custom_roots_p != params.end()) {
                for (const auto& custom_root_certificate : *custom_roots_p) {
                    root_certificates.push_back(custom_root_certificate.get<std::string>());
                }
            }
            const auto ssl_ctx = tls_init_handler_impl(params["host"], root_certificates, {});

            std::shared_ptr<http_client> client;
            auto&& get = [&] {
                client = make_http_client(m_io, params["is_secure"] ? ssl_ctx.get() : nullptr);
                GDK_RUNTIME_ASSERT(client != nullptr);

                const boost::beast::http::verb verb = boost::beast::http::string_to_verb(params["method"]);
                return client->request(verb, params).get();
            };

            constexpr uint8_t num_redirects = 5;
            for (uint8_t i = 0; i < num_redirects; ++i) {
                result = get();
                if (!result.value("location", std::string{}).empty()) {
                    GDK_RUNTIME_ASSERT_MSG(!m_use_tor, "redirection over Tor is not supported");
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

    nlohmann::json ga_session::refresh_http_data(const std::string& type, bool refresh)
    {
        nlohmann::json cached_data = nlohmann::json::object();
        std::string last_modified;

        {
            locker_t locker(m_mutex);
            m_cache.get_key_value(type, { [&cached_data, &last_modified](const auto& db_blob) {
                if (!db_blob) {
                    return;
                }
                try {
                    cached_data = nlohmann::json::from_msgpack(db_blob->begin(), db_blob->end());
                    last_modified = cached_data.at("headers").at("last-modified");
                } catch (const std::exception& e) {
                    GDK_LOG_SEV(log_level::warning) << "Error reading cached json: " << e.what();
                    cached_data = nlohmann::json::object();
                }
            } });
        }

        if (!refresh) {
            return cached_data;
        }

        const std::string url = m_net_params.get_registry_connection_string(m_use_tor) + "/" + type + ".json";
        nlohmann::json get_params = { { "method", "GET" }, { "urls", { url } }, { "accept", "json" } };
        if (!last_modified.empty()) {
            get_params.update({ { "headers",
                { { boost::beast::http::to_string(boost::beast::http::field::if_modified_since), last_modified } } } });
        }

        const nlohmann::json data = http_request(get_params);

        GDK_RUNTIME_ASSERT_MSG(!data.contains("error"), "error during refresh");
        if (data.value("not_modified", false)) {
            // Our cached copy is up to date, return it
            return cached_data;
        }

        GDK_RUNTIME_ASSERT_MSG(data["body"].is_object(), "expected JSON");
        locker_t locker(m_mutex);
        m_cache.upsert_key_value(type, nlohmann::json::to_msgpack(data));
        m_cache.save_db();
        return data;
    }

    nlohmann::json ga_session::refresh_assets(const nlohmann::json& params)
    {
        GDK_RUNTIME_ASSERT(params.value("assets", false) || params.value("icons", false));

        nlohmann::json result;

        const bool refresh = params.value("refresh", true);

        if (params.value("assets", false)) {
            const auto assets = refresh_http_data("index", refresh);
            nlohmann::json json_assets;
            if (assets.find("error") == assets.end()) {
                json_assets = assets.value("body", nlohmann::json::object());
                json_assets.update({ { m_net_params.policy_asset(),
                    { { "asset_id", m_net_params.policy_asset() }, { "name", "btc" } } } });
            }
            result["assets"] = json_assets;
        }

        if (params.value("icons", false)) {
            const auto icons = refresh_http_data("icons", refresh);
            nlohmann::json json_icons;
            if (icons.find("error") == icons.end()) {
                json_icons = icons.value("body", nlohmann::json::object());
            }
            result["icons"] = json_icons;
        }

        return result;
    }

    std::shared_ptr<ga_session::nlocktime_t> ga_session::update_nlocktime_info()
    {
        locker_t locker(m_mutex);

        if (!m_nlocktimes) {
            nlohmann::json nlocktime_json;
            {
                unique_unlock unlocker(locker);
                nlocktime_json = fetch_nlocktime_json();
            }
            m_nlocktimes = std::make_shared<nlocktime_t>();
            for (const auto& v : nlocktime_json.at("list")) {
                const uint32_t vout = v.at("output_n");
                const std::string k{ json_get_value(v, "txhash") + ":" + std::to_string(vout) };
                m_nlocktimes->emplace(std::make_pair(k, v));
            }
        }

        return m_nlocktimes;
    }

    // Idempotent
    nlohmann::json ga_session::fetch_nlocktime_json() { return wamp_cast_json(wamp_call("txs.upcoming_nlocktime")); }

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
            if (!result.value("error", std::string{}).empty()) {
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

    void ga_session::reset()
    {
        stop_reconnect();
        m_pool.join();
        on_failed_login();
        unsubscribe();
        disconnect();
    }

    std::pair<std::string, std::string> ga_session::sign_challenge(
        ga_session::locker_t& locker, const std::string& challenge)
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

    nlohmann::json ga_session::set_fee_estimates(ga_session::locker_t& locker, const nlohmann::json& fee_estimates)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

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
        return m_fee_estimates;
    }

    void ga_session::register_user(const std::string& mnemonic, bool supports_csv)
    {
        locker_t locker(m_mutex);
        register_user(locker, mnemonic, supports_csv);
    }

    void ga_session::register_user(ga_session::locker_t& locker, const std::string& mnemonic, bool supports_csv)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        software_signer registerer(m_net_params, mnemonic);

        // Get our master xpub
        const auto master_xpub = registerer.get_xpub();
        const auto master_chain_code_hex = b2h(master_xpub.first);
        const auto master_pub_key_hex = b2h(master_xpub.second);

        // Get our gait path xpub and compute gait_path from it
        const auto gait_xpub = registerer.get_xpub(ga_pubkeys::get_gait_generation_path());
        const auto gait_path_hex = b2h(ga_pubkeys::get_gait_path_bytes(gait_xpub));

        register_user(locker, master_pub_key_hex, master_chain_code_hex, gait_path_hex, supports_csv);
    }

    void ga_session::register_user(const std::string& master_pub_key_hex, const std::string& master_chain_code_hex,
        const std::string& gait_path_hex, bool supports_csv)
    {
        locker_t locker(m_mutex);
        register_user(locker, master_pub_key_hex, master_chain_code_hex, gait_path_hex, supports_csv);
    }

    void ga_session::register_user(ga_session::locker_t& locker, const std::string& master_pub_key_hex,
        const std::string& master_chain_code_hex, const std::string& gait_path_hex, bool supports_csv)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        unique_unlock unlocker(locker);
        const auto user_agent = get_user_agent(supports_csv, m_user_agent);
        auto result = wamp_call("login.register", master_pub_key_hex, master_chain_code_hex, user_agent, gait_path_hex);
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));
    }

    // Idempotent
    std::string ga_session::get_challenge(const std::string& address)
    {
        const bool nlocktime_support = true;
        return wamp_cast(wamp_call("login.get_trezor_challenge", address, nlocktime_support));
    }

    void ga_session::upload_confidential_addresses(
        uint32_t subaccount, const std::vector<std::string>& confidential_addresses)
    {
        GDK_RUNTIME_ASSERT(confidential_addresses.size() > 0);

        auto result
            = wamp_call("txs.upload_authorized_assets_confidential_address", subaccount, confidential_addresses);
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));

        // subtract from the required_ca
        locker_t locker(m_mutex);
        const uint32_t remaining = m_subaccounts[subaccount]["required_ca"];
        if (remaining) {
            m_subaccounts[subaccount]["required_ca"]
                = confidential_addresses.size() > remaining ? 0 : remaining - confidential_addresses.size();
        }
    }

    void ga_session::update_login_data(
        locker_t& locker, nlohmann::json& login_data, const std::string& root_xpub_bip32, bool watch_only)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(m_signer != nullptr);

        m_login_data = login_data;

        // Parse gait_path into a derivation path
        const auto gait_path_bytes = h2b(m_login_data["gait_path"]);
        GDK_RUNTIME_ASSERT(gait_path_bytes.size() == m_gait_path.size() * 2);
        adjacent_transform(gait_path_bytes.begin(), gait_path_bytes.end(), m_gait_path.begin(),
            [](auto first, auto second) { return uint32_t((first << 8u) + second); });

        // Create our GA and recovery pubkey collections
        m_ga_pubkeys = std::make_unique<ga_pubkeys>(m_net_params, m_gait_path);
        m_recovery_pubkeys = std::make_unique<ga_user_pubkeys>(m_net_params);

        const uint32_t min_fee_rate = m_login_data["min_fee"];
        if (min_fee_rate != m_min_fee_rate) {
            m_min_fee_rate = min_fee_rate;
            m_fee_estimates.assign(NUM_FEE_ESTIMATES, m_min_fee_rate);
        }
        m_fiat_source = login_data["exchange"];
        m_fiat_currency = login_data["fiat_currency"];
        update_fiat_rate(locker, json_get_value(login_data, "fiat_exchange"));

        const uint32_t block_height = m_login_data["block_height"];
        m_block_height = block_height;

        m_subaccounts.clear();
        m_next_subaccount = 0;
        for (const auto& sa : m_login_data["subaccounts"]) {
            const uint32_t subaccount = sa["pointer"];
            std::string type = sa["type"];
            if (type == "simple") {
                type = "2of2";
            }
            const std::string satoshi_str = sa["satoshi"];
            const amount satoshi{ strtoull(satoshi_str.c_str(), nullptr, 10) };
            const std::string recovery_chain_code = json_get_value(sa, "2of3_backup_chaincode");
            const std::string recovery_pub_key = json_get_value(sa, "2of3_backup_pubkey");
            const std::string recovery_xpub_sig = json_get_value(sa, "2of3_backup_xpub_sig");
            std::string recovery_xpub = std::string();
            // TODO: fail if *any* 2of3 subaccount has missing or invalid
            //       signature of the corresponding backup/recovery key.
            if (!recovery_xpub_sig.empty() && !watch_only) {
                recovery_xpub = json_get_value(sa, "2of3_backup_xpub");
                GDK_RUNTIME_ASSERT(make_xpub(recovery_xpub) == make_xpub(recovery_chain_code, recovery_pub_key));
                const auto message = format_recovery_key_message(recovery_xpub, subaccount);
                const auto message_hash = format_bitcoin_message_hash(ustring_span(message));
                pub_key_t login_pubkey;
                if (m_signer->is_hw_device()) {
                    wally_ext_key_ptr parent = bip32_public_key_from_bip32_xpub(root_xpub_bip32);
                    ext_key derived = bip32_public_key_from_parent_path(*parent, signer::LOGIN_PATH);
                    memcpy(login_pubkey.begin(), derived.pub_key, sizeof(derived.pub_key));
                } else {
                    login_pubkey = m_signer->get_xpub(signer::LOGIN_PATH).second;
                }
                GDK_RUNTIME_ASSERT(ec_sig_verify(login_pubkey, message_hash, h2b(recovery_xpub_sig)));
            }

            // Get the subaccount name. Use the server provided value if
            // its present (i.e. no client blob enabled yet, or watch-only)
            const std::string svr_sa_name = json_get_value(sa, "name");
            const std::string blob_sa_name = m_blob.get_subaccount_name(subaccount);
            const std::string& sa_name = svr_sa_name.empty() ? blob_sa_name : svr_sa_name;
            const bool is_hidden = m_blob.get_subaccount_hidden(subaccount);
            insert_subaccount(locker, subaccount, sa_name, sa["receiving_id"], recovery_pub_key, recovery_chain_code,
                recovery_xpub, type, satoshi, json_get_value(sa, "has_txs", false), sa.value("required_ca", 0),
                is_hidden);

            if (subaccount > m_next_subaccount) {
                m_next_subaccount = subaccount;
            }
        }
        ++m_next_subaccount;

        // Insert the main account so callers can treat all accounts equally
        const std::string satoshi_str = login_data["satoshi"];
        const amount satoshi{ strtoull(satoshi_str.c_str(), nullptr, 10) };
        const bool has_txs = json_get_value(m_login_data, "has_txs", false);
        const std::string sa_name = m_blob.get_subaccount_name(0);
        const bool is_hidden = m_blob.get_subaccount_hidden(0);
        insert_subaccount(locker, 0, sa_name, m_login_data["receiving_id"], std::string(), std::string(), std::string(),
            "2of2", satoshi, has_txs, 0, is_hidden);

        m_system_message_id = json_get_value(m_login_data, "next_system_message_id", 0);
        m_system_message_ack_id = 0;
        m_system_message_ack = std::string();
        m_watch_only = watch_only;
        // TODO: Assert we aren't locked in all calls that should be disabled
        // (the server prevents these calls but its faster to reject them locally)
        m_is_locked = json_get_value(login_data, "reset_2fa_active", false);

        const auto p = m_login_data.find("limits");
        update_spending_limits(locker, p == m_login_data.end() ? nlohmann::json::object() : *p);

        auto& appearance = m_login_data["appearance"];
        cleanup_appearance_settings(locker, appearance);

        m_earliest_block_time = m_login_data["earliest_key_creation_time"];

        // Compute wallet identifier for callers to use if they wish.
        const chain_code_t main_chaincode{ h2b_array<32>(m_login_data["chain_code"]) };
        const pub_key_t main_pubkey{ h2b_array<EC_PUBLIC_KEY_LEN>(m_login_data["public_key"]) };
        const xpub_hdkey main_hdkey(m_net_params.is_main_net(), std::make_pair(main_chaincode, main_pubkey));
        m_login_data["wallet_hash_id"] = main_hdkey.to_hashed_identifier(m_net_params.network());

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

        // Notify the caller of their settings
        if (m_notification_handler != nullptr) {
            const auto settings = get_settings(locker);
            call_notification_handler(
                locker, new nlohmann::json({ { "event", "settings" }, { "settings", settings } }));
        }

        // Notify the caller of 2fa reset status
        if (m_notification_handler != nullptr) {
            const auto& days_remaining = login_data["reset_2fa_days_remaining"];
            const auto& disputed = login_data["reset_2fa_disputed"];
            nlohmann::json reset_status
                = { { "is_active", m_is_locked }, { "days_remaining", days_remaining }, { "is_disputed", disputed } };
            call_notification_handler(
                locker, new nlohmann::json({ { "event", "twofactor_reset" }, { "twofactor_reset", reset_status } }));
        }

        // Notify the caller of the current fees
        on_new_fees(locker, m_login_data["fee_estimates"]);
    }

    void ga_session::update_fiat_rate(ga_session::locker_t& locker, const std::string& rate_str)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        try {
            m_fiat_rate = amount::format_amount(rate_str, 8);
        } catch (const std::exception& e) {
            m_fiat_rate.clear();
            GDK_LOG_SEV(log_level::error)
                << "failed to update fiat rate from string '" << rate_str << "': " << e.what();
        }
    }

    void ga_session::update_spending_limits(ga_session::locker_t& locker, const nlohmann::json& limits)
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
        return m_block_height;
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

    std::unique_ptr<ga_session::locker_t> ga_session::get_multi_call_locker(uint32_t category_flags, bool wait_for_lock)
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
            asio::post(m_pool, [this, subaccounts, details] { on_new_transaction(subaccounts, details); });
            return;
        }

        no_std_exception_escape([&]() {
            using namespace std::chrono_literals;

            GDK_RUNTIME_ASSERT(locker.owns_lock());

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

            for (auto subaccount : subaccounts) {
                const auto p = m_subaccounts.find(subaccount);
                // TODO: Handle other logged in sessions creating subaccounts
                GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");

                // Mark the balances of each affected subaccount dirty
                p->second["has_transactions"] = true;
                p->second.erase("satoshi");

                // Update affected subaccounts as required
                m_tx_list_caches.on_new_transaction(subaccount, details);
            }
            m_nlocktimes.reset();

            if (m_notification_handler == nullptr) {
                return;
            }

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
            call_notification_handler(
                locker, new nlohmann::json({ { "event", "transaction" }, { "transaction", std::move(details) } }));
        });
    }

    void ga_session::on_new_block(nlohmann::json details)
    {
        auto locker_p{ get_multi_call_locker(MC_TX_CACHE, false) };
        auto& locker = *locker_p;

        if (!locker.owns_lock()) {
            // Try again: 'post' this to allow the competing thread to proceed.
            asio::post(m_pool, [this, details] { on_new_block(details); });
            return;
        }

        no_std_exception_escape([&]() {
            GDK_RUNTIME_ASSERT(locker.owns_lock());
            json_rename_key(details, "count", "block_height");
            details["initial_timestamp"] = m_earliest_block_time;

            // Update the tx list cache before we update our own block height,
            // in case this is a reorg (in which case 'diverged_count'refers to
            // blocks diverged from the current GA tip)
            m_tx_list_caches.on_new_block(m_block_height, details);

            const uint32_t block_height = details["block_height"];
            if (block_height > m_block_height) {
                m_block_height = block_height;
            }

            if (m_notification_handler != nullptr) {
                details.erase("diverged_count");
                call_notification_handler(
                    locker, new nlohmann::json({ { "event", "block" }, { "block", std::move(details) } }));
            }
        });
    }

    void ga_session::on_new_fees(locker_t& locker, const nlohmann::json& details)
    {
        no_std_exception_escape([&]() {
            GDK_RUNTIME_ASSERT(locker.owns_lock());
            auto new_estimates = set_fee_estimates(locker, details);

            // Note: notification recipient must destroy the passed JSON
            if (m_notification_handler != nullptr) {
                call_notification_handler(
                    locker, new nlohmann::json({ { "event", "fees" }, { "fees", new_estimates } }));
            }
        });
    }

    nlohmann::json ga_session::login(const std::string& mnemonic, const std::string& password)
    {
        GDK_LOG_NAMED_SCOPE("login");

        locker_t locker(m_mutex);

        GDK_RUNTIME_ASSERT_MSG(!m_signer, "re-login on an existing session always fails");
        return login(locker, password.empty() ? mnemonic : decrypt_mnemonic(mnemonic, password));
    }

    void ga_session::push_appearance_to_server(ga_session::locker_t& locker) const
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        const auto appearance = mp_cast(m_login_data["appearance"]);
        wamp_call(locker, "login.set_appearance", appearance.get());
    }

    nlohmann::json ga_session::authenticate(const std::string& sig_der_hex, const std::string& path_hex,
        const std::string& root_xpub_bip32, const std::string& device_id, const nlohmann::json& hw_device)
    {
        locker_t locker(m_mutex);
        return authenticate(locker, sig_der_hex, path_hex, root_xpub_bip32, device_id, hw_device);
    }

    nlohmann::json ga_session::authenticate(ga_session::locker_t& locker, const std::string& sig_der_hex,
        const std::string& path_hex, const std::string& root_xpub_bip32, const std::string& device_id,
        const nlohmann::json& hw_device)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        if (m_signer == nullptr) {
            GDK_LOG_SEV(log_level::debug) << "authenticate called for hardware device";
            // Logging in with a hardware wallet; create our proxy signer
            m_signer = std::make_shared<hardware_signer>(m_net_params, hw_device);
        }

        // TODO: If no device id is given, generate one, update our settings and
        // call the storage interface to store the settings (once storage/caching is implemented)
        std::string id = device_id.empty() ? "fake_dev_id" : device_id;
        const auto user_agent = get_user_agent(m_signer->supports_arbitrary_scripts(), m_user_agent);

        auto result = wamp_call(locker, "login.authenticate", sig_der_hex, false, path_hex, device_id, user_agent);
        nlohmann::json login_data = wamp_cast_json(result);

        if (login_data.is_boolean()) {
            throw login_error(res::id_login_failed);
        }

        const bool is_wallet_locked = json_get_value(login_data, "reset_2fa_active", false);
        const std::string server_hmac = login_data["client_blob_hmac"];
        bool is_blob_on_server = !client_blob::is_zero_hmac(server_hmac);

        if (!is_wallet_locked && !is_blob_on_server) {
            // No client blob: create one, save it to the server and cache it,
            // but only if the wallet isn't locked for a two factor reset.
            // Subaccount names
            for (const auto& sa : login_data["subaccounts"]) {
                m_blob.set_subaccount_name(sa["pointer"], json_get_value(sa, "name"));
            }
            // Tx memos
            nlohmann::json tx_memos = wamp_cast_json(wamp_call(locker, "txs.get_memos"));
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
        }

        if (m_blob_hmac.empty()) {
            // Load our client blob from from the cache if we have one
            m_cache.get_key_value("client_blob", { [this, &server_hmac](const auto& db_blob) {
                if (db_blob) {
                    const std::string db_hmac = client_blob::compute_hmac(m_blob_hmac_key.get(), *db_blob);
                    if (db_hmac == server_hmac) {
                        // Cached blob is current, load it
                        m_blob.load(*m_blob_aes_key, *db_blob);
                        m_blob_hmac = server_hmac;
                    }
                }
            } });
        }

        if (is_blob_on_server) {
            // The server has a blob for this wallet. If we havent got an
            // up to date copy of it loaded yet, do so.
            if (m_blob_hmac.empty()) {
                // No cached blob, or our cached blob is out of date:
                // Load the latest blob from the server and cache it
                load_client_blob(locker, true);
            }
            GDK_RUNTIME_ASSERT(!m_blob_hmac.empty()); // Must have a client blob from this point
        }

        constexpr bool watch_only = false;
        update_login_data(locker, login_data, root_xpub_bip32, watch_only);

        const std::string receiving_id = m_login_data["receiving_id"];
        std::vector<autobahn::wamp_subscription> subscriptions;

        subscriptions.emplace_back(
            subscribe(locker, "com.greenaddress.txs.wallet_" + receiving_id, [this](const autobahn::wamp_event& event) {
                auto details = wamp_cast_json(event);
                if (!ignore_tx_notification(details)) {
                    std::vector<uint32_t> subaccounts = cleanup_tx_notification(details);
                    on_new_transaction(subaccounts, details);
                }
            }));

        subscriptions.emplace_back(
            subscribe(locker, "com.greenaddress.cbs.wallet_" + receiving_id, [this](const autobahn::wamp_event& event) {
                auto details = wamp_cast_json(event);
                locker_t notify_locker(m_mutex);
                // Check the hmac as we will be notified of our own changes
                // when more than one session is logged in at a time.
                if (m_blob_hmac != json_get_value(details, "hmac")) {
                    // Another session has updated our client blob, mark it dirty.
                    m_blob_outdated = true;
                }
            }));

        subscriptions.emplace_back(subscribe(locker, "com.greenaddress.blocks",
            [this](const autobahn::wamp_event& event) { on_new_block(wamp_cast_json(event)); }));

        subscriptions.emplace_back(
            subscribe(locker, "com.greenaddress.fee_estimates", [this](const autobahn::wamp_event& event) {
                locker_t notify_locker(m_mutex);
                on_new_fees(notify_locker, get_fees_as_json(event));
            }));

        m_subscriptions.insert(m_subscriptions.end(), subscriptions.begin(), subscriptions.end());

        //#if 0 // Just for testing pre-segwit txs
        if (json_get_value(m_login_data, "segwit_server", true)
            && !json_get_value(m_login_data["appearance"], "use_segwit", false)) {
            // Enable segwit
            m_login_data["appearance"]["use_segwit"] = true;
            push_appearance_to_server(locker);
        }
        //#endif

        // Notify the caller of their current block
        const uint32_t block_height = m_block_height;
        const auto block_hash = m_login_data["block_hash"];
        locker.unlock();
        on_new_block(nlohmann::json(
            { { "block_height", block_height }, { "block_hash", block_hash }, { "diverged_count", 0 } }));
        return get_post_login_data();
    }

    void ga_session::load_client_blob(ga_session::locker_t& locker, bool encache)
    {
        // Load the latest blob from the server
        GDK_LOG_SEV(log_level::info) << "Fetching client blob from server";
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        auto ret = wamp_cast_json(wamp_call(locker, "login.get_client_blob", 0));
        const auto server_blob = base64_to_bytes(ret["blob"]);
        // Verify the servers hmac
        auto server_hmac = client_blob::compute_hmac(*m_blob_hmac_key, server_blob);
        GDK_RUNTIME_ASSERT_MSG(server_hmac == ret["hmac"], "Bad server client blob");
        m_blob.load(*m_blob_aes_key, server_blob);

        if (encache) {
            encache_client_blob(locker, server_blob);
        }
        m_blob_hmac = server_hmac;
        m_blob_outdated = false; // Blob is now current with the servers view
    }

    bool ga_session::save_client_blob(ga_session::locker_t& locker, const std::string& old_hmac)
    {
        // Generate our encrypted blob + hmac, store on the server, cache locally
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        const auto saved{ m_blob.save(*m_blob_aes_key, *m_blob_hmac_key) };
        auto blob_b64{ base64_string_from_bytes(saved.first) };

        auto result = wamp_call(locker, "login.set_client_blob", blob_b64.get(), 0, saved.second, old_hmac);
        blob_b64.reset();
        if (!wamp_cast<bool>(result)) {
            // Raced with another update on the server, caller should try again
            GDK_LOG_SEV(log_level::info) << "Save client blob race, retrying";
            return false;
        }
        // Blob has been saved on the server, cache it locally
        encache_client_blob(locker, saved.first);
        m_blob_hmac = saved.second;
        m_blob_outdated = false; // Blob is now current with the servers view
        return true;
    }

    void ga_session::encache_client_blob(ga_session::locker_t& locker, const std::vector<unsigned char>& data)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        m_cache.upsert_key_value("client_blob", data);
        m_cache.save_db();
    }

    void ga_session::set_local_encryption_keys(const pub_key_t& public_key, bool is_hw_wallet)
    {
        locker_t locker(m_mutex);
        set_local_encryption_keys(locker, public_key, is_hw_wallet);
    }

    void ga_session::set_local_encryption_keys(
        ga_session::locker_t& locker, const pub_key_t& public_key, bool is_hw_wallet)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(m_local_encryption_key == boost::none);
        GDK_RUNTIME_ASSERT(m_blob_aes_key == boost::none);
        GDK_RUNTIME_ASSERT(m_blob_hmac_key == boost::none);
        m_local_encryption_key = pbkdf2_hmac_sha512(public_key, signer::PASSWORD_SALT);
        auto tmp_key = pbkdf2_hmac_sha512(public_key, signer::BLOB_SALT);
        auto tmp_span = gsl::make_span(tmp_key);
        m_blob_aes_key.emplace(sha256(tmp_span.subspan(SHA256_LEN)));
        m_blob_hmac_key.emplace(make_byte_array<SHA256_LEN>(tmp_span.subspan(SHA256_LEN, SHA256_LEN)));
        m_cache.load_db(m_local_encryption_key.get(), is_hw_wallet ? 1 : 0);
        // Save the cache in case we carried forward data from a previous version
        m_cache.save_db(); // No-op if unchanged
        m_nlocktimes.reset();
    }

    void ga_session::on_failed_login()
    {
        try {
            locker_t locker(m_mutex);
            m_signer.reset();
            m_user_pubkeys.reset();
            m_mnemonic.clear();
            m_local_encryption_key = boost::none;
            m_blob_aes_key = boost::none;
            m_blob_hmac_key = boost::none;
            m_blob_outdated = false; // Blob will be reloaded if needed when login succeeds
        } catch (const std::exception& ex) {
        }
    }

    bool ga_session::login_from_cached(const std::string& mnemonic)
    {
        try {
            locker_t locker(m_mutex);
            login(locker, mnemonic);
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    nlohmann::json ga_session::login(ga_session::locker_t& locker, const std::string& mnemonic)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        // Create our signer
        GDK_LOG_SEV(log_level::debug) << "creating signer for mnemonic";
        m_signer = std::make_shared<software_signer>(m_net_params, mnemonic);

        // Create our local user keys repository
        m_user_pubkeys = std::make_unique<ga_user_pubkeys>(m_net_params, m_signer->get_xpub());

        // Cache local encryption key
        const auto pwd_xpub = m_signer->get_xpub(signer::CLIENT_SECRET_PATH);
        constexpr bool is_hw_wallet = false;
        set_local_encryption_keys(locker, pwd_xpub.second, is_hw_wallet);

        // TODO: Unify normal and trezor logins
        const auto challenge_arg = m_signer->get_challenge();
        std::string challenge = wamp_cast(wamp_call(locker, "login.get_challenge", challenge_arg));

        const auto hexder_path = sign_challenge(locker, challenge);
        m_mnemonic = mnemonic;

        return authenticate(
            locker, hexder_path.first, hexder_path.second, std::string(), std::string(), nlohmann::json::object());
    }

    nlohmann::json ga_session::get_settings()
    {
        locker_t locker(m_mutex);
        return get_settings(locker);
    }

    nlohmann::json ga_session::get_settings(ga_session::locker_t& locker)
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
        ga_session::locker_t& locker, const nlohmann::json& src_json, nlohmann::json& dst_json, bool from_settings)
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

    nlohmann::json ga_session::login_with_pin(const std::string& pin, const nlohmann::json& pin_data)
    {
        // FIXME: clear password after use
        const auto password = get_pin_password(pin, pin_data.at("pin_identifier"));
        const std::string salt = pin_data.at("salt");
        const auto key = pbkdf2_hmac_sha512_256(password, ustring_span(salt));

        // FIXME: clear data after use
        const auto data = nlohmann::json::parse(aes_cbc_decrypt(key, pin_data.at("encrypted_data")));

        return login(data.at("mnemonic"), std::string());
    }

    nlohmann::json ga_session::login_watch_only(const std::string& username, const std::string& password)
    {
        const std::map<std::string, std::string> args = { { "username", username }, { "password", password } };
        const auto user_agent = get_user_agent(true, m_user_agent);
        nlohmann::json login_data = wamp_cast_json(wamp_call("login.watch_only_v2", "custom", args, user_agent));

        if (login_data.is_boolean()) {
            throw login_error(res::id_login_failed);
        }
        locker_t locker(m_mutex);
        m_signer = std::make_shared<watch_only_signer>(m_net_params);
        constexpr bool watch_only = true;
        update_login_data(locker, login_data, std::string(), watch_only);

        const std::string receiving_id = m_login_data["receiving_id"];
        std::vector<autobahn::wamp_subscription> subscriptions;

        subscriptions.emplace_back(
            subscribe(locker, "com.greenaddress.txs.wallet_" + receiving_id, [this](const autobahn::wamp_event& event) {
                auto details = wamp_cast_json(event);
                if (!ignore_tx_notification(details)) {
                    std::vector<uint32_t> subaccounts = cleanup_tx_notification(details);
                    on_new_transaction(subaccounts, details);
                }
            }));

        m_subscriptions.insert(m_subscriptions.end(), subscriptions.begin(), subscriptions.end());

        // Notify the caller of their current block
        const uint32_t block_height = m_block_height;
        const auto block_hash = m_login_data["block_hash"];
        locker.unlock();
        on_new_block(nlohmann::json(
            { { "block_height", block_height }, { "block_hash", block_hash }, { "diverged_count", 0 } }));

        return get_post_login_data();
    }

    void ga_session::register_subaccount_xpubs(const std::vector<std::string>& bip32_xpubs)
    {
        locker_t locker(m_mutex);

        GDK_RUNTIME_ASSERT(!m_subaccounts.empty());
        GDK_RUNTIME_ASSERT(bip32_xpubs.size() == m_subaccounts.size());
        GDK_RUNTIME_ASSERT(!m_user_pubkeys);

        m_user_pubkeys = std::make_unique<ga_user_pubkeys>(m_net_params, make_xpub(bip32_xpubs[0]));
        for (size_t i = 1; i < m_subaccounts.size(); ++i) {
            m_user_pubkeys->add_subaccount(m_subaccounts[i]["pointer"], make_xpub(bip32_xpubs[i]));
        }
    }

    nlohmann::json ga_session::get_fee_estimates()
    {
        locker_t locker(m_mutex);

        // TODO: augment with last_updated, user preference for display?
        return { { "fees", m_fee_estimates } };
    }

    std::string ga_session::get_mnemonic_passphrase(const std::string& password)
    {
        locker_t locker(m_mutex);

        GDK_RUNTIME_ASSERT(!m_watch_only);
        GDK_RUNTIME_ASSERT(!m_mnemonic.empty());

        return password.empty() ? m_mnemonic : encrypt_mnemonic(m_mnemonic, password);
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
        nlohmann::json details = wamp_cast_json(wamp_call(locker, "login.get_system_message", system_message_id));

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

    void ga_session::ack_system_message(const std::string& message)
    {
        const auto info = get_system_message_info(message);

        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(message == m_system_message_ack);
        GDK_RUNTIME_ASSERT(m_signer != nullptr);

        const auto hash = format_bitcoin_message_hash(ustring_span(info.first));
        const auto sig_der_hex = sig_to_der_hex(m_signer->sign_hash(info.second, hash));

        ack_system_message(locker, info.first, sig_der_hex);
    }

    void ga_session::ack_system_message(const std::string& message_hash_hex, const std::string& sig_der_hex)
    {
        locker_t locker(m_mutex);
        ack_system_message(locker, message_hash_hex, sig_der_hex);
    }

    void ga_session::ack_system_message(
        ga_session::locker_t& locker, const std::string& message_hash_hex, const std::string& sig_der_hex)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        const auto ack_id = m_system_message_ack_id;
        auto result = wamp_call(locker, "login.ack_system_message", ack_id, message_hash_hex, sig_der_hex);
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

    nlohmann::json ga_session::convert_fiat_cents(ga_session::locker_t& locker, amount::value_type fiat_cents) const
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        return amount::convert_fiat_cents(fiat_cents, m_fiat_currency, m_fiat_rate);
    }

    // Idempotent
    bool ga_session::set_watch_only(const std::string& username, const std::string& password)
    {
        return wamp_cast<bool>(wamp_call("addressbook.sync_custom", username, password));
    }

    std::string ga_session::get_watch_only_username()
    {
        auto result = wamp_cast_json(wamp_call("addressbook.get_sync_status"));
        return json_get_value(result, "username");
    }

    // Idempotent
    bool ga_session::remove_account(const nlohmann::json& twofactor_data)
    {
        return wamp_cast<bool>(wamp_call("login.remove_account", mp_cast(twofactor_data).get()));
    }

    nlohmann::json ga_session::get_subaccounts()
    {
        locker_t locker(m_mutex);
        std::vector<nlohmann::json> details;
        details.reserve(m_subaccounts.size());

        for (const auto& sa : m_subaccounts) {
            details.emplace_back(get_subaccount(locker, sa.first));
        }

        return details;
    }

    nlohmann::json ga_session::get_subaccount(uint32_t subaccount)
    {
        locker_t locker(m_mutex);
        return get_subaccount(locker, subaccount);
    }

    nlohmann::json ga_session::get_subaccount_balance_from_server(
        uint32_t subaccount, uint32_t num_confs, bool confidential)
    {
        if (!m_net_params.is_liquid()) {
            auto balance = wamp_cast_json(wamp_call("txs.get_balance", subaccount, num_confs));
            // TODO: Make sure another session didn't change fiat currency
            {
                // Update our exchange rate from the results
                locker_t locker(m_mutex);
                update_fiat_rate(locker, json_get_value(balance, "fiat_exchange"));
            }
            const std::string satoshi_str = json_get_value(balance, "satoshi");
            const amount::value_type satoshi = strtoull(satoshi_str.c_str(), nullptr, 10);
            return { { "btc", satoshi } };
        }
        const auto utxos = get_unspent_outputs(
            { { "subaccount", subaccount }, { "num_confs", num_confs }, { "confidential", confidential } });

        const auto accumulate_if = [](const auto& utxos, auto pred) {
            return std::accumulate(
                std::begin(utxos), std::end(utxos), int64_t{ 0 }, [pred](int64_t init, const nlohmann::json& utxo) {
                    amount::value_type satoshi{ 0 };
                    if (pred(utxo)) {
                        satoshi = utxo.at("satoshi");
                    }
                    return init + satoshi;
                });
        };

        nlohmann::json balance({ { "btc", 0 } });
        for (const auto& item : utxos.items()) {
            const auto& key = item.key();
            if (key != "error") {
                const auto& item_utxos = item.value();
                const amount::value_type satoshi
                    = accumulate_if(item_utxos, [](const auto& utxo) { return !utxo.contains("error"); });
                balance[key] = satoshi;
            }
        }

        return balance;
    }

    nlohmann::json ga_session::get_cached_subaccount(uint32_t subaccount) const
    {
        locker_t locker(m_mutex);
        const auto p = m_subaccounts.find(subaccount);
        GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");
        return p->second;
    }

    nlohmann::json ga_session::get_subaccount(ga_session::locker_t& locker, uint32_t subaccount)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        const bool is_liquid = m_net_params.is_liquid();

        const auto p = m_subaccounts.find(subaccount);
        GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");
        auto& details = p->second;

        const auto p_satoshi = details.find("satoshi");
        if (p_satoshi == details.end() || is_liquid) {
            const auto satoshi = [this, &locker, subaccount] {
                unique_unlock unlocker{ locker };
                return get_subaccount_balance_from_server(subaccount, 0, false);
            }();

            // m_subaccounts is no longer guaranteed to be valid after the call above.
            // e.g. when running concurrently with a reconnection trigger.
            const auto p = m_subaccounts.find(subaccount);
            GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");
            details = p->second;

            const auto p_satoshi = details.find("satoshi");
            if (p_satoshi == details.end() || is_liquid) {
                details["satoshi"] = satoshi;
            }
        }

        return details;
    }

    void ga_session::rename_subaccount(uint32_t subaccount, const std::string& new_name)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT_MSG(!m_is_locked, "Wallet is locked");

        const auto p = m_subaccounts.find(subaccount);
        GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");
        const std::string old_name = json_get_value(p->second, "name");
        if (old_name != new_name) {
            update_blob(locker, std::bind(&client_blob::set_subaccount_name, &m_blob, subaccount, new_name));
            // Look up our subaccount again as iterators may have been invalidated
            m_subaccounts.find(subaccount)->second["name"] = new_name;
        }
    }

    void ga_session::set_subaccount_hidden(uint32_t subaccount, bool is_hidden)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT_MSG(!m_is_locked, "Wallet is locked");

        const auto p = m_subaccounts.find(subaccount);
        GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");
        const bool old_hidden = json_get_value(p->second, "hidden", false);
        if (old_hidden != is_hidden) {
            update_blob(locker, std::bind(&client_blob::set_subaccount_hidden, &m_blob, subaccount, is_hidden));
            // Look up our subaccount again as iterators may have been invalidated
            m_subaccounts.find(subaccount)->second["hidden"] = is_hidden;
        }
    }

    nlohmann::json ga_session::insert_subaccount(ga_session::locker_t& locker, uint32_t subaccount,
        const std::string& name, const std::string& receiving_id, const std::string& recovery_pub_key,
        const std::string& recovery_chain_code, const std::string& recovery_xpub, const std::string& type,
        amount satoshi, bool has_txs, uint32_t required_ca, bool is_hidden)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(m_signer != nullptr);

        GDK_RUNTIME_ASSERT(m_subaccounts.find(subaccount) == m_subaccounts.end());
        GDK_RUNTIME_ASSERT(type == "2of2" || type == "2of3" || type == "2of2_no_recovery");

        // FIXME: replace "pointer" with "subaccount"; pointer should only be used
        // for the final path element in a derivation
        nlohmann::json sa = { { "name", name }, { "pointer", subaccount }, { "receiving_id", receiving_id },
            { "type", type }, { "recovery_pub_key", recovery_pub_key }, { "recovery_chain_code", recovery_chain_code },
            { "recovery_xpub", recovery_xpub }, { "satoshi", { { "btc", satoshi.value() } } },
            { "has_transactions", has_txs }, { "required_ca", required_ca }, { "hidden", is_hidden } };
        m_subaccounts[subaccount] = sa;

        if (subaccount != 0) {
            // Add user and recovery pubkeys for the subaccount
            if (m_user_pubkeys != nullptr && !m_user_pubkeys->have_subaccount(subaccount)) {
                const uint32_t path[2] = { harden(3), harden(subaccount) };
                m_user_pubkeys->add_subaccount(subaccount, m_signer->get_xpub(path));
            }

            if (m_recovery_pubkeys != nullptr && !recovery_chain_code.empty()) {
                m_recovery_pubkeys->add_subaccount(subaccount, make_xpub(recovery_chain_code, recovery_pub_key));
            }
        }

        return sa;
    }

    uint32_t ga_session::get_next_subaccount(const std::string& type)
    {
        // the `type` argument isn't used in ga_session, only in ga_rust
        (void)type;
        locker_t locker(m_mutex);
        const uint32_t subaccount = m_next_subaccount;
        ++m_next_subaccount;
        return subaccount;
    }

    nlohmann::json ga_session::create_subaccount(const nlohmann::json& details, uint32_t subaccount)
    {
        const uint32_t path[2] = { harden(3), harden(subaccount) };

        // FIXME: pass locker throughout subaccount creation
        const auto xpub = [this, &path] {
            locker_t locker(m_mutex);
            GDK_RUNTIME_ASSERT(m_signer != nullptr);
            return m_signer->get_bip32_xpub(path);
        }();
        return create_subaccount(details, subaccount, xpub);
    }

    nlohmann::json ga_session::create_subaccount(
        const nlohmann::json& details, uint32_t subaccount, const std::string& xpub)
    {
        const std::string name = details.at("name");
        const std::string type = details.at("type");
        std::string recovery_mnemonic = json_get_value(details, "recovery_mnemonic");
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
            = wamp_cast(wamp_call("txs.create_subaccount_v2", subaccount, std::string(), type, xpubs, sigs));

        locker_t locker(m_mutex);
        constexpr bool has_txs = false;
        m_user_pubkeys->add_subaccount(subaccount, make_xpub(xpub));
        constexpr bool is_hidden = false;
        nlohmann::json subaccount_details = insert_subaccount(locker, subaccount, name, recv_id, recovery_pub_key,
            recovery_chain_code, recovery_bip32_xpub, type, amount(), has_txs, 0, is_hidden);

        if (type == "2of3") {
            subaccount_details["recovery_mnemonic"] = recovery_mnemonic;
            subaccount_details["recovery_xpub"] = recovery_bip32_xpub;
        }
        if (!name.empty()) {
            update_blob(locker, std::bind(&client_blob::set_subaccount_name, &m_blob, subaccount, name));
        }
        return subaccount_details;
    }

    void ga_session::update_blob(locker_t& locker, std::function<bool()> update_fn)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
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

    // Idempotent
    template <typename T>
    void ga_session::change_settings(const std::string& key, const T& value, const nlohmann::json& twofactor_data)
    {
        auto result = wamp_call("login.change_settings", key, value, mp_cast(twofactor_data).get());
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
        ga_session::locker_t& locker, const std::string& currency, const std::string& exchange)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        auto fiat_rate = wamp_cast_nil(wamp_call(locker, "login.set_pricing_source_v2", currency, exchange));

        m_fiat_source = exchange;
        m_fiat_currency = currency;
        update_fiat_rate(locker, fiat_rate.get_value_or(std::string()));
    }

    bool ga_session::unblind_utxo(nlohmann::json& utxo, const std::string& policy_asset)
    {
        amount::value_type value;

        if (boost::conversion::try_lexical_convert(json_get_value(utxo, "value"), value)) {
            utxo["satoshi"] = value;
            utxo["assetblinder"] = ZEROS;
            utxo["amountblinder"] = ZEROS;
            const auto asset_tag = h2b(utxo.value("asset_tag", policy_asset));
            GDK_RUNTIME_ASSERT(asset_tag[0] == 0x1);
            utxo["asset_id"] = b2h_rev(gsl::make_span(asset_tag.data() + 1, asset_tag.size() - 1));
            utxo["confidential"] = false;
            return false; // Cache not updated
        }
        if (utxo.contains("txhash")) {
            const auto txhash = h2b(utxo.at("txhash"));
            const auto vout = utxo["pt_idx"];
            locker_t locker(m_mutex);
            const auto value = m_cache.get_liquid_output(txhash, vout);
            if (value) {
                utxo.insert(value->begin(), value->end());
                utxo["confidential"] = true;
                return false; // Cache not updated
            }
        }
        const auto rangeproof = h2b(utxo.at("range_proof"));
        const auto commitment = h2b(utxo.at("commitment"));
        const auto nonce_commitment = h2b(utxo.at("nonce_commitment"));
        const auto asset_tag = h2b(utxo.at("asset_tag"));
        const auto extra_commitment = h2b(utxo.at("script"));

        GDK_RUNTIME_ASSERT(asset_tag[0] == 0xa || asset_tag[0] == 0xb);

        const auto blinding_key = [this, &extra_commitment]() -> boost::optional<std::array<unsigned char, 32>> {
            locker_t locker(m_mutex);
            GDK_RUNTIME_ASSERT(m_signer != nullptr);

            if (m_signer->is_hw_device()) {
                return boost::none;
            }

            // if it's software signer, fetch the blinding key immediately
            return m_signer->get_blinding_key_from_script(extra_commitment);
        }();

        try {
            unblind_t unblinded;
            if (blinding_key) {
                unblinded = asset_unblind(
                    *blinding_key, rangeproof, commitment, nonce_commitment, extra_commitment, asset_tag);
            } else if (has_blinding_nonce(utxo.at("nonce_commitment"), utxo.at("script"))) {
                const auto blinding_nonce = get_blinding_nonce(utxo.at("nonce_commitment"), utxo.at("script"));
                unblinded
                    = asset_unblind_with_nonce(blinding_nonce, rangeproof, commitment, extra_commitment, asset_tag);
            } else {
                // hw and missing nonce in the map
                utxo["error"] = "missing blinding nonce";
                return false; // Cache not updated
            }

            utxo["satoshi"] = std::get<3>(unblinded);
            // Return in display order
            utxo["assetblinder"] = b2h_rev(std::get<2>(unblinded));
            utxo["amountblinder"] = b2h_rev(std::get<1>(unblinded));
            utxo["asset_id"] = b2h_rev(std::get<0>(unblinded));
            utxo["confidential"] = true;
            if (utxo.contains("txhash")) {
                const auto txhash = h2b(utxo.at("txhash"));
                const auto vout = utxo["pt_idx"];

                locker_t locker(m_mutex);
                // check again, we released the lock earlier, so some other thread could have started to unblind too
                if (!m_cache.get_liquid_output(txhash, vout)) {
                    m_cache.insert_liquid_output(txhash, vout, utxo);
                    return true; // Cache was updated
                }
            }
        } catch (const std::exception& ex) {
            utxo["error"] = "failed to unblind utxo";
        }
        return false; // Cache not updated
    }

    nlohmann::json ga_session::cleanup_utxos(nlohmann::json& utxos, const std::string& policy_asset)
    {
        bool updated_cache = false;

        for (auto& utxo : utxos) {
            // Clean up the type of returned values
            const bool external = !json_get_value(utxo, "private_key").empty();

            const script_type utxo_script_type = utxo["script_type"];

            // Address type is generated for spendable UTXOs
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
                if (external) {
                    // UTXO generated by sweeping, so its spendable
                    addr_type = address_type::p2pkh;
                }
                break;
            }
            utxo["address_type"] = addr_type;

            if (external) {
                json_rename_key(utxo, "tx_hash", "txhash");
                json_rename_key(utxo, "tx_pos", "pt_idx");
                utxo["satoshi"] = json_get_value<amount::value_type>(utxo, "value");
            } else {
                // TODO: check data returned by server for blinded utxos
                if (!policy_asset.empty()) {
                    if (json_get_value(utxo, "is_relevant", true)) {
                        updated_cache |= unblind_utxo(utxo, policy_asset);
                    }
                } else {
                    amount::value_type value;
                    GDK_RUNTIME_ASSERT(boost::conversion::try_lexical_convert(json_get_value(utxo, "value"), value));
                    utxo["satoshi"] = value;
                }
            }
            utxo.erase("value");
            if (utxo.find("block_height") != utxo.end() && utxo["block_height"].is_null()) {
                utxo["block_height"] = 0;
            }
            json_add_if_missing(utxo, "subtype", 0u);
        }

        if (updated_cache) {
            locker_t locker(m_mutex);
            m_cache.save_db();
        }
        return utxos;
    }

    tx_list_cache::container_type ga_session::get_tx_list(ga_session::locker_t& locker, uint32_t subaccount,
        uint32_t page_id, const std::string& start_date, const std::string& end_date, nlohmann::json& state_info)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        const std::vector<std::string> date_range{ start_date, end_date };

        auto result
            = wamp_call(locker, "txs.get_list_v2", page_id, std::string(), std::string(), date_range, subaccount);
        nlohmann::json txs = wamp_cast_json(result);

        // Update block height and fiat rate in our state info
        const uint32_t block_height = txs["cur_block"];
        if (block_height > state_info["cur_block"]) {
            state_info["cur_block"] = block_height;
        }
        // Note: fiat_value is actually the fiat exchange rate
        if (!txs["fiat_value"].is_null()) {
            state_info["fiat_exchange"] = txs["fiat_value"];
        }

        auto& tx_list = txs["list"];
        return tx_list_cache::container_type{ std::make_move_iterator(tx_list.begin()),
            std::make_move_iterator(tx_list.end()) };
    }

    tx_list_cache::container_type ga_session::get_raw_transactions(uint32_t subaccount, uint32_t first, uint32_t count)
    {
        if (!count) {
            return tx_list_cache::container_type();
        }

        auto locker_p{ get_multi_call_locker(MC_TX_CACHE, true) };
        auto& locker = *locker_p;

        // Mark for other threads that a tx cache affecting call is running
        m_multi_call_category |= MC_TX_CACHE;
        const auto cleanup = gsl::finally([this]() { m_multi_call_category &= ~MC_TX_CACHE; });

        auto&& server_get = [this, &locker, subaccount](uint32_t page_id, const std::string& start_date,
                                const std::string& end_date, nlohmann::json& state_info) {
            return get_tx_list(locker, subaccount, page_id, start_date, end_date, state_info);
        };

        tx_list_cache::container_type tx_list;
        nlohmann::json state_info;
        std::tie(tx_list, state_info) = m_tx_list_caches.get(subaccount)->get(first, count, server_get);

        // Update our local block height from the returned results
        // TODO: Use block_hash/height reversal to detect reorgs & uncache

        if (state_info.contains("cur_block") && state_info["cur_block"] > m_block_height) {
            m_block_height = state_info["cur_block"];
        }

        if (!state_info.at("fiat_exchange").is_null()) {
            const double fiat_rate = state_info["fiat_exchange"];
            update_fiat_rate(locker, std::to_string(fiat_rate));
        }

        return tx_list;
    }

    nlohmann::json ga_session::get_transactions(const nlohmann::json& details)
    {
        const uint32_t subaccount = details.at("subaccount");
        const uint32_t first = details.at("first");
        const uint32_t count = details.at("count");

        if (json_get_value(details, "clear_cache", false)) {
            // Clear the tx list cache on user request
            locker_t locker(m_mutex);
            m_tx_list_caches.purge_all();
        }

        tx_list_cache::container_type tx_list = get_raw_transactions(subaccount, first, count);
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
        }

        const auto datadir = gdk_config().value("datadir", std::string{});
        const auto path = datadir + "/state";
        const bool is_liquid = m_net_params.is_liquid();
        auto is_cached = true;
        for (auto& tx_details : tx_list) {
            const uint32_t tx_block_height = json_add_if_missing(tx_details, "block_height", 0, true);
            // TODO: Server should set subaccount to null if this is a spend from multiple subaccounts
            json_add_if_missing(tx_details, "has_payment_request", false);
            const std::string fee_str = tx_details["fee"];
            const amount::value_type fee = strtoull(fee_str.c_str(), nullptr, 10);
            tx_details["fee"] = fee;
            const std::string tx_data = json_get_value(tx_details, "data");
            tx_details.erase("data");
            const uint32_t tx_size = tx_details["size"];
            tx_details.erase("size");
            if (!tx_data.empty()) {
                // Only unconfirmed transactions are returned with the tx hex.
                // In this case update the size, weight etc.
                // At the moment to fetch the correct info for confirmed
                // transactions, callers must call get_transaction_details
                // on the hash of the confirmed transaction.
                // Once caching is implemented this info can be populated up
                // front so callers can always expect it.
                const auto tx = tx_from_hex(tx_data, tx_flags(is_liquid));

                update_tx_info(m_net_params, tx, tx_details);
            } else {
                tx_details["transaction_size"] = tx_size;
                tx_details["transaction_weight"] = tx_details["vsize"].get<uint32_t>() * 4;
                json_rename_key(tx_details, "vsize", "transaction_vsize");
            }
            // Compute fee in satoshi/kb, with the best integer accuracy we can
            const uint32_t tx_vsize = tx_details["transaction_vsize"];
            tx_details["fee_rate"] = fee * 1000 / tx_vsize;

            std::map<std::string, amount> received, spent;
            std::map<uint32_t, nlohmann::json> in_map, out_map;
            std::set<std::string> unique_asset_ids;

            // Clean up and categorize the endpoints
            cleanup_utxos(tx_details["eps"], m_net_params.policy_asset());

            for (auto& ep : tx_details["eps"]) {
                ep.erase("id");
                json_add_if_missing(ep, "subaccount", 0, true);
                json_rename_key(ep, "pubkey_pointer", "pointer");
                json_rename_key(ep, "ad", "address");
                json_add_if_missing(ep, "pointer", 0, true);
                json_add_if_missing(ep, "address", std::string(), true);
                ep.erase("is_credit");

                const bool is_tx_output = json_get_value(ep, "is_output", false);
                const bool is_relevant = json_get_value(ep, "is_relevant", false);

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
                GDK_RUNTIME_ASSERT(m.emplace(pt_idx, ep).second);
            }

            // Store the endpoints as inputs/outputs in tx index order
            nlohmann::json::array_t inputs, outputs;
            for (auto& it : in_map) {
                inputs.emplace_back(it.second);
            }
            tx_details["inputs"] = inputs;

            for (auto& it : out_map) {
                outputs.emplace_back(it.second);
            }
            tx_details["outputs"] = outputs;
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
                tx_details["type"] = "unblindable";
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
                    if (is_liquid) {
                        const std::string script = ep["script"];
                        if (script.empty()) {
                            continue;
                        }
                    }
                    std::string addressee;
                    if (!json_get_value(ep, "is_relevant", false)) {
                        // Add unique addressees that aren't ourselves
                        const auto& social_destination = ep.find("social_destination");
                        if (social_destination != ep.end()) {
                            if (social_destination->is_object()) {
                                addressee = (*social_destination)["name"];
                            } else {
                                addressee = *social_destination;
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

            if (m_spv_enabled) {
                tx_details["spv_verified"] = "in_progress";
                if (!datadir.empty() && is_cached) {
                    nlohmann::json net_params = m_net_params.get_json();
                    net_params["electrum_url"] = m_electrum_url;
                    net_params["tls"] = m_electrum_tls;

                    const nlohmann::json verify_params
                        = { { "txid", tx_details["txhash"] }, { "height", tx_details["block_height"] },
                              { "path", path }, { "network", net_params }, { "encryption_key", "TBD" } };

                    const auto verify_result = spv_verify_tx(verify_params);
                    GDK_LOG_SEV(log_level::debug) << "spv_verify_tx:" << verify_result;
                    if (verify_result == 0) {
                        // Cannot verify because tx height > headers height
                        is_cached = false; // only one blocking header download call per cycle
                        asio::post(m_pool, [verify_params] {
                            // Starts a separate thread to download headers
                            while (true) {
                                const auto verify_result = spv_verify_tx(verify_params);
                                if (verify_result != 0) {
                                    break;
                                }
                            }
                        });
                    } else if (verify_result == 1) {
                        tx_details["spv_verified"] = "verified";
                    } else if (verify_result == 2) {
                        tx_details["spv_verified"] = "not_verified";
                    } else if (verify_result == 3) {
                        tx_details["spv_verified"] = "disabled";
                    } else if (verify_result == 4) {
                        tx_details["spv_verified"] = "not_longest";
                    } else if (verify_result == 5) {
                        tx_details["spv_verified"] = "unconfirmed";
                    }
                }
            } else {
                tx_details["spv_verified"] = "disabled";
            }
            tx_details["addressees"] = addressees;
            tx_details["user_signed"] = true;
            tx_details["server_signed"] = true;
        }

        return tx_list;
    }

    autobahn::wamp_subscription ga_session::subscribe(
        ga_session::locker_t& locker, const std::string& topic, const autobahn::wamp_event_handler& callback)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        unique_unlock unlocker(locker);
        autobahn::wamp_subscription sub;
        auto subscribe_future
            = m_session->subscribe(topic, callback, autobahn::wamp_subscribe_options("exact"))
                  .then(boost::launch::deferred,
                      [&sub](boost::future<autobahn::wamp_subscription> subscription) { sub = subscription.get(); });
        subscribe_future.get();
        GDK_LOG_SEV(log_level::debug) << "subscribed to topic:" << sub.id();
        return sub;
    }

    void ga_session::set_notification_handler(GA_notification_handler handler, void* context)
    {
        locker_t locker(m_mutex);
        set_notification_handler(locker, handler, context);
    }

    void ga_session::set_notification_handler(locker_t& locker, GA_notification_handler handler, void* context)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        m_notification_handler = handler;
        m_notification_context = context;
    }

    void ga_session::call_notification_handler(locker_t& locker, nlohmann::json* details)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(m_notification_handler != nullptr);
        // Note: notification recipient must destroy the passed JSON
        const auto details_c = reinterpret_cast<GA_json*>(details);
        {
            GA_notification_handler handler = m_notification_handler;
            void* context = m_notification_context;

            unique_unlock unlocker(locker);
            handler(context, details_c);
        }
        if (details_c == nullptr) {
            set_notification_handler(locker, nullptr, nullptr);
        }
    }

    amount ga_session::get_dust_threshold() const
    {
        locker_t locker(m_mutex);
        const amount::value_type v = m_login_data.at("dust");
        return amount(v);
    }

    nlohmann::json ga_session::get_blinded_scripts(const nlohmann::json& details)
    {
        GDK_RUNTIME_ASSERT(m_net_params.is_liquid());

        // Get the wallet transactions from the tx list cache
        std::vector<uint32_t> subaccounts;
        if (details.contains("subaccount")) {
            // Only get txs for specified subaccount
            subaccounts.push_back(details["subaccount"]);
        } else {
            // No subaccount specified - get transactions for all subaccounts
            locker_t locker(m_mutex);
            for (const auto& subaccount : m_subaccounts) {
                subaccounts.push_back(subaccount.second["pointer"]);
            }
        }

        nlohmann::json answer = nlohmann::json::array();
        std::set<std::pair<std::string, std::string>> no_dups;

        for (const uint32_t sa : subaccounts) {
            const auto tx_list = get_raw_transactions(sa, 0, 0xffffffff);

            locker_t locker(m_mutex); // For m_cache

            for (const auto& tx : tx_list) {
                for (const auto& ep : tx.at("eps")) {
                    if (!json_get_value(ep, "is_relevant", false)
                        || m_cache.has_liquid_output(h2b(tx.at("txhash")), ep["pt_idx"])) {
                        continue; // Not relevant or already cached; ignore
                    }

                    const std::string asset_tag = json_get_value(ep, "asset_tag");
                    if (asset_tag.empty() || boost::algorithm::starts_with(asset_tag, "01")) {
                        continue; // Unblinded or not an asset; ignore
                    }
                    const std::string nonce_commitment = json_get_value(ep, "nonce_commitment");
                    const std::string script = json_get_value(ep, "script");

                    if (!nonce_commitment.empty() && !script.empty()) {
                        bool was_inserted = no_dups.emplace(std::make_pair(nonce_commitment, script)).second;
                        if (was_inserted && !m_cache.has_liquid_blinding_nonce(h2b(nonce_commitment), h2b(script))) {
                            // Not previously seen and not cached; add to the list to return
                            answer.push_back({ { "script", script }, { "pubkey", nonce_commitment } });
                        }
                    }
                }
            }
        }
        return answer;
    }

    std::vector<unsigned char> ga_session::get_blinding_nonce(const std::string& pubkey, const std::string& script)
    {
        GDK_RUNTIME_ASSERT(!pubkey.empty() && !script.empty());
        locker_t locker(m_mutex);

        const auto nonce = m_cache.get_liquid_blinding_nonce(h2b(pubkey), h2b(script));
        GDK_RUNTIME_ASSERT(nonce != boost::none);
        return nonce.get();
    }

    bool ga_session::has_blinding_nonce(const std::string& pubkey, const std::string& script)
    {
        locker_t locker(m_mutex);
        return m_cache.has_liquid_blinding_nonce(h2b(pubkey), h2b(script));
    }

    void ga_session::set_blinding_nonce(const std::string& pubkey, const std::string& script, const std::string& nonce)
    {
        locker_t locker(m_mutex);
        m_cache.insert_liquid_blinding_nonce(h2b(pubkey), h2b(script), h2b(nonce));
    }

    // Idempotent
    nlohmann::json ga_session::get_unspent_outputs(const nlohmann::json& details)
    {
        const uint32_t subaccount = details.at("subaccount");
        const uint32_t num_confs = details.at("num_confs");
        const bool all_coins = json_get_value(details, "all_coins", false);
        const bool confidential_only = details.value("confidential", false);
        const bool is_liquid = m_net_params.is_liquid();

        GDK_RUNTIME_ASSERT(!confidential_only || is_liquid);

        nlohmann::json utxos = get_all_unspent_outputs(subaccount, num_confs, all_coins);

        const auto nlocktimes = update_nlocktime_info();
        if (!nlocktimes->empty()) {
            for (auto& utxo : utxos) {
                const uint32_t vout = utxo.at("pt_idx");
                const std::string k{ json_get_value(utxo, "txhash") + ":" + std::to_string(vout) };
                const auto it = nlocktimes->find(k);
                if (it != nlocktimes->end()) {
                    utxo["nlocktime_at"] = it->second.at("nlocktime_at");
                }
            };
        }

        cleanup_utxos(utxos, m_net_params.policy_asset());

        nlohmann::json asset_utxos({});
        for (const auto& utxo : utxos) {
            if (utxo.contains("error")) {
                asset_utxos["error"].emplace_back(utxo);
            } else {
                const bool confidential_utxo = is_liquid && utxo.at("confidential");
                // Either return all or only confidential UTXOs
                if (!confidential_only || confidential_utxo) {
                    const auto utxo_asset_id = asset_id_from_json(m_net_params, utxo);
                    asset_utxos[utxo_asset_id].emplace_back(utxo);
                }
            }
        }

        // Sort the utxos such that the oldest are first, with the default
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

        return asset_utxos;
    }

    // Idempotent
    nlohmann::json ga_session::get_all_unspent_outputs(uint32_t subaccount, uint32_t num_confs, bool all_coins)
    {
        return wamp_cast_json(wamp_call("txs.get_all_unspent_outputs", num_confs, subaccount, "any", all_coins));
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

        auto utxos = wamp_cast_json(wamp_call("vault.get_utxos_for_script_hash", script_hash_hex));
        for (auto& utxo : utxos) {
            utxo["private_key"] = b2h(private_key_bytes);
            utxo["compressed"] = compressed;
            utxo["public_key"] = b2h(public_key_bytes);
            utxo["prevout_script"] = b2h(script_bytes);
            utxo["script_type"] = script_type::ga_pubkey_hash_out;
        }

        return cleanup_utxos(utxos, m_net_params.policy_asset());
    }

    // Idempotent
    nlohmann::json ga_session::set_unspent_outputs_status(
        const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        auto result = wamp_call("vault.set_utxo_status", mp_cast(details).get(), mp_cast(twofactor_data).get());
        return wamp_cast_json(result);
    }

    // Idempotent
    nlohmann::json ga_session::get_transaction_details(const std::string& txhash) const
    {
        const std::string tx_data = wamp_cast(wamp_call("txs.get_raw_output", txhash));

        const auto tx = tx_from_hex(tx_data, tx_flags(m_net_params.is_liquid()));
        nlohmann::json ret = { { "txhash", txhash } };
        update_tx_info(m_net_params, tx, ret);
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
        bool watch_only;
        uint32_t csv_blocks;
        std::vector<uint32_t> csv_buckets;
        {
            locker_t locker(m_mutex);
            watch_only = m_watch_only;
            csv_blocks = m_csv_blocks;
            csv_buckets = is_historic ? m_csv_buckets : std::vector<uint32_t>();
        }

        json_rename_key(address, "ad", "address"); // Returned by wamp call get_my_addresses
        json_add_if_missing(address, "branch", 1); // FIXME: Remove when all servers updated
        json_rename_key(address, "addr_type", "address_type");

        const std::string addr_type = address["address_type"];
        const script_type addr_script_type = set_addr_script_type(address, addr_type);

        if (!address.contains("script") && !watch_only) {
            // FIXME: get_my_addresses doesn't return script yet. This is
            // inefficient until the server is updated.
            address["script"] = b2h(output_script_from_utxo(address));
        }
        const auto server_script = h2b(address["script"]);
        const auto server_address = get_address_from_script(m_net_params, server_script, addr_type);

        if (!watch_only) {
            // Compute the address locally to verify the servers data
            const auto script = output_script_from_utxo(address);
            const auto user_address = get_address_from_script(m_net_params, script, addr_type);
            GDK_RUNTIME_ASSERT(server_address == user_address);
            if (address.contains("address")) {
                GDK_RUNTIME_ASSERT(user_address == address["address"]);
            }
        }
        address["address"] = server_address;

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

            const auto script_sha = sha256(server_script);
            std::vector<unsigned char> witness_program = { 0x00, 0x20 };
            witness_program.insert(witness_program.end(), script_sha.begin(), script_sha.end());

            const auto script_hash = scriptpubkey_p2sh_from_hash160(hash160(witness_program));
            address["blinding_script_hash"] = b2h(script_hash);
            // We will add the blinding key later
        }
    }

    nlohmann::json ga_session::get_previous_addresses(uint32_t subaccount, uint32_t last_pointer)
    {
        auto addresses = wamp_cast_json(wamp_call("addressbook.get_my_addresses", subaccount, last_pointer));
        uint32_t seen_pointer = 0;

        for (auto& address : addresses) {
            address["subaccount"] = subaccount;
            update_address_info(address, true);
            json_rename_key(address, "num_tx", "tx_count");
            seen_pointer = address["pointer"];
        }
        return nlohmann::json{ { "subaccount", subaccount }, { "last_pointer", seen_pointer }, { "list", addresses } };
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
        auto address = wamp_cast_json(wamp_call("vault.fund", subaccount, return_pointer, addr_type));
        update_address_info(address, false);
        GDK_RUNTIME_ASSERT(address["address_type"] == addr_type);
        return address;
    }

    nlohmann::json ga_session::get_balance(const nlohmann::json& details)
    {
        const uint32_t subaccount = details.at("subaccount");
        const uint32_t num_confs = details.at("num_confs");
        const uint32_t confidential = json_get_value(details, "confidential", false);

        if (num_confs == 0 && !m_net_params.is_liquid()) {
            // The subaccount details contains the confs=0 balance
            return get_subaccount(subaccount)["satoshi"];
        }
        // Anything other than confs=0 needs to be fetched from the server
        return get_subaccount_balance_from_server(subaccount, num_confs, confidential);
    }

    // Idempotent
    nlohmann::json ga_session::get_available_currencies() const
    {
        return wamp_cast_json(wamp_call("login.available_currencies"));
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
        // subaccounts of type '2of2_no_recovery' (have 'recovery' built in)
        // and '2of3' do not allow csv addresses.
        // short-circuit subaccount 0 as it has a known fixed type
        return subaccount == 0 || get_cached_subaccount(subaccount)["type"] == "2of2";
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

    nlohmann::json ga_session::get_twofactor_config(bool reset_cached)
    {
        locker_t locker(m_mutex);
        return get_twofactor_config(locker, reset_cached);
    }

    nlohmann::json ga_session::get_twofactor_config(locker_t& locker, bool reset_cached)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        if (m_twofactor_config.is_null() || reset_cached) {
            const auto config = wamp_cast_json(wamp_call(locker, "twofactor.get_config"));
            set_twofactor_config(locker, config);
        }
        nlohmann::json ret = m_twofactor_config;

        ret["limits"] = get_spending_limits(locker);
        return ret;
    }

    void ga_session::set_twofactor_config(locker_t& locker, const nlohmann::json& config)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        const auto email_addr = json_get_value(config, "email_addr");
        nlohmann::json email_config
            = { { "enabled", config["email"] }, { "confirmed", config["email_confirmed"] }, { "data", email_addr } };
        nlohmann::json sms_config
            = { { "enabled", config["sms"] }, { "confirmed", config["sms"] }, { "data", config["sms_number"] } };
        nlohmann::json phone_config
            = { { "enabled", config["phone"] }, { "confirmed", config["phone"] }, { "data", config["phone_number"] } };
        // Return the server generated gauth URL until gauth is enabled
        // (after being enabled, the server will no longer return it)
        const bool gauth_enabled = config["gauth"];
        std::string gauth_data = MASKED_GAUTH_SEED;
        if (!gauth_enabled) {
            gauth_data = config["gauth_url"];
        }
        nlohmann::json gauth_config
            = { { "enabled", gauth_enabled }, { "confirmed", gauth_enabled }, { "data", gauth_data } };

        const auto& days_remaining = m_login_data["reset_2fa_days_remaining"];
        const auto& disputed = m_login_data["reset_2fa_disputed"];
        nlohmann::json reset_status
            = { { "is_active", m_is_locked }, { "days_remaining", days_remaining }, { "is_disputed", disputed } };

        nlohmann::json twofactor_config
            = { { "all_methods", ALL_2FA_METHODS }, { "email", email_config }, { "sms", sms_config },
                  { "phone", phone_config }, { "gauth", gauth_config }, { "twofactor_reset", reset_status } };
        std::swap(m_twofactor_config, twofactor_config);
        set_enabled_twofactor_methods(locker);
    }

    void ga_session::set_enabled_twofactor_methods(locker_t& locker)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        std::vector<std::string> enabled_methods;
        enabled_methods.reserve(ALL_2FA_METHODS.size());
        for (const auto& m : ALL_2FA_METHODS) {
            if (json_get_value(m_twofactor_config[m], "enabled", false)) {
                enabled_methods.emplace_back(m);
            }
        }
        m_twofactor_config["enabled_methods"] = enabled_methods;
        m_twofactor_config["any_enabled"] = !enabled_methods.empty();
    }

    std::vector<std::string> ga_session::get_all_twofactor_methods()
    {
        // TODO: Return from 2fa config when methods are returned from the server
        return ALL_2FA_METHODS;
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

        wamp_call(locker, "twofactor.set_email", email, mp_cast(twofactor_data).get());
        // FIXME: update data only after activate?
        m_twofactor_config["email"]["data"] = email;
    }

    void ga_session::activate_email(const std::string& code)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        wamp_call(locker, "twofactor.activate_email", code);
        m_twofactor_config["email"]["confirmed"] = true;
    }

    void ga_session::init_enable_twofactor(
        const std::string& method, const std::string& data, const nlohmann::json& twofactor_data)
    {
        const std::string api_method = "twofactor.init_enable_" + method;

        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        wamp_call(locker, api_method, data, mp_cast(twofactor_data).get());
        m_twofactor_config[method]["data"] = data;
    }

    void ga_session::enable_twofactor(const std::string& method, const std::string& code)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        auto config = wamp_cast_json(wamp_call(locker, "twofactor.enable_" + method, code));
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
            = wamp_cast_json(wamp_call(locker, "twofactor.enable_gauth", code, mp_cast(twofactor_data).get()));
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

        wamp_call(locker, "twofactor.disable_" + method, mp_cast(twofactor_data).get());

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
    void ga_session::auth_handler_request_code(
        const std::string& method, const std::string& action, const nlohmann::json& twofactor_data)
    {
        wamp_call("twofactor.request_" + method, action, mp_cast(twofactor_data).get());
    }

    // Idempotent
    std::string ga_session::auth_handler_request_proxy_code(
        const std::string& action, const nlohmann::json& twofactor_data)
    {
        auto result = wamp_call("twofactor.request_proxy", action, mp_cast(twofactor_data).get());
        return wamp_cast_json(result);
    }

    // Idempotent
    nlohmann::json ga_session::request_twofactor_reset(const std::string& email)
    {
        return wamp_cast_json(wamp_call("twofactor.request_reset", email));
    }

    // Idempotent
    nlohmann::json ga_session::request_undo_twofactor_reset(const std::string& email)
    {
        return wamp_cast_json(wamp_call("twofactor.request_undo_reset", email));
    }

    // Idempotent
    nlohmann::json ga_session::confirm_twofactor_reset(
        const std::string& email, bool is_dispute, const nlohmann::json& twofactor_data)
    {
        auto result = wamp_call("twofactor.confirm_reset", email, is_dispute, mp_cast(twofactor_data).get());
        return wamp_cast_json(result);
    }

    // Idempotent
    nlohmann::json ga_session::confirm_undo_twofactor_reset(
        const std::string& email, const nlohmann::json& twofactor_data)
    {
        auto result = wamp_call("twofactor.confirm_undo_reset", email, mp_cast(twofactor_data).get());
        return wamp_cast_json(result);
    }

    // Idempotent
    nlohmann::json ga_session::cancel_twofactor_reset(const nlohmann::json& twofactor_data)
    {
        return wamp_cast_json(wamp_call("twofactor.cancel_reset", mp_cast(twofactor_data).get()));
    }

    // Idempotent
    nlohmann::json ga_session::set_pin(
        const std::string& mnemonic, const std::string& pin, const std::string& device_id)
    {
        GDK_RUNTIME_ASSERT(pin.length() >= 4);
        GDK_RUNTIME_ASSERT(!device_id.empty() && device_id.length() <= 100);

        // FIXME: secure_array
        const auto seed = bip39_mnemonic_to_seed(mnemonic);

        // Ask the server to create a new PIN identifier and PIN password
        constexpr bool return_password = true;
        const std::string pin_info = wamp_cast(wamp_call("pin.set_pin_login", pin, device_id, return_password));

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
            { "encrypted_data", aes_cbc_encrypt(key, json) } };
    }

    void ga_session::disable_all_pin_logins()
    {
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(wamp_call("pin.remove_all_pin_logins")));
    }

    // Idempotent
    std::vector<unsigned char> ga_session::get_pin_password(const std::string& pin, const std::string& pin_identifier)
    {
        std::string password = wamp_cast(wamp_call("pin.get_password", pin, pin_identifier));
        return std::vector<unsigned char>(password.begin(), password.end());
    }

    std::shared_ptr<signer> ga_session::get_signer()
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(m_signer != nullptr);
        return m_signer;
    }

    // Post-login idempotent
    ga_pubkeys& ga_session::get_ga_pubkeys()
    {
        GDK_RUNTIME_ASSERT(m_ga_pubkeys != nullptr);
        return *m_ga_pubkeys;
    }

    // Post-login idempotent
    user_pubkeys& ga_session::get_user_pubkeys()
    {
        GDK_RUNTIME_ASSERT_MSG(m_user_pubkeys != nullptr, "Cannot derive keys in watch-only mode");
        return *m_user_pubkeys;
    }

    // Post-login idempotent
    ga_user_pubkeys& ga_session::get_recovery_pubkeys()
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

    std::vector<uint32_t> ga_session::get_subaccount_full_path(uint32_t subaccount, uint32_t pointer)
    {
        if (m_user_pubkeys) {
            locker_t locker(m_mutex);
            return m_user_pubkeys->get_subaccount_full_path(subaccount, pointer);
        }
        return ga_user_pubkeys::get_ga_subaccount_full_path(subaccount, pointer);
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

    ae_protocol_support_level ga_session::ae_protocol_support() const
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(m_signer != nullptr);
        return m_signer->ae_protocol_support();
    }

    std::vector<unsigned char> ga_session::output_script_from_utxo(const nlohmann::json& utxo)
    {
        locker_t locker(m_mutex);
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

    nlohmann::json ga_session::sign_transaction(const nlohmann::json& details)
    {
        return sign_ga_transaction(*this, details);
    }

    nlohmann::json ga_session::send_transaction(const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        GDK_RUNTIME_ASSERT(json_get_value(details, "error").empty());
        GDK_RUNTIME_ASSERT_MSG(json_get_value(details, "user_signed", false), "Tx must be signed before sending");

        nlohmann::json result = details;

        // We must have a tx and it must be signed by the user
        GDK_RUNTIME_ASSERT(result.find("transaction") != result.end());
        GDK_RUNTIME_ASSERT(json_get_value(result, "user_signed", false));
        // Check memo is storable
        const std::string memo = json_get_value(result, "memo");
        check_tx_memo(memo);

        // FIXME: test weight and return error in create_transaction, not here
        const std::string tx_hex = result.at("transaction");
        const size_t MAX_TX_WEIGHT = 400000;
        const uint32_t flags = tx_flags(details.at("liquid"));
        const auto unsigned_tx = tx_from_hex(tx_hex, flags);
        GDK_RUNTIME_ASSERT(tx_get_weight(unsigned_tx) < MAX_TX_WEIGHT);

        nlohmann::json private_data;
        // FIXME: social_destination/social_destination_type/payreq if BIP70

        const auto blinding_nonces_p = result.find("blinding_nonces");
        if (blinding_nonces_p != result.end()) {
            private_data["blinding_nonces"] = *blinding_nonces_p;
        }

        constexpr bool return_tx = true;
        auto tx_details = wamp_cast_json(wamp_call(
            "vault.send_raw_tx", tx_hex, mp_cast(twofactor_data).get(), mp_cast(private_data).get(), return_tx));

        const amount::value_type decrease = tx_details.at("limit_decrease");
        const auto txhash_hex = tx_details["txhash"];
        result["txhash"] = txhash_hex;
        // Update the details with the server signed transaction, since it
        // may be a slightly different size once signed
        const auto tx = tx_from_hex(tx_details["tx"], flags);
        update_tx_size_info(tx, result);
        result["server_signed"] = true;

        locker_t locker(m_mutex);
        if (!memo.empty()) {
            update_blob(locker, std::bind(&client_blob::set_tx_memo, &m_blob, txhash_hex, memo));
        }
        if (decrease != 0) {
            update_spending_limits(locker, tx_details["limits"]);
        }

        // Notify the tx cache that a new tx is expected
        m_tx_list_caches.on_new_transaction(details.at("subaccount"), { { "txhash", txhash_hex } });

        return result;
    }

    // Idempotent
    std::string ga_session::broadcast_transaction(const std::string& tx_hex)
    {
        return wamp_cast(wamp_call("vault.broadcast_raw_tx", tx_hex));
    }

    // Idempotent
    void ga_session::send_nlocktimes() { GDK_RUNTIME_ASSERT(wamp_cast<bool>(wamp_call("txs.send_nlocktime"))); }

    nlohmann::json ga_session::get_expired_deposits(const nlohmann::json& deposit_details)
    {
        auto asset_utxos = get_unspent_outputs(deposit_details);

        const uint32_t curr_block_height = get_block_height();
        const uint32_t expires_at_block
            = std::max(curr_block_height, deposit_details.value("expires_at_block", curr_block_height));

        std::for_each(std::begin(asset_utxos), std::end(asset_utxos), [expires_at_block](nlohmann::json& utxos) {
            utxos.erase(std::remove_if(std::begin(utxos), std::end(utxos),
                            [expires_at_block](const auto& u) { return u.at("nlocktime_at") > expires_at_block; }),
                std::end(utxos));
        });

        return asset_utxos;
    }

    void ga_session::set_csvtime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        const uint32_t value = locktime_details.at("value");
        locker_t locker(m_mutex);
        // This not only saves a server round trip in case of bad value, but
        // also ensures that the value is recoverable.
        GDK_RUNTIME_ASSERT(std::find(m_csv_buckets.begin(), m_csv_buckets.end(), value) != m_csv_buckets.end());
        auto result = wamp_call(locker, "login.set_csvtime", value, mp_cast(twofactor_data).get());
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));

        m_csv_blocks = value;
    }

    void ga_session::set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        const uint32_t value = locktime_details.at("value");
        auto result = wamp_call("login.set_nlocktime", value, mp_cast(twofactor_data).get());
        GDK_RUNTIME_ASSERT(wamp_cast<bool>(result));

        locker_t locker(m_mutex);
        m_nlocktime = value;
    }

    void ga_session::set_transaction_memo(const std::string& txhash_hex, const std::string& memo)
    {
        check_tx_memo(memo);
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT_MSG(!m_is_locked, "Wallet is locked");
        update_blob(locker, std::bind(&client_blob::set_tx_memo, &m_blob, txhash_hex, memo));
    }

} // namespace sdk
} // namespace ga
