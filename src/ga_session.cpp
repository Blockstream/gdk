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

    gdk_logger_t& websocket_boost_logger::m_log = gdk_logger::get();

    namespace {
        static const std::string SOCKS5("socks5://");
        static const std::string USER_AGENT("[v2,sw,csv]");
        static const std::string USER_AGENT_NO_CSV("[v2,sw]");
        static const std::string CACHE_UPCOMING_NLOCKTIME("upcomingnlocktime");
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
        static const uint32_t DEFAULT_TOR_SOCKS_WAIT = 15; // maximum timeout for the tor socks to get ready

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

        template <typename T> static nlohmann::json get_json_result(const T& result)
        {
            const auto obj = result.template argument<msgpack::object>(0);
            std::stringstream ss;
            ss << obj;
            return nlohmann::json::parse(ss.str());
        }

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

        static msgpack::object_handle as_messagepack(const nlohmann::json& json)
        {
            if (json.is_null()) {
                return msgpack::object_handle();
            }
            const auto buffer = nlohmann::json::to_msgpack(json);
            return msgpack::unpack(reinterpret_cast<const char*>(buffer.data()), buffer.size());
        }

        inline auto sig_to_der_hex(const ecdsa_sig_t& signature) { return b2h(ec_sig_to_der(signature)); }

        template <typename T>
        void connect_to_endpoint(const wamp_session_ptr& session, const ga_session::transport_t& transport)
        {
            std::array<boost::future<void>, 3> futures;
            futures[0] = boost::get<std::shared_ptr<T>>(transport)->connect().then(
                boost::launch::deferred, [&](boost::future<void> connected) {
                    connected.get();
                    futures[1] = session->start().then(boost::launch::deferred, [&](boost::future<void> started) {
                        started.get();
                        futures[2] = session->join("realm1").then(
                            boost::launch::deferred, [&](boost::future<uint64_t> joined) { joined.get(); });
                    });
                });

            for (auto&& f : futures) {
                f.get();
            }
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
        struct BlindingNoncesHash {
            std::size_t operator()(const std::pair<std::string, std::string>& k) const
            {
                return std::hash<std::string>()(k.first) ^ (std::hash<std::string>()(k.second) << 1);
            }
        };

        std::string get_user_agent(bool supports_csv, const std::string& version)
        {
            const auto& user_agent = supports_csv ? USER_AGENT : USER_AGENT_NO_CSV;
            return user_agent + version;
        }
    } // namespace

    uint32_t websocket_rng_type::operator()() const
    {
        uint32_t b;
        get_random_bytes(sizeof(b), &b, sizeof(b));
        return b;
    }

    event_loop_controller::event_loop_controller(boost::asio::io_context& io)
        : m_work_guard(boost::asio::make_work_guard(io))
    {
        m_run_thread = std::thread([&] { io.run(); });
    }

    void event_loop_controller::reset()
    {
        no_std_exception_escape([this] {
            m_work_guard.reset();
            m_run_thread.join();
        });
    }

    ga_session::ga_session(const nlohmann::json& net_params)
        : m_net_params(network_parameters{ network_parameters::get(net_params.at("name")) })
        , m_proxy(socksify(net_params.value("proxy", std::string{})))
        , m_use_tor(net_params.value("use_tor", false))
        , m_has_network_proxy(!m_proxy.empty())
        , m_io()
        , m_controller(m_io)
        , m_ping_timer(m_io)
        , m_notification_handler(nullptr)
        , m_notification_context(nullptr)
        , m_min_fee_rate(DEFAULT_MIN_FEE)
        , m_earliest_block_time(0)
        , m_next_subaccount(0)
        , m_block_height(0)
        , m_system_message_id(0)
        , m_system_message_ack_id(0)
        , m_watch_only(true)
        , m_is_locked(false)
        , m_tx_last_notification(std::chrono::system_clock::now())
        , m_cache(net_params.at("name"))
        , m_user_agent(net_params.value("user_agent", GDK_COMMIT))
    {
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
        connect_with_tls() ? make_client<client_tls>() : make_client<client>();
    }

    ga_session::~ga_session()
    {
        no_std_exception_escape([this] {
            reset();
            m_controller.reset();
        });
    }

    bool ga_session::is_connected() const
    {
        const bool tls = connect_with_tls();
        return tls ? is_transport_connected<transport_tls>() : is_transport_connected<transport>();
    }

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
            locker_t locker{ m_mutex };
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

    bool ga_session::connect_with_tls() const
    {
        return boost::algorithm::starts_with(m_net_params.get_connection_string(m_use_tor), "wss://");
    }

    void ga_session::set_socket_options()
    {
        auto set_option = [this](auto option) {
            const bool tls = connect_with_tls();
            GDK_RUNTIME_ASSERT(tls ? set_socket_option<transport_tls>(option) : set_socket_option<transport>(option));
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

        const bool tls = connect_with_tls();
        tls ? make_transport<transport_tls>() : make_transport<transport>();
        tls ? connect_to_endpoint<transport_tls>(m_session, m_transport)
            : connect_to_endpoint<transport>(m_session, m_transport);

        set_socket_options();
        start_ping_timer();
    }

    template <typename T>
    std::enable_if_t<std::is_same<T, client>::value> ga_session::set_tls_init_handler(
        __attribute__((unused)) const std::string& host_name)
    {
    }
    template <typename T>
    std::enable_if_t<std::is_same<T, client_tls>::value> ga_session::set_tls_init_handler(const std::string& host_name)
    {
        boost::get<std::unique_ptr<T>>(m_client)->set_tls_init_handler(
            [this, host_name](const websocketpp::connection_hdl) {
                return tls_init_handler_impl(
                    host_name, m_net_params.gait_wamp_cert_roots(), m_net_params.gait_wamp_cert_pins());
            });
    }

    template <typename T> void ga_session::make_client()
    {
        m_client = std::make_unique<T>();
        boost::get<std::unique_ptr<T>>(m_client)->init_asio(&m_io);
        set_tls_init_handler<T>(websocketpp::uri(m_net_params.gait_wamp_url()).get_host());
    }

    template <typename T> void ga_session::make_transport()
    {
        using client_type
            = std::unique_ptr<std::conditional_t<std::is_same<T, transport_tls>::value, client_tls, client>>;

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
        boost::get<client_type>(m_client)->set_pong_timeout_handler(m_heartbeat_handler);
        m_transport = std::make_shared<T>(
            *boost::get<client_type>(m_client), server, m_proxy, m_log_level == logging_levels::debug);
        boost::get<std::shared_ptr<T>>(m_transport)
            ->attach(std::static_pointer_cast<autobahn::wamp_transport_handler>(m_session));
    }

    template <typename T> void ga_session::disconnect_transport() const
    {
        auto transport = boost::get<std::shared_ptr<T>>(m_transport);
        if (!transport) {
            return;
        }

        no_std_exception_escape([&] {
            const auto status = transport->disconnect().wait_for(boost::chrono::seconds(DEFAULT_DISCONNECT_WAIT));
            if (status != boost::future_status::ready) {
                GDK_LOG_SEV(log_level::info) << "future not ready on disconnect";
            }
        });
        no_std_exception_escape([&] { transport->detach(); });
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

    void ga_session::ping_timer_handler(const boost::system::error_code& ec)
    {
        if (ec == boost::asio::error::operation_aborted) {
            return;
        }
        const bool tls = connect_with_tls();
        const bool expect_pong = tls ? ping<transport_tls>() : ping<transport>();
        if (!expect_pong) {
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
            locker_t locker{ m_mutex };
            if (m_notification_handler != nullptr) {
                call_notification_handler(locker, new nlohmann::json({ { "event", event }, { event, details } }));
            }
        });
    }

    void ga_session::try_reconnect()
    {
        GDK_LOG_NAMED_SCOPE("try_reconnect");

        if (!m_network_control.is_enabled()) {
            GDK_LOG_SEV(log_level::info) << "reconnect is disabled. backing off...";
            return;
        }

        if (is_connected()) {
            GDK_LOG_SEV(log_level::info) << "attempting to reconnect but transport still connected. backing off...";
            emit_notification(
                "network", { { "connected", true }, { "login_required", false }, { "heartbeat_timeout", true } });
            return;
        }

        if (!m_network_control.set_reconnect(true)) {
            GDK_LOG_SEV(log_level::info) << "reconnect in progress. backing off...";
            return;
        }

        m_ping_timer.cancel();
        m_network_control.reset();

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

                if (!m_network_control.retrying(backoff_time)) {
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

            m_network_control.set_reconnect(false);

            if (!is_connected()) {
                start_ping_timer();
            }
        });
    }

    void ga_session::stop_reconnect()
    {
        if (m_network_control.reconnecting()) {
            m_network_control.set_exit();
        }
    }

    void ga_session::reconnect_hint(bool enable, bool restart)
    {
        m_network_control.set_enabled(enable);
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
            locker_t locker{ m_mutex };

            if (m_notification_handler != nullptr) {
                const nlohmann::json details{ { "connected", false } };
                call_notification_handler(
                    locker, new nlohmann::json({ { "event", "session" }, { "session", details } }));
            }

            m_signer.reset();
        }

        m_ping_timer.cancel();

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
        connect_with_tls() ? disconnect_transport<transport_tls>() : disconnect_transport<transport>();
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
        const auto cached_value = [this, &type] {
            locker_t locker(m_mutex);
            return m_cache.get(type);
        }();

        std::string last_modified;
        nlohmann::json cached_data = nlohmann::json::object();
        if (cached_value) {
            try {
                cached_data = nlohmann::json::from_msgpack(cached_value->begin(), cached_value->end());
                last_modified = cached_data.at("headers").at("last-modified");
            } catch (const std::exception& e) {
                GDK_LOG_SEV(log_level::warning) << "Error reading cached json: " << e.what();
                cached_data = nlohmann::json::object();
            }
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
            return cached_data;
        }

        GDK_RUNTIME_ASSERT_MSG(data["body"].is_object(), "expected JSON");
        locker_t locker(m_mutex);
        m_cache.upsert_keyvalue(type, nlohmann::json::to_msgpack(data));
        if (m_local_encryption_key) {
            m_cache.save_db(m_local_encryption_key.get());
        }
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

    ga_session::nlocktime_t ga_session::get_upcoming_nlocktime()
    {
        auto upcoming = [this]() -> boost::optional<nlohmann::json> {
            locker_t locker(m_mutex);
            const auto value = m_cache.get(CACHE_UPCOMING_NLOCKTIME);
            if (value) {
                return nlohmann::json::from_msgpack(value->begin(), value->end());
            } else {
                return boost::none;
            }
        }();

        if (!upcoming) {
            wamp_call([&upcoming](wamp_call_result result) { upcoming = get_json_result(result.get()); },
                "com.greenaddress.txs.upcoming_nlocktime");
            locker_t locker(m_mutex);
            m_cache.upsert_keyvalue(CACHE_UPCOMING_NLOCKTIME, nlohmann::json::to_msgpack(upcoming.get()));
        }

        const auto upcoming_l = upcoming.get().at("list");

        std::map<std::pair<std::string, uint32_t>, nlohmann::json> upcoming_nlocktime;
        std::for_each(std::cbegin(upcoming_l), std::cend(upcoming_l), [&upcoming_nlocktime](const auto& v) {
            const auto k = std::make_pair<std::string, uint32_t>(v.at("txhash"), v.at("output_n"));
            upcoming_nlocktime.insert(std::make_pair(k, v));
        });

        return upcoming_nlocktime;
    }

    nlohmann::json ga_session::validate_asset_domain_name(__attribute__((unused)) const nlohmann::json& params)
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
        // FIXME: securely destroy all held data
    }

    std::pair<std::string, std::string> ga_session::sign_challenge(
        ga_session::locker_t& locker, const std::string& challenge)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        auto path_bytes = get_random_bytes<8>();

        std::vector<uint32_t> path(4);
        adjacent_transform(std::begin(path_bytes), std::end(path_bytes), std::begin(path),
            [](auto first, auto second) { return uint32_t((first << 8) + second); });

        const auto challenge_hash = uint256_to_base256(challenge);

        return { sig_to_der_hex(get_signer().sign_hash(path, challenge_hash)), b2h(path_bytes) };
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
        wamp_call([](wamp_call_result result) { GDK_RUNTIME_ASSERT(result.get().argument<bool>(0)); },
            "com.greenaddress.login.register", master_pub_key_hex, master_chain_code_hex, user_agent, gait_path_hex);
    }

    // Idempotent
    std::string ga_session::get_challenge(const std::string& address)
    {
        constexpr bool nlocktime_support = true;
        std::string challenge;
        wamp_call([&challenge](wamp_call_result result) { challenge = result.get().argument<std::string>(0); },
            "com.greenaddress.login.get_trezor_challenge", address, nlocktime_support);
        return challenge;
    }

    void ga_session::upload_confidential_addresses(
        locker_t& locker, uint32_t subaccount, std::vector<std::string> confidential_addresses)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        unique_unlock unlocker(locker);
        GDK_RUNTIME_ASSERT(confidential_addresses.size() > 0);

        bool r{ false };
        {
            wamp_call([&r](wamp_call_result result) { r = result.get().argument<bool>(0); },
                "com.greenaddress.txs.upload_authorized_assets_confidential_address", subaccount,
                confidential_addresses);
        }
        GDK_RUNTIME_ASSERT(r);

        // subtract from the required_ca
        uint32_t original = m_subaccounts[subaccount]["required_ca"];
        if (original > 0) {
            m_subaccounts[subaccount]["required_ca"]
                = confidential_addresses.size() > original ? 0 : original - confidential_addresses.size();
        }
    }

    void ga_session::upload_confidential_addresses(uint32_t subaccount, std::vector<std::string> confidential_addresses)
    {
        locker_t locker(m_mutex);

        upload_confidential_addresses(locker, subaccount, confidential_addresses);
    }

    void ga_session::update_login_data(locker_t& locker, nlohmann::json& login_data, bool watch_only)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

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
        update_fiat_rate(locker, login_data["fiat_exchange"]);

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

            insert_subaccount(locker, subaccount, sa["name"], sa["receiving_id"], recovery_pub_key, recovery_chain_code,
                type, satoshi, json_get_value(sa, "has_txs", false), sa.value("required_ca", 0));

            if (subaccount > m_next_subaccount) {
                m_next_subaccount = subaccount;
            }
        }
        ++m_next_subaccount;

        // Insert the main account so callers can treat all accounts equally
        const std::string satoshi_str = login_data["satoshi"];
        const amount satoshi{ strtoull(satoshi_str.c_str(), nullptr, 10) };
        const bool has_txs = json_get_value(m_login_data, "has_txs", false);
        insert_subaccount(locker, 0, std::string(), m_login_data["receiving_id"], std::string(), std::string(), "2of2",
            satoshi, has_txs, 0);

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
        m_nlocktime = m_login_data["nlocktime_blocks"];

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

        // Notify the caller of their current block
        on_new_block(
            locker, nlohmann::json({ { "block_height", block_height }, { "block_hash", m_login_data["block_hash"] } }));
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

    bool ga_session::have_subaccounts() const
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_subaccounts.empty());
        return m_subaccounts.size() != 1u;
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

    void ga_session::on_new_transaction(locker_t& locker, nlohmann::json details)
    {
        no_std_exception_escape([&]() GDK_REQUIRES(m_mutex) {
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

            for (auto subaccount : affected) {
                const auto p = m_subaccounts.find(subaccount);
                // TODO: Handle other logged in sessions creating subaccounts
                GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");

                // Mark the balances of each affected subaccount dirty
                p->second["has_transactions"] = true;
                p->second.erase("satoshi");

                // Mark cached tx lists as dirty
                m_tx_list_caches.purge(subaccount);
            }
            m_cache.clear_keyvalue(CACHE_UPCOMING_NLOCKTIME);

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

    void ga_session::on_new_block(locker_t& locker, nlohmann::json details)
    {
        no_std_exception_escape([&]() GDK_REQUIRES(m_mutex) {
            GDK_RUNTIME_ASSERT(locker.owns_lock());
            json_rename_key(details, "count", "block_height");
            details["initial_timestamp"] = m_earliest_block_time;
            const uint32_t block_height = details["block_height"];
            if (block_height > m_block_height) {
                m_block_height = block_height;
            }
            if (m_notification_handler != nullptr) {
                details.erase("diverged_count");
                call_notification_handler(
                    locker, new nlohmann::json({ { "event", "block" }, { "block", std::move(details) } }));
            }

            // Erase all cached tx lists
            // This is much simpler than trying to handle updates, potentially with reorgs
            m_tx_list_caches.purge_all();
        });
    }

    void ga_session::on_new_fees(locker_t& locker, const nlohmann::json& details)
    {
        no_std_exception_escape([&]() GDK_REQUIRES(m_mutex) {
            GDK_RUNTIME_ASSERT(locker.owns_lock());
            auto new_estimates = set_fee_estimates(locker, details);

            // Note: notification recipient must destroy the passed JSON
            if (m_notification_handler != nullptr) {
                call_notification_handler(
                    locker, new nlohmann::json({ { "event", "fees" }, { "fees", new_estimates } }));
            }
        });
    }

    void ga_session::login(const std::string& mnemonic, const std::string& password)
    {
        GDK_LOG_NAMED_SCOPE("login");

        locker_t locker{ m_mutex };

        GDK_RUNTIME_ASSERT_MSG(!m_signer, "re-login on an existing session always fails");
        login(locker, password.empty() ? mnemonic : decrypt_mnemonic(mnemonic, password));
    }

    void ga_session::push_appearance_to_server(ga_session::locker_t& locker) const
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        const auto appearance = as_messagepack(m_login_data["appearance"]);

        unique_unlock unlocker(locker);
        wamp_call(
            [](wamp_call_result result) { result.get(); }, "com.greenaddress.login.set_appearance", appearance.get());
    }

    void ga_session::authenticate(const std::string& sig_der_hex, const std::string& path_hex,
        const std::string& device_id, const nlohmann::json& hw_device)
    {
        locker_t locker(m_mutex);
        authenticate(locker, sig_der_hex, path_hex, device_id, hw_device);
    }

    void ga_session::authenticate(ga_session::locker_t& locker, const std::string& sig_der_hex,
        const std::string& path_hex, const std::string& device_id, const nlohmann::json& hw_device)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        if (m_signer == nullptr) {
            GDK_LOG_SEV(log_level::debug) << "authenticate called for hardware device";
            // Logging in with a hardware wallet; create our proxy signer
            m_signer = std::make_unique<hardware_signer>(m_net_params, hw_device);
        }

        // TODO: If no device id is given, generate one, update our settings and
        // call the storage interface to store the settings (once storage/caching is implemented)
        std::string id = device_id.empty() ? "fake_dev_id" : device_id;
        nlohmann::json login_data;
        {
            const auto user_agent = get_user_agent(get_signer().supports_arbitrary_scripts(), m_user_agent);

            unique_unlock unlocker(locker);
            wamp_call([&login_data](wamp_call_result result) { login_data = get_json_result(result.get()); },
                "com.greenaddress.login.authenticate", sig_der_hex, false, path_hex, device_id, user_agent);
        }

        if (login_data.is_boolean()) {
            throw login_error(res::id_login_failed);
        }
        constexpr bool watch_only = false;
        update_login_data(locker, login_data, watch_only);

        const std::string receiving_id = m_login_data["receiving_id"];
        std::vector<autobahn::wamp_subscription> subscriptions;

        subscriptions.emplace_back(
            subscribe(locker, "com.greenaddress.txs.wallet_" + receiving_id, [this](const autobahn::wamp_event& event) {
                locker_t notify_locker(m_mutex);
                on_new_transaction(notify_locker, get_json_result(event));
            }));

        subscriptions.emplace_back(
            subscribe(locker, "com.greenaddress.blocks", [this](const autobahn::wamp_event& event) {
                locker_t notify_locker(m_mutex);
                on_new_block(notify_locker, get_json_result(event));
            }));

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
    }

    void ga_session::set_local_encryption_key(byte_span_t key)
    {
        locker_t locker{ m_mutex };
        GDK_RUNTIME_ASSERT(key.size() == PBKDF2_HMAC_SHA512_LEN);
        GDK_RUNTIME_ASSERT(m_local_encryption_key == boost::none);
        auto tmp = std::array<unsigned char, PBKDF2_HMAC_SHA512_LEN>();
        std::copy(key.begin(), key.end(), tmp.begin());
        m_local_encryption_key = tmp;
        m_cache.load_db(m_local_encryption_key.get(), /*hw*/ 1);
        m_cache.clear_keyvalue(CACHE_UPCOMING_NLOCKTIME);
    }

    void ga_session::on_failed_login()
    {
        try {
            locker_t locker(m_mutex);
            m_signer.reset();
            m_user_pubkeys.reset();
            m_mnemonic.clear();
            m_local_encryption_key = boost::none;
        } catch (const std::exception& ex) {
        }
    }

    bool ga_session::login_from_cached(const std::string& mnemonic)
    {
        try {
            locker_t locker{ m_mutex };
            login(locker, mnemonic);
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    void ga_session::login(ga_session::locker_t& locker, const std::string& mnemonic)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        // Create our signer
        GDK_LOG_SEV(log_level::debug) << "creating signer for mnemonic";
        m_signer = std::make_unique<software_signer>(m_net_params, mnemonic);

        // Create our local user keys repository
        m_user_pubkeys = std::make_unique<ga_user_pubkeys>(m_net_params, get_signer().get_xpub());

        // Cache local encryption password
        const auto pwd_xpub = get_signer().get_xpub(PASSWORD_PATH);

        m_local_encryption_key = [&pwd_xpub] {
            const auto local_password = pbkdf2_hmac_sha512(pwd_xpub.second, PASSWORD_SALT);
            std::array<unsigned char, PBKDF2_HMAC_SHA512_LEN> tmp;
            std::copy(local_password.begin(), local_password.end(), tmp.begin());
            return boost::optional<std::array<unsigned char, PBKDF2_HMAC_SHA512_LEN>>(tmp);
        }();
        m_cache.load_db(m_local_encryption_key.get(), /*sw*/ 0);
        m_cache.clear_keyvalue(CACHE_UPCOMING_NLOCKTIME);

        // TODO: Unify normal and trezor logins
        std::string challenge;
        const auto challenge_arg = get_signer().get_challenge();
        {
            unique_unlock unlocker(locker);
            wamp_call([&challenge](wamp_call_result result) { challenge = result.get().argument<std::string>(0); },
                "com.greenaddress.login.get_challenge", challenge_arg);
        }

        const auto hexder_path = sign_challenge(locker, challenge);
        m_mnemonic = mnemonic;

        authenticate(locker, hexder_path.first, hexder_path.second, std::string(), nlohmann::json::object());
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
        settings["nlocktime"] = m_nlocktime;

        return settings;
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

    void ga_session::login_with_pin(const std::string& pin, const nlohmann::json& pin_data)
    {
        // FIXME: clear password after use
        const auto password = get_pin_password(pin, pin_data.at("pin_identifier"));
        const std::string salt = pin_data.at("salt");
        const auto key = pbkdf2_hmac_sha512_256(password, ustring_span(salt));

        // FIXME: clear data after use
        const auto data = nlohmann::json::parse(aes_cbc_decrypt(key, pin_data.at("encrypted_data")));

        login(data.at("mnemonic"), std::string());
    }

    void ga_session::login_watch_only(const std::string& username, const std::string& password)
    {
        const std::map<std::string, std::string> args = { { "username", username }, { "password", password } };
        nlohmann::json login_data;
        const auto user_agent = get_user_agent(true, m_user_agent);
        wamp_call([&login_data](wamp_call_result result) { login_data = get_json_result(result.get()); },
            "com.greenaddress.login.watch_only_v2", "custom", args, user_agent);

        if (login_data.is_boolean()) {
            throw login_error(res::id_login_failed);
        }
        locker_t locker(m_mutex);
        constexpr bool watch_only = true;
        m_signer = std::make_unique<watch_only_signer>(m_net_params);
        update_login_data(locker, login_data, watch_only);

        const std::string receiving_id = m_login_data["receiving_id"];
        std::vector<autobahn::wamp_subscription> subscriptions;

        subscriptions.emplace_back(
            subscribe(locker, "com.greenaddress.txs.wallet_" + receiving_id, [this](const autobahn::wamp_event& event) {
                locker_t notify_locker(m_mutex);
                on_new_transaction(notify_locker, get_json_result(event));
            }));

        m_subscriptions.insert(m_subscriptions.end(), subscriptions.begin(), subscriptions.end());
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
        nlohmann::json details;
        const auto system_message_id = m_system_message_id;
        {
            unique_unlock unlocker(locker);
            wamp_call([&details](wamp_call_result result) { details = get_json_result(result.get()); },
                "com.greenaddress.login.get_system_message", system_message_id);
        }

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

        const auto hash = format_bitcoin_message_hash(ustring_span(info.first));
        const auto sig_der_hex = sig_to_der_hex(get_signer().sign_hash(info.second, hash));

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
        {
            unique_unlock unlocker(locker);
            wamp_call([](wamp_call_result result) { GDK_RUNTIME_ASSERT(result.get().argument<bool>(0)); },
                "com.greenaddress.login.ack_system_message", ack_id, message_hash_hex, sig_der_hex);
        }

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
        bool r;
        wamp_call([&r](wamp_call_result result) { r = result.get().argument<bool>(0); },
            "com.greenaddress.addressbook.sync_custom", username, password);
        return r;
    }

    std::string ga_session::get_watch_only_username()
    {
        nlohmann::json r;
        wamp_call([&r](wamp_call_result result) { r = get_json_result(result.get()); },
            "com.greenaddress.addressbook.get_sync_status");
        return json_get_value(r, "username");
    }

    // Idempotent
    bool ga_session::remove_account(const nlohmann::json& twofactor_data)
    {
        bool r;
        wamp_call([&r](wamp_call_result result) { r = result.get().argument<bool>(0); },
            "com.greenaddress.login.remove_account", as_messagepack(twofactor_data).get());
        return r;
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

    nlohmann::json ga_session::get_subaccount_balance_from_server(uint32_t subaccount, uint32_t num_confs)
    {
        if (!m_net_params.liquid()) {
            nlohmann::json balance;
            wamp_call([&balance](wamp_call_result result) { balance = get_json_result(result.get()); },
                "com.greenaddress.txs.get_balance", subaccount, num_confs);
            // TODO: Make sure another session didn't change fiat currency
            {
                locker_t locker{ m_mutex };
                update_fiat_rate(locker, balance["fiat_exchange"]); // Note: key name is wrong from the server!
            }
            const std::string satoshi_str = json_get_value(balance, "satoshi");
            const amount::value_type satoshi = strtoull(satoshi_str.c_str(), nullptr, 10);
            return { { "btc", satoshi } };
        }
        const auto utxos = get_unspent_outputs({ { "subaccount", subaccount }, { "num_confs", num_confs } });

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
            const auto& item_utxos = item.value();
            const int64_t satoshi
                = accumulate_if(item_utxos, [](auto utxo) { return utxo.find("error") == utxo.end(); });
            balance[key] = satoshi;
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

        const auto p = m_subaccounts.find(subaccount);
        GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");
        auto& details = p->second;

        const auto p_satoshi = details.find("satoshi");
        if (p_satoshi == details.end() || m_net_params.liquid()) {
            const auto satoshi = [this, &locker, subaccount] {
                unique_unlock unlocker{ locker };
                return get_subaccount_balance_from_server(subaccount, 0);
            }();

            // m_subaccounts is no longer guaranteed to be valid after the call above.
            // e.g. when running concurrently with a reconnection trigger.
            const auto p = m_subaccounts.find(subaccount);
            GDK_RUNTIME_ASSERT_MSG(p != m_subaccounts.end(), "Unknown subaccount");
            details = p->second;

            const auto p_satoshi = details.find("satoshi");
            if (p_satoshi == details.end() || m_net_params.liquid()) {
                details["satoshi"] = satoshi;
            }
        }

        return details;
    }

    void ga_session::rename_subaccount(uint32_t subaccount, const std::string& new_name)
    {
        GDK_RUNTIME_ASSERT_MSG(subaccount != 0, "Main subaccount name cannot be changed");
        wamp_call([](wamp_call_result result) { GDK_RUNTIME_ASSERT(result.get().argument<bool>(0)); },
            "com.greenaddress.txs.rename_subaccount", subaccount, new_name);

        locker_t locker(m_mutex);
        const auto p = m_subaccounts.find(subaccount);
        if (p != m_subaccounts.end()) {
            p->second["name"] = new_name;
        }
    }

    nlohmann::json ga_session::insert_subaccount(ga_session::locker_t& locker, uint32_t subaccount,
        const std::string& name, const std::string& receiving_id, const std::string& recovery_pub_key,
        const std::string& recovery_chain_code, const std::string& type, amount satoshi, bool has_txs,
        uint32_t required_ca)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        GDK_RUNTIME_ASSERT(m_subaccounts.find(subaccount) == m_subaccounts.end());
        GDK_RUNTIME_ASSERT(type == "2of2" || type == "2of3" || type == "2of2_no_recovery");

        // FIXME: replace "pointer" with "subaccount"; pointer should only be used
        // for the final path element in a derivation
        nlohmann::json sa = { { "name", name }, { "pointer", subaccount }, { "receiving_id", receiving_id },
            { "type", type }, { "recovery_pub_key", recovery_pub_key }, { "recovery_chain_code", recovery_chain_code },
            { "satoshi", { { "btc", satoshi.value() } } }, { "has_transactions", has_txs },
            { "required_ca", required_ca } };
        m_subaccounts[subaccount] = sa;

        if (subaccount != 0) {
            // Add user and recovery pubkeys for the subaccount
            if (m_user_pubkeys != nullptr && !m_user_pubkeys->have_subaccount(subaccount)) {
                const uint32_t path[2] = { harden(3), harden(subaccount) };
                m_user_pubkeys->add_subaccount(subaccount, get_signer().get_xpub(path));
            }

            if (m_recovery_pubkeys != nullptr && !recovery_chain_code.empty()) {
                m_recovery_pubkeys->add_subaccount(subaccount, make_xpub(recovery_chain_code, recovery_pub_key));
            }
        }

        return sa;
    }

    uint32_t ga_session::get_next_subaccount()
    {
        locker_t locker(m_mutex);
        const uint32_t subaccount = m_next_subaccount;
        ++m_next_subaccount;
        return subaccount;
    }

    nlohmann::json ga_session::create_subaccount(const nlohmann::json& details)
    {
        const uint32_t subaccount = get_next_subaccount();
        const uint32_t path[2] = { harden(3), harden(subaccount) };

        const auto xpub = [this, &path] {
            locker_t locker{ m_mutex };
            return get_signer().get_bip32_xpub(path);
        }();
        return create_subaccount(details, subaccount, xpub);
    }

    nlohmann::json ga_session::create_subaccount(
        const nlohmann::json& details, uint32_t subaccount, const std::string& xpub)
    {
        const std::string name = details.at("name");
        const std::string type = details.at("type");
        std::string recovery_mnemonic;
        std::string recovery_pub_key;
        std::string recovery_chain_code;
        std::string recovery_bip32_xpub;

        std::vector<std::string> xpubs{ { xpub } };

        GDK_RUNTIME_ASSERT(subaccount < 16384u); // Disallow more than 16k subaccounts

        if (type == "2of3") {
            // The user can provide a recovery mnemonic or bip32 xpub; if not,
            // we generate and return a mnemonic for them.
            std::string mnemonic_or_xpub = json_get_value(details, "recovery_xpub");
            if (mnemonic_or_xpub.empty()) {
                recovery_mnemonic = json_get_value(details, "recovery_mnemonic");
                if (recovery_mnemonic.empty()) {
                    recovery_mnemonic = bip39_mnemonic_from_bytes(get_random_bytes<32>());
                }
                mnemonic_or_xpub = recovery_mnemonic;
            }

            software_signer subsigner(m_net_params, mnemonic_or_xpub);

            const uint32_t mnemonic_path[2] = { harden(3), harden(subaccount) };
            const auto path = recovery_mnemonic.empty() ? empty_span<uint32_t>() : mnemonic_path;
            xpubs.emplace_back(subsigner.get_bip32_xpub(path));
            const auto recovery_xpub = subsigner.get_xpub(path);

            recovery_chain_code = b2h(recovery_xpub.first);
            recovery_pub_key = b2h(recovery_xpub.second);
            recovery_bip32_xpub = subsigner.get_bip32_xpub(path);
        }

        std::string receiving_id;
        {
            wamp_call(
                [&receiving_id](wamp_call_result result) { receiving_id = result.get().argument<std::string>(0); },
                "com.greenaddress.txs.create_subaccount_v2", subaccount, name, type, xpubs);
        }

        locker_t locker(m_mutex);
        constexpr bool has_txs = false;
        m_user_pubkeys->add_subaccount(subaccount, make_xpub(xpub));
        nlohmann::json subaccount_details = insert_subaccount(
            locker, subaccount, name, receiving_id, recovery_pub_key, recovery_chain_code, type, amount(), has_txs, 0);

        if (type == "2of3") {
            subaccount_details["recovery_mnemonic"] = recovery_mnemonic;
            subaccount_details["recovery_xpub"] = recovery_bip32_xpub;
        }
        return subaccount_details;
    }

    // Idempotent
    template <typename T>
    void ga_session::change_settings(const std::string& key, const T& value, const nlohmann::json& twofactor_data)
    {
        bool r{ false };
        wamp_call([&r](wamp_call_result result) { r = result.get().argument<bool>(0); },
            "com.greenaddress.login.change_settings", key, value, as_messagepack(twofactor_data).get());
        GDK_RUNTIME_ASSERT(r);
    }

    void ga_session::change_settings_limits(const nlohmann::json& details, const nlohmann::json& twofactor_data)
    {
        change_settings("tx_limits", as_messagepack(details).get(), twofactor_data);
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

        std::string fiat_rate;
        {
            unique_unlock unlocker(locker);
            wamp_call(
                [&fiat_rate](boost::future<autobahn::wamp_call_result> result) {
                    fiat_rate = result.get().argument<std::string>(0);
                },
                "com.greenaddress.login.set_pricing_source_v2", currency, exchange);
        }

        m_fiat_source = exchange;
        m_fiat_currency = currency;
        update_fiat_rate(locker, fiat_rate);
    }

    void ga_session::unblind_utxo(nlohmann::json& utxo, const std::string& policy_asset)
    {
        amount::value_type value;

        if (boost::conversion::try_lexical_convert(json_get_value(utxo, "value"), value)) {
            utxo["satoshi"] = value;
            utxo["abf"] = b2h(abf_t{ { 0 } });
            utxo["vbf"] = b2h(vbf_t{ { 0 } });
            const auto asset_tag = h2b(utxo.value("asset_tag", policy_asset));
            GDK_RUNTIME_ASSERT(asset_tag[0] == 0x1);
            utxo["asset_id"] = b2h_rev(gsl::make_span(asset_tag.data() + 1, asset_tag.size() - 1));
            utxo["confidential"] = false;
            return;
        }
        if (utxo.contains("txhash")) {
            const auto txhash = h2b(utxo.at("txhash"));
            const auto vout = utxo["pt_idx"];
            locker_t locker(m_mutex);
            const auto value = m_cache.get_liquidoutput(txhash, vout);
            if (value) {
                utxo.insert(value->begin(), value->end());
                utxo["confidential"] = true;
                return;
            }
        }
        const auto rangeproof = h2b(utxo.at("range_proof"));
        const auto commitment = h2b(utxo.at("commitment"));
        const auto nonce_commitment = h2b(utxo.at("nonce_commitment"));
        const auto asset_tag = h2b(utxo.at("asset_tag"));
        const auto extra_commitment = h2b(utxo.at("script"));

        GDK_RUNTIME_ASSERT(asset_tag[0] == 0xa || asset_tag[0] == 0xb);

        const auto blinding_key = [this, &extra_commitment]() -> boost::optional<std::array<unsigned char, 32>> {
            locker_t locker{ m_mutex };

            if (!get_signer().get_hw_device().empty()) {
                return boost::none;
            }

            // if it's software signer, fetch the blinding key immediately
            return get_signer().get_blinding_key_from_script(extra_commitment);
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
                return;
            }

            utxo["satoshi"] = std::get<3>(unblinded);
            utxo["abf"] = b2h(std::get<2>(unblinded));
            utxo["vbf"] = b2h(std::get<1>(unblinded));
            utxo["asset_id"] = b2h_rev(std::get<0>(unblinded));
            utxo["confidential"] = true;
            if (utxo.contains("txhash")) {
                const auto txhash = h2b(utxo.at("txhash"));
                const auto vout = utxo["pt_idx"];

                locker_t locker(m_mutex);
                // check again, we released the lock earlier, so some other thread could have started to unblind too
                if (!m_cache.get_liquidoutput(txhash, vout)) {
                    m_cache.insert_liquidoutput(txhash, vout, utxo);
                }
            }
        } catch (const std::exception& ex) {
            utxo["error"] = "failed to unblind utxo";
        }
    }

    nlohmann::json ga_session::cleanup_utxos(nlohmann::json& utxos, const std::string& policy_asset)
    {
        for (auto& utxo : utxos) {
            // Clean up the type of returned values
            const bool external = !json_get_value(utxo, "private_key").empty();

            const script_type utxo_script_type = utxo["script_type"];

            // Address type is generated for spendable UTXOs
            std::string addr_type;
            switch (utxo_script_type) {
            case script_type::p2sh_p2wsh_csv_fortified_out:
            case script_type::redeem_p2sh_p2wsh_csv_fortified:
                addr_type = address_type::csv;
                break;
            case script_type::p2sh_p2wsh_fortified_out:
            case script_type::redeem_p2sh_p2wsh_fortified:
                addr_type = address_type::p2wsh;
                break;
            case script_type::p2sh_fortified_out:
            case script_type::redeem_p2sh_fortified:
                addr_type = address_type::p2sh;
                break;
            case script_type::pubkey_hash_out:
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
                        unblind_utxo(utxo, policy_asset);
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

        locker_t locker(m_mutex);
        if (m_local_encryption_key) {
            m_cache.save_db(m_local_encryption_key.get());
        }
        return utxos;
    }

    nlohmann::json ga_session::get_transactions(const nlohmann::json& details)
    {
        const uint32_t subaccount = details.at("subaccount");
        const uint32_t first = details.at("first");
        const uint32_t count = details.at("count");

        return m_tx_list_caches.get(subaccount)->get(first, count, [this, subaccount](uint32_t page) {
            return get_transactions(subaccount, page);
        });
    }

    std::vector<nlohmann::json> ga_session::get_transactions(uint32_t subaccount, uint32_t page_id)
    {
        nlohmann::json txs;
        wamp_call([&txs](wamp_call_result result) { txs = get_json_result(result.get()); },
            "com.greenaddress.txs.get_list_v2", page_id, std::string(), std::string(), std::string(), subaccount);

        {
            locker_t locker(m_mutex);
            // Update our local block height from the returned results
            // TODO: Use block_hash/height reversal to detect reorgs & uncache
            const uint32_t block_height = txs["cur_block"];
            if (block_height > m_block_height) {
                m_block_height = block_height;
            }

            // Note: fiat_value is actually the fiat exchange rate
            if (!txs["fiat_value"].is_null()) {
                const double fiat_rate = txs["fiat_value"];
                update_fiat_rate(locker, std::to_string(fiat_rate));
            }
        }
        // Postprocess the returned API data
        // TODO: confidential transactions, social payments/BIP70
        txs.erase("fiat_value");
        txs.erase("cur_block");
        txs.erase("block_hash");
        txs.erase("unclaimed"); // Always empty, never used
        txs.erase("fiat_currency");
        txs["page_id"] = page_id;
        json_add_if_missing(txs, "next_page_id", 0, true);

        // Remove all replaced transactions
        // TODO: Add 'replaces' to txs that were bumped, and mark replaced
        // txs that aren't in our list as double spent
        std::vector<nlohmann::json> tx_list;
        tx_list.reserve(txs["list"].size());
        for (auto& tx_details : txs["list"]) {
            if (tx_details.find("replaced_by") == tx_details.end()) {
                tx_list.emplace_back(tx_details);
            }
        }

        const auto is_liquid = m_net_params.liquid();
        for (auto& tx_details : tx_list) {
            const uint32_t tx_block_height = json_add_if_missing(tx_details, "block_height", 0, true);
            // TODO: Server should set subaccount to null if this is a spend from multiple subaccounts
            json_add_if_missing(tx_details, "has_payment_request", false);
            json_add_if_missing(tx_details, "memo", std::string());
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
                const auto tx = tx_from_hex(
                    tx_data, WALLY_TX_FLAG_USE_WITNESS | (m_net_params.liquid() ? WALLY_TX_FLAG_USE_ELEMENTS : 0));

                update_tx_info(m_net_params, tx, tx_details);
            } else {
                tx_details["transaction_size"] = tx_size;
                if (tx_details.find("vsize") == tx_details.end() || tx_details["vsize"].is_null()) {
                    // FIXME: Can be removed once the backend is upgraded and DB back populated
                    tx_details["transaction_vsize"] = tx_size;
                    tx_details["transaction_weight"] = tx_size * 4;
                } else {
                    tx_details["transaction_weight"] = tx_details["vsize"].get<uint32_t>() * 4;
                    json_rename_key(tx_details, "vsize", "transaction_vsize");
                }
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
                    const auto asset_id = asset_id_from_string(ep.value("asset_id", std::string{}));
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

            GDK_RUNTIME_ASSERT((is_liquid && unique_asset_ids.size() > 0)
                || (unique_asset_ids.size() == 1 && *unique_asset_ids.begin() == "btc"));

            // TODO: improve the detection of tx type.
            bool net_positive{ false };
            bool net_positive_set{ false };
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
            if (net_positive) {
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
        const auto details_c = reinterpret_cast<const GA_json*>(details);
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
        GDK_RUNTIME_ASSERT(m_net_params.liquid());

        nlohmann::json answer = nlohmann::json::array();
        std::unordered_set<std::pair<std::string, std::string>, BlindingNoncesHash> no_dups;

        // there's an hard-limit of 30 pages from the backend, see https://api.greenaddress.it/txs.html#get_list_v2
        for (size_t page_id = 0; page_id < 30; ++page_id) {
            nlohmann::json txs;

            if (details.contains("subaccount") && details.at("subaccount").is_number()) {
                wamp_call([&txs](wamp_call_result result) { txs = get_json_result(result.get()); },
                    "com.greenaddress.txs.get_list_v2", page_id, std::string(), std::string(), std::string(),
                    details.at("subaccount").get<uint32_t>());
            } else {
                // make sure it wasn't set OR it's "all" (the only other value supported)
                GDK_RUNTIME_ASSERT(!details.contains("subaccount") || details.at("subaccount") == "all");

                wamp_call([&txs](wamp_call_result result) { txs = get_json_result(result.get()); },
                    "com.greenaddress.txs.get_list_v2", page_id, std::string(), std::string(), std::string(),
                    std::string("all"));
            }

            // lock to guard m_cache
            locker_t locker(m_mutex);

            for (const auto& tx : txs.at("list")) {
                for (const auto& ep : tx.at("eps")) {
                    const auto txhash = h2b(tx.at("txhash"));
                    const auto vout = ep["pt_idx"];
                    if (m_cache.has_liquidoutput(txhash, vout)) {
                        continue;
                    }

                    const std::string& asset_tag = json_get_value(ep, "asset_tag", std::string{});
                    const std::string& nonce_commitment = json_get_value(ep, "nonce_commitment", std::string{});
                    const std::string& script = json_get_value(ep, "script", std::string{});

                    if (asset_tag.empty() || boost::algorithm::starts_with(asset_tag, "01") // unblinded
                        || !json_get_value(ep, "is_relevant", false) // not relevant
                        || nonce_commitment.empty() || script.empty()) {
                        continue;
                    }

                    const auto map_key = std::make_pair(nonce_commitment, script);

                    // don't ask for the same nonces multiple times
                    if (no_dups.find(map_key) != no_dups.end()
                        || m_cache.has_liquidblindingnonce(h2b(nonce_commitment), h2b(script))) {
                        continue;
                    }

                    no_dups.insert(map_key);
                    answer.push_back({ { "script", script }, { "pubkey", nonce_commitment } });
                }
            }

            // last page since there are less than 30 elements, backends defaults to that number
            if (txs.at("list").size() < 30) {
                break;
            }
        }

        return answer;
    }

    std::array<unsigned char, 32> ga_session::get_blinding_nonce(const std::string& pubkey, const std::string& script)
    {
        GDK_RUNTIME_ASSERT(!pubkey.empty() && !script.empty());
        locker_t locker(m_mutex);

        const auto data = m_cache.get_liquidblindingnonce(h2b(pubkey), h2b(script));
        GDK_RUNTIME_ASSERT(data != boost::none);

        std::array<unsigned char, 32> answer;

        GDK_RUNTIME_ASSERT(data->size() == 32);
        std::copy(data->begin(), data->end(), answer.begin());

        return answer;
    }

    bool ga_session::has_blinding_nonce(const std::string& pubkey, const std::string& script)
    {
        locker_t locker(m_mutex);
        return m_cache.has_liquidblindingnonce(h2b(pubkey), h2b(script));
    }

    void ga_session::set_blinding_nonce(const std::string& pubkey, const std::string& script, const std::string& nonce)
    {
        locker_t locker(m_mutex);
        m_cache.insert_liquidblindingnonce(h2b(pubkey), h2b(script), h2b(nonce));
    }

    // Idempotent
    nlohmann::json ga_session::get_unspent_outputs(const nlohmann::json& details)
    {
        const uint32_t subaccount = details.at("subaccount");
        const uint32_t num_confs = details.at("num_confs");
        const bool confidential_only = details.value("confidential", false);

        GDK_RUNTIME_ASSERT(!confidential_only || m_net_params.liquid());

        nlohmann::json utxos;
        wamp_call(
            [&utxos](wamp_call_result result) {
                const auto r = result.get();
                if (r.number_of_arguments() != 0) {
                    utxos = get_json_result(r);
                }
            },
            "com.greenaddress.txs.get_all_unspent_outputs", num_confs, subaccount, "any");

        const auto upcoming_nlocktime = get_upcoming_nlocktime();
        if (!upcoming_nlocktime.empty()) {
            std::for_each(std::begin(utxos), std::end(utxos), [&upcoming_nlocktime](auto& utxo) {
                const auto k = std::make_pair<std::string, uint32_t>(utxo.at("txhash"), utxo.at("pt_idx"));
                const auto it = upcoming_nlocktime.find(k);
                if (it != upcoming_nlocktime.end()) {
                    utxo["nlocktime_at"] = it->second.at("nlocktime_at");
                }
            });
        }

        cleanup_utxos(utxos, m_net_params.policy_asset());

        nlohmann::json asset_utxos({});
        std::for_each(
            std::begin(utxos), std::end(utxos), [&asset_utxos, &confidential_only, this](const nlohmann::json& utxo) {
                const auto has_error = utxo.find("error") != utxo.end();
                if (has_error) {
                    asset_utxos["error"].emplace_back(utxo);
                } else {
                    const bool confidential_utxo = m_net_params.liquid() && utxo.at("confidential");
                    // either return all or only confidential UTXOs
                    if (!confidential_only || confidential_utxo) {
                        const auto utxo_asset_tag = asset_id_from_string(utxo.value("asset_id", std::string{}));
                        asset_utxos[utxo_asset_tag].emplace_back(utxo);
                    }
                }
            });

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
    nlohmann::json ga_session::get_unspent_outputs_for_private_key(
        const std::string& private_key, const std::string& password, uint32_t unused)
    {
        // Unused will be used in the future to support specifying the address type if
        // it can't be determined from the private_key format
        GDK_RUNTIME_ASSERT(unused == 0);

        std::vector<unsigned char> private_key_bytes;
        bool compressed;
        std::tie(private_key_bytes, compressed) = to_private_key_bytes(private_key, password, m_net_params.main_net());
        auto public_key_bytes = ec_public_key_from_private_key(gsl::make_span(private_key_bytes));
        if (!compressed) {
            public_key_bytes = ec_public_key_decompress(public_key_bytes);
        }
        const auto script_bytes = scriptpubkey_p2pkh_from_hash160(hash160(public_key_bytes));
        auto script_hash_bytes = sha256(script_bytes);
        std::reverse(script_hash_bytes.begin(), script_hash_bytes.end());

        nlohmann::json utxos;
        wamp_call(
            [&utxos](wamp_call_result result) {
                const auto r = result.get();
                if (r.number_of_arguments() != 0) {
                    utxos = get_json_result(r);
                }
            },
            "com.greenaddress.vault.get_utxos_for_script_hash", b2h(script_hash_bytes));

        for (auto& utxo : utxos) {
            utxo["private_key"] = b2h(private_key_bytes);
            utxo["compressed"] = compressed;
            utxo["public_key"] = b2h(public_key_bytes);
            utxo["prevout_script"] = b2h(script_bytes);
            utxo["script_type"] = script_type::pubkey_hash_out;
        }

        return cleanup_utxos(utxos, m_net_params.policy_asset());
    }

    // Idempotent
    nlohmann::json ga_session::get_transaction_details(const std::string& txhash) const
    {
        std::string tx_data;
        wamp_call([&tx_data](wamp_call_result result) { tx_data = result.get().argument<std::string>(0); },
            "com.greenaddress.txs.get_raw_output", txhash);

        const uint32_t flags = WALLY_TX_FLAG_USE_WITNESS | (m_net_params.liquid() ? WALLY_TX_FLAG_USE_ELEMENTS : 0);
        const auto tx = tx_from_hex(tx_data, flags);
        nlohmann::json result = { { "txhash", txhash } };
        update_tx_info(m_net_params, tx, result);
        return result;
    }

    nlohmann::json ga_session::get_receive_address(uint32_t subaccount, const std::string& addr_type_)
    {
        std::string addr_type = addr_type_.empty() ? get_default_address_type(subaccount) : addr_type_;
        const bool is_known
            = addr_type == address_type::p2sh || addr_type == address_type::p2wsh || addr_type == address_type::csv;

        GDK_RUNTIME_ASSERT_MSG(is_known, "Unknown address type");

        nlohmann::json address;
        wamp_call([&address](wamp_call_result result) { address = get_json_result(result.get()); },
            "com.greenaddress.vault.fund", subaccount, true, addr_type);
        json_rename_key(address, "addr_type", "address_type");
        GDK_RUNTIME_ASSERT(address["address_type"] == addr_type);

        // Add the script type, to allow addresses to be used interchangably with utxos
        script_type addr_script_type;
        if (addr_type == address_type::csv) {
            addr_script_type = script_type::p2sh_p2wsh_csv_fortified_out;
        } else if (addr_type == address_type::p2wsh) {
            addr_script_type = script_type::p2sh_p2wsh_fortified_out;
        } else {
            addr_script_type = script_type::p2sh_fortified_out;
        }
        address["script_type"] = addr_script_type;

        const auto server_script = h2b(address["script"]);
        const auto server_address = get_address_from_script(m_net_params, server_script, addr_type);

        if (m_net_params.liquid()) {
            // we treat the script as a segwit wrapped script, which is the only supported type on Liquid at the moment
            GDK_RUNTIME_ASSERT(addr_script_type == script_type::p2sh_p2wsh_csv_fortified_out
                || addr_script_type == script_type::p2sh_p2wsh_fortified_out);

            const auto script_sha = sha256(server_script);
            std::vector<unsigned char> witness_program = { 0x00, 0x20 };
            witness_program.insert(witness_program.end(), script_sha.begin(), script_sha.end());

            const auto script_hash = scriptpubkey_p2sh_from_hash160(hash160(witness_program));
            address["blinding_script_hash"] = b2h(script_hash);
        }

        if (!m_watch_only) {
            // Compute the address locally to verify the servers data
            const auto script = output_script_from_utxo(address);
            const auto user_address = get_address_from_script(m_net_params, script, addr_type);
            GDK_RUNTIME_ASSERT(server_address == user_address);
        }

        // Only scriptpubkey, we will add the blinding key later
        address["address"] = server_address;

        return address;
    }

    nlohmann::json ga_session::get_receive_address(const nlohmann::json& details)
    {
        const uint32_t subaccount = details.value("subaccount", 0);
        const std::string addr_type_ = details.value("address_type", std::string{});

        return get_receive_address(subaccount, addr_type_);
    }

    std::string ga_session::blind_address(const std::string& unblinded_addr, const std::string& blinding_key_hex)
    {
        const auto public_key = h2b(blinding_key_hex);
        return confidential_addr_from_addr(unblinded_addr, m_net_params.blinded_prefix(), public_key);
    }

    std::string ga_session::extract_confidential_address(const std::string& blinded_address)
    {
        return confidential_addr_to_addr(blinded_address, m_net_params.blinded_prefix());
    }

    std::string ga_session::get_blinding_key_for_script(const std::string& script_hex)
    {
        locker_t locker{ m_mutex };
        const auto public_key = get_signer().get_public_key_from_blinding_key(h2b(script_hex));
        return b2h(public_key);
    }

    nlohmann::json ga_session::get_balance(const nlohmann::json& details)
    {
        const uint32_t subaccount = details.at("subaccount");
        const uint32_t num_confs = details.at("num_confs");

        if (num_confs == 0 && !m_net_params.liquid()) {
            // The subaccount details contains the confs=0 balance
            return get_subaccount(subaccount)["satoshi"];
        }
        // Anything other than confs=0 needs to be fetched from the server
        return get_subaccount_balance_from_server(subaccount, num_confs);
    }

    // Idempotent
    nlohmann::json ga_session::get_available_currencies() const
    {
        nlohmann::json a;
        wamp_call([&a](wamp_call_result result) { a = get_json_result(result.get()); },
            "com.greenaddress.login.available_currencies");
        return a;
    }

    nlohmann::json ga_session::get_hw_device() const
    {
        locker_t locker{ m_mutex };
        return get_signer().get_hw_device();
    }

#if 1
    // Note: Current design is to always enable RBF if the server supports
    // it, perhaps allowing disabling for individual txs or only for BIP 70
    bool ga_session::is_rbf_enabled() const
    {
        locker_t locker(m_mutex);
        return !m_net_params.liquid() && json_get_value(m_login_data, "rbf", true);
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
        // subaccounts of type '2of2_no_recovery' do not allow csv addresses (because they have
        // 'recovery' built in).
        // short-circuit subaccount 0 as it has a known fixed type
        return subaccount == 0 || get_cached_subaccount(subaccount)["type"] != "2of2_no_recovery";
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
            nlohmann::json f;
            {
                unique_unlock unlocker(locker);
                wamp_call([&f](wamp_call_result result) { f = get_json_result(result.get()); },
                    "com.greenaddress.twofactor.get_config");
            }
            json_add_if_missing(f, "email_addr", std::string(), true);

            nlohmann::json email_config
                = { { "enabled", f["email"] }, { "confirmed", f["email_confirmed"] }, { "data", f["email_addr"] } };
            nlohmann::json sms_config
                = { { "enabled", f["sms"] }, { "confirmed", f["sms"] }, { "data", f["phone_number"] } };
            nlohmann::json phone_config
                = { { "enabled", f["phone"] }, { "confirmed", f["phone"] }, { "data", f["phone_number"] } };
            // Return the server generated gauth URL until gauth is enabled
            // (after being enabled, the server will no longer return it)
            const bool gauth_enabled = f["gauth"];
            std::string gauth_data = MASKED_GAUTH_SEED;
            if (!gauth_enabled) {
                gauth_data = f["gauth_url"];
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
            set_enabled_twofactor_methods(locker, twofactor_config);
            std::swap(m_twofactor_config, twofactor_config);
        }
        nlohmann::json ret = m_twofactor_config;

        ret["limits"] = get_spending_limits(locker);
        return ret;
    }

    // Nominally idempotent, but called on m_twofactor_config so needs locking
    void ga_session::set_enabled_twofactor_methods(locker_t& locker, nlohmann::json& config)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());

        std::vector<std::string> enabled_methods;
        enabled_methods.reserve(ALL_2FA_METHODS.size());
        for (const auto& m : ALL_2FA_METHODS) {
            if (json_get_value(config[m], "enabled", false)) {
                enabled_methods.emplace_back(m);
            }
        }
        config["enabled_methods"] = enabled_methods;
        config["any_enabled"] = !enabled_methods.empty();
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

        {
            unique_unlock unlocker(locker);
            wamp_call([](wamp_call_result result) { result.get(); }, "com.greenaddress.twofactor.set_email", email,
                as_messagepack(twofactor_data).get());
        }
        // FIXME: update data only after activate?
        m_twofactor_config["email"]["data"] = email;
    }

    void ga_session::activate_email(const std::string& code)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        {
            unique_unlock unlocker(locker);
            wamp_call([](wamp_call_result result) { result.get(); }, "com.greenaddress.twofactor.activate_email", code);
        }
        m_twofactor_config["email"]["confirmed"] = true;
    }

    void ga_session::init_enable_twofactor(
        const std::string& method, const std::string& data, const nlohmann::json& twofactor_data)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        const std::string api_method = "com.greenaddress.twofactor.init_enable_" + method;
        {
            unique_unlock unlocker(locker);
            wamp_call(
                [](wamp_call_result result) { result.get(); }, api_method, data, as_messagepack(twofactor_data).get());
        }
        m_twofactor_config[method]["data"] = data;
    }

    void ga_session::enable_twofactor(const std::string& method, const std::string& code)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        {
            unique_unlock unlocker(locker);
            std::string api_method = "com.greenaddress.twofactor.enable_" + method;
            wamp_call([](wamp_call_result result) { result.get(); }, api_method, code);
        }
        // Update our local 2fa config
        const std::string masked; // TODO: Use a real masked value
        m_twofactor_config[method] = { { "enabled", true }, { "confirmed", true }, { "data", masked } };
        set_enabled_twofactor_methods(locker, m_twofactor_config);
    }

    void ga_session::enable_gauth(const std::string& code, const nlohmann::json& twofactor_data)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        {
            unique_unlock unlocker(locker);
            wamp_call([](wamp_call_result result) { result.get(); }, "com.greenaddress.twofactor.enable_gauth", code,
                as_messagepack(twofactor_data).get());
        }
        // Update our local 2fa config
        m_twofactor_config["gauth"] = { { "enabled", true }, { "confirmed", true }, { "data", MASKED_GAUTH_SEED } };
        set_enabled_twofactor_methods(locker, m_twofactor_config);
    }

    void ga_session::disable_twofactor(const std::string& method, const nlohmann::json& twofactor_data)
    {
        locker_t locker(m_mutex);
        GDK_RUNTIME_ASSERT(!m_twofactor_config.is_null()); // Caller must fetch before changing

        const std::string api_method = "com.greenaddress.twofactor.disable_" + method;
        {
            unique_unlock unlocker(locker);
            wamp_call([](wamp_call_result result) { result.get(); }, api_method, as_messagepack(twofactor_data).get());
        }
        // If the call succeeds it means the method was previously enabled, hence
        // for email the email address is still confirmed even though 2fa is disabled.
        const bool confirmed = method == "email";

        const std::string masked
            = method == "gauth" ? MASKED_GAUTH_SEED : std::string(); // TODO: Use a real masked value

        // Update our local 2fa config
        m_twofactor_config[method] = { { "enabled", false }, { "confirmed", confirmed }, { "data", masked } };
        set_enabled_twofactor_methods(locker, m_twofactor_config);
    }

    // Idempotent
    void ga_session::auth_handler_request_code(
        const std::string& method, const std::string& action, const nlohmann::json& twofactor_data)
    {
        const std::string api_method = "com.greenaddress.twofactor.request_" + method;
        wamp_call(
            [](wamp_call_result result) { result.get(); }, api_method, action, as_messagepack(twofactor_data).get());
    }

    // Idempotent
    nlohmann::json ga_session::reset_twofactor(const std::string& email)
    {
        const std::string api_method = "com.greenaddress.twofactor.request_reset";
        nlohmann::json state;
        wamp_call([&state](wamp_call_result result) { state = get_json_result(result.get()); }, api_method, email);
        return state;
    }

    // Idempotent
    nlohmann::json ga_session::confirm_twofactor_reset(
        const std::string& email, bool is_dispute, const nlohmann::json& twofactor_data)
    {
        const std::string api_method = "com.greenaddress.twofactor.confirm_reset";
        nlohmann::json state;
        wamp_call([&state](wamp_call_result result) { state = get_json_result(result.get()); }, api_method, email,
            is_dispute, as_messagepack(twofactor_data).get());
        return state;
    }

    // Idempotent
    nlohmann::json ga_session::cancel_twofactor_reset(const nlohmann::json& twofactor_data)
    {
        const std::string api_method = "com.greenaddress.twofactor.cancel_reset";
        nlohmann::json state;
        wamp_call([&state](wamp_call_result result) { state = get_json_result(result.get()); }, api_method,
            as_messagepack(twofactor_data).get());
        return state;
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
        std::string pin_info;
        constexpr bool return_password = true;
        wamp_call([&pin_info](wamp_call_result result) { pin_info = result.get().argument<std::string>(0); },
            "com.greenaddress.pin.set_pin_login", pin, device_id, return_password);

        std::vector<std::string> id_and_password;
        boost::algorithm::split(id_and_password, pin_info, boost::is_any_of(";"));
        GDK_RUNTIME_ASSERT(id_and_password.size() == 2u);
        const auto& password = id_and_password.back();

        // Encrypt the users mnemonic and seed using a key dervied from the
        // PIN password and a randomly generated salt.
        // Note the use of base64 here is to remain binary compatible with
        // old GreenBits installs.
        const auto salt = get_random_bytes<16>();
        const auto salt_b64 = websocketpp::base64_encode(salt.data(), salt.size());
        const auto key = pbkdf2_hmac_sha512_256(ustring_span(password), ustring_span(salt_b64));

        // FIXME: secure string
        const std::string json = nlohmann::json({ { "mnemonic", mnemonic }, { "seed", b2h(seed) } }).dump();

        return { { "pin_identifier", id_and_password.front() }, { "salt", salt_b64 },
            { "encrypted_data", aes_cbc_encrypt(key, json) } };
    }

    void ga_session::disable_all_pin_logins()
    {
        bool r{ false };
        wamp_call([&r](wamp_call_result result) { r = result.get().argument<bool>(0); },
            "com.greenaddress.pin.remove_all_pin_logins");
        GDK_RUNTIME_ASSERT(r);
    }

    // Idempotent
    std::vector<unsigned char> ga_session::get_pin_password(const std::string& pin, const std::string& pin_identifier)
    {
        std::string password;
        wamp_call([&password](wamp_call_result result) { password = result.get().argument<std::string>(0); },
            "com.greenaddress.pin.get_password", pin, pin_identifier);

        return std::vector<unsigned char>(password.begin(), password.end());
    }

    // Post-login idempotent
    signer& ga_session::get_signer()
    {
        GDK_RUNTIME_ASSERT(m_signer != nullptr);
        return *m_signer;
    };

    const signer& ga_session::get_signer() const
    {
        GDK_RUNTIME_ASSERT(m_signer != nullptr);
        return *m_signer;
    };

    // Post-login idempotent
    ga_pubkeys& ga_session::get_ga_pubkeys()
    {
        GDK_RUNTIME_ASSERT(m_ga_pubkeys != nullptr);
        return *m_ga_pubkeys;
    }

    // Post-login idempotent
    ga_user_pubkeys& ga_session::get_user_pubkeys()
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

    bool ga_session::has_recovery_pubkeys_subaccount(uint32_t subaccount)
    {
        locker_t locker{ m_mutex };
        return get_recovery_pubkeys().have_subaccount(subaccount);
    }

    std::string ga_session::get_service_xpub(uint32_t subaccount)
    {
        locker_t locker{ m_mutex };
        return get_ga_pubkeys().get_subaccount(subaccount).to_base58();
    }

    std::string ga_session::get_recovery_xpub(uint32_t subaccount)
    {
        locker_t locker{ m_mutex };
        return get_recovery_pubkeys().get_subaccount(subaccount).to_base58();
    }

    bool ga_session::supports_low_r() const
    {
        locker_t locker{ m_mutex };
        return get_signer().supports_low_r();
    }

    liquid_support_level ga_session::hw_liquid_support() const
    {
        locker_t locker{ m_mutex };
        return get_signer().supports_liquid();
    }

    std::vector<unsigned char> ga_session::output_script_from_utxo(const nlohmann::json& utxo)
    {
        locker_t locker{ m_mutex };
        return ::ga::sdk::output_script_from_utxo(
            m_net_params, get_ga_pubkeys(), get_user_pubkeys(), get_recovery_pubkeys(), utxo);
    }

    ecdsa_sig_t ga_session::sign_hash(gsl::span<const uint32_t> path, gsl::span<const unsigned char> hash)
    {
        locker_t locker{ m_mutex };
        return get_signer().sign_hash(path, hash);
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

        // FIXME: test weight and return error in create_transaction, not here
        const std::string tx_hex = result.at("transaction");
        const size_t MAX_TX_WEIGHT = 400000;
        const uint32_t flags = WALLY_TX_FLAG_USE_WITNESS | (details.at("liquid") ? WALLY_TX_FLAG_USE_ELEMENTS : 0);
        const auto unsigned_tx = tx_from_hex(tx_hex, flags);
        GDK_RUNTIME_ASSERT(tx_get_weight(unsigned_tx) < MAX_TX_WEIGHT);

        nlohmann::json private_data;
        const std::string memo = json_get_value(result, "memo");
        if (!memo.empty()) {
            private_data["memo"] = memo;
        }
        // FIXME: social_destination/social_destination_type/payreq if BIP70

        const auto blinding_nonces_p = result.find("blinding_nonces");
        if (blinding_nonces_p != result.end()) {
            private_data["blinding_nonces"] = *blinding_nonces_p;
        }

        constexpr bool return_tx = true;
        nlohmann::json tx_details;
        wamp_call([&tx_details](wamp_call_result result) { tx_details = get_json_result(result.get()); },
            "com.greenaddress.vault.send_raw_tx", tx_hex, as_messagepack(twofactor_data).get(),
            as_messagepack(private_data).get(), return_tx);

        amount::value_type decrease = tx_details.at("limit_decrease");
        if (decrease != 0) {
            locker_t locker(m_mutex);
            update_spending_limits(locker, tx_details["limits"]);
        }

        // Update the details with the server signed transaction, since it
        // may be a slightly different size once signed
        result["txhash"] = tx_details["txhash"];
        const auto tx = tx_from_hex(tx_details["tx"], flags);
        update_tx_info(tx, result);
        result["server_signed"] = true;
        return result;
    }

    // Idempotent
    std::string ga_session::broadcast_transaction(const std::string& tx_hex)
    {
        std::string tx_hash;
        wamp_call([&tx_hash](wamp_call_result result) { tx_hash = result.get().argument<std::string>(0); },
            "com.greenaddress.vault.broadcast_raw_tx", tx_hex);
        return tx_hash;
    }

    void ga_session::sign_input(
        const wally_tx_ptr& tx, uint32_t index, const nlohmann::json& u, const std::string& der_hex)
    {
        ::ga::sdk::sign_input(*this, tx, index, u, der_hex);
    }

    void ga_session::blind_output(const nlohmann::json& details, const wally_tx_ptr& tx, uint32_t index,
        const nlohmann::json& output, const std::string& asset_commitment_hex, const std::string& value_commitment_hex,
        const std::string& abf, const std::string& vbf)
    {
        ::ga::sdk::blind_output(*this, details, tx, index, output, h2b<33>(asset_commitment_hex),
            h2b<33>(value_commitment_hex), h2b<32>(abf), h2b<32>(vbf));
    }

    // Idempotent
    void ga_session::send_nlocktimes()
    {
        bool r;
        wamp_call([&r](wamp_call_result result) { r = result.get().argument<bool>(0); },
            "com.greenaddress.txs.send_nlocktime");
        GDK_RUNTIME_ASSERT(r);
    }

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
        bool r;
        const uint32_t value = locktime_details.at("value");
        wamp_call([&r](wamp_call_result result) { r = result.get().argument<bool>(0); },
            "com.greenaddress.login.set_csvtime", value, as_messagepack(twofactor_data).get());
        GDK_RUNTIME_ASSERT(r);
    }

    void ga_session::set_nlocktime(const nlohmann::json& locktime_details, const nlohmann::json& twofactor_data)
    {
        bool r;
        const uint32_t value = locktime_details.at("value");
        wamp_call([&r](wamp_call_result result) { r = result.get().argument<bool>(0); },
            "com.greenaddress.login.set_nlocktime", value, as_messagepack(twofactor_data).get());
        GDK_RUNTIME_ASSERT(r);

        locker_t locker{ m_mutex };
        m_nlocktime = value;
    }

    // Idempotent
    void ga_session::set_transaction_memo(
        const std::string& txhash_hex, const std::string& memo, const std::string& memo_type)
    {
        wamp_call([](boost::future<autobahn::wamp_call_result> result) { result.get(); },
            "com.greenaddress.txs.change_memo", txhash_hex, memo, memo_type);

        // Invalidate the tx list caches so that subsequent calls to get_transactions go back
        // to the server and pull down the new memo.
        // FIXME: This is a very bad way of doing this and it only works for the local gdk
        // instance. In future transaction memos will be stored in client authenticated blobs
        // and subject to notifications.
        m_tx_list_caches.purge_all();
    }

} // namespace sdk
} // namespace ga
