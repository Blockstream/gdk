#include <array>
#include <boost/asio/io_context.hpp>
#include <cstdio>
#include <fstream>
#include <map>
#include <thread>

#include <sys/stat.h>
#include <sys/types.h>

#ifndef WIN32
#include <unistd.h>
#endif

#include "session.hpp"

#include "autobahn_wrapper.hpp"
#include "boost_wrapper.hpp"
#include "exception.hpp"
#include "http_client.hpp"
#include "io_runner.hpp"
#include "logging.hpp"
#include "network_parameters.hpp"
#include "utils.hpp"
#include "version.h"
#include "wamp_transport.hpp"

using namespace std::literals;
namespace asio = boost::asio;
namespace wlog = websocketpp::log;

namespace ga {
namespace sdk {
    struct websocket_rng_type {
        uint32_t operator()() const
        {
            uint32_t b;
            get_random_bytes(sizeof(b), &b, sizeof(b));
            return b;
        }
    };

    class websocket_boost_logger {
    public:
        static gdk_logger_t& m_log;

        explicit websocket_boost_logger(wlog::channel_type_hint::value hint)
            : websocket_boost_logger(0, hint)
        {
        }

        websocket_boost_logger(wlog::level l, __attribute__((unused)) wlog::channel_type_hint::value hint)
            : m_level(l)
        {
        }

        websocket_boost_logger()
            : websocket_boost_logger(0, 0)
        {
        }

        void set_channels(wlog::level l) { m_level = l; }
        void clear_channels(wlog::level __attribute__((unused)) l) { m_level = 0; }

        constexpr static auto get_severity_level(wlog::level l)
        {
            switch (l) {
            case wlog::alevel::devel:
            case wlog::elevel::devel:
            case wlog::elevel::library:
                return boost::log::trivial::debug;
            case wlog::elevel::warn:
                return boost::log::trivial::warning;
            case wlog::elevel::rerror:
                return boost::log::trivial::error;
            case wlog::elevel::fatal:
                return boost::log::trivial::fatal;
            case wlog::elevel::info:
            default:
                return boost::log::trivial::info;
            }
        }

        void write(wlog::level l, const std::string& s)
        {
            if (dynamic_test(l)) {
                BOOST_LOG_SEV(m_log, get_severity_level(l)) << s;
            }
        }

        void write(wlog::level l, char const* s)
        {
            if (dynamic_test(l)) {
                BOOST_LOG_SEV(m_log, get_severity_level(l)) << s;
            }
        }

        bool static_test(wlog::level l) const { return (m_level & l) != 0; }
        bool dynamic_test(wlog::level l) { return (m_level & l) != 0; }

        wlog::level m_level;
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
            static const long timeout_proxy = 1200000; // in ms
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
            static const long timeout_proxy = 1200000; // in ms
        };
        using transport_type = websocketpp::transport::asio::endpoint<websocketpp_gdk_tls_config::transport_config>;
    };

    using transport = autobahn::wamp_websocketpp_websocket_transport<websocketpp_gdk_config>;
    using transport_tls = autobahn::wamp_websocketpp_websocket_transport<websocketpp_gdk_tls_config>;

    gdk_logger_t& websocket_boost_logger::m_log = gdk_logger::get();

    namespace {
        // networking defaults
        static const uint32_t WAMP_CALL_TIMEOUT_SECS = 10;
        static const auto DEFAULT_PING = 60s; // ping message interval
        static const uint32_t DEFAULT_KEEPIDLE = 1; // tcp heartbeat frequency in seconds
        static const uint32_t DEFAULT_KEEPINTERVAL = 1; // tcp heartbeat frequency in seconds
        static const uint32_t DEFAULT_KEEPCNT = 2; // tcp unanswered heartbeats

        static void set_socket_options(autobahn::wamp_websocket_transport* t, bool is_tls)
        {
            auto set_option = [t, is_tls](auto option) {
                if (is_tls) {
                    GDK_RUNTIME_ASSERT((static_cast<transport_tls*>(t))->set_socket_option(option));
                } else {
                    GDK_RUNTIME_ASSERT((static_cast<transport*>(t))->set_socket_option(option));
                }
            };

            asio::ip::tcp::no_delay no_delay(true);
            set_option(no_delay);
            asio::socket_base::keep_alive keep_alive(true);
            set_option(keep_alive);

#if defined __APPLE__
            using tcp_keep_alive = asio::detail::socket_option::integer<IPPROTO_TCP, TCP_KEEPALIVE>;
            set_option(tcp_keep_alive{ DEFAULT_KEEPIDLE });
#elif __linux__ || __ANDROID__ || __FreeBSD__
            using keep_idle = asio::detail::socket_option::integer<IPPROTO_TCP, TCP_KEEPIDLE>;
            set_option(keep_idle{ DEFAULT_KEEPIDLE });
#endif
#ifndef __WIN64
            using keep_interval = asio::detail::socket_option::integer<IPPROTO_TCP, TCP_KEEPINTVL>;
            set_option(keep_interval{ DEFAULT_KEEPINTERVAL });
            using keep_count = asio::detail::socket_option::integer<IPPROTO_TCP, TCP_KEEPCNT>;
            set_option(keep_count{ DEFAULT_KEEPCNT });
#endif
        }

        template <typename FN> static void future_wait(FN&& f, const char* context)
        {
            const auto status = f.wait_for(boost::chrono::seconds(30));
            if (status == boost::future_status::ready) {
                f.get();
            } else {
                GDK_LOG_SEV(log_level::info) << "future not ready on " << context;
            }
        }

        static void handle_disconnect(asio::io_context::executor_type executor,
            std::shared_ptr<autobahn::wamp_websocket_transport>& t, std::shared_ptr<autobahn::wamp_session>& s)
        {
            if (s) {
                no_std_exception_escape([&executor, &s] {
                    auto f = asio::post(executor, std::packaged_task<boost::future<std::string>()>([&s] {
                        return s->leave();
                    })).get();
                    future_wait(f, "session leave");
                });
                no_std_exception_escape([&executor, &s] {
                    auto f = asio::post(executor, std::packaged_task<boost::future<void>()>([&s] {
                        return s->stop();
                    })).get();
                    future_wait(f, "session stop");
                });
            }

            if (t) {
                no_std_exception_escape([&executor, &t] {
                    auto f = asio::post(executor, std::packaged_task<boost::future<void>()>([&t] {
                        return t->disconnect();
                    })).get();
                    future_wait(f, "session disconnect");
                });

                // Wait for the transport to be disconnected
                bool connected = true;
                GDK_LOG_SEV(log_level::debug) << "waiting for connection to die";
                while (connected) {
                    auto f = asio::post(executor, std::packaged_task<bool()>([&t] { return t->is_connected(); }));
                    connected = f.get();
                }
                GDK_LOG_SEV(log_level::debug) << "connection is dead";

                no_std_exception_escape(
                    [&executor, &t] { asio::post(executor, std::packaged_task<void()>([&t] { t->detach(); })).get(); });
            }
        }

        static bool connection_ping_ok(std::shared_ptr<autobahn::wamp_websocket_transport>& t, bool is_tls)
        {
            GDK_LOG_SEV(log_level::info) << "net: pinging";
            if (is_tls) {
                return std::static_pointer_cast<transport_tls>(t)->ping(std::string());
            }
            return std::static_pointer_cast<transport>(t)->ping(std::string());
        }

        template <typename T> static nlohmann::json wamp_cast_json_impl(const T& result)
        {
            if (!result.number_of_arguments()) {
                return nlohmann::json();
            }
            const auto obj = result.template argument<msgpack::object>(0);
            msgpack::sbuffer sbuf;
            msgpack::pack(sbuf, obj);
            return nlohmann::json::from_msgpack(sbuf.data(), sbuf.data() + sbuf.size());
        }

        template <typename T>
        static bool is_elapsed(std::chrono::time_point<std::chrono::system_clock> from, T duration)
        {
            const auto t = std::chrono::system_clock::now();
            return t < from || t - from > duration;
        }
    } // namespace

    class exponential_backoff {
    public:
        explicit exponential_backoff()
            : m_limit(300s)
        {
            reset();
        }

        std::chrono::seconds get_backoff()
        {
            if (m_n == 0) {
                return 1s;
            }
            m_elapsed += m_waiting;
            const auto v
                = std::min(static_cast<uint32_t>(m_limit.count()), uint32_t{ 1 } << std::min(m_n, uint32_t{ 31 }));
            std::random_device rd;
            std::uniform_int_distribution<uint32_t> d(v / 2, v);
            m_waiting = std::chrono::seconds(d(rd));
            return m_waiting;
        }

        bool limit_reached() const { return m_elapsed >= m_limit; }
        std::chrono::seconds elapsed() const { return m_elapsed; }
        std::chrono::seconds waiting() const { return m_waiting; }

        void increment() { ++m_n; }

        void reset()
        {
            m_n = 0;
            m_elapsed = 0s;
            m_waiting = 0s;
        }

    private:
        const std::chrono::seconds m_limit;
        uint32_t m_n;
        std::chrono::seconds m_elapsed;
        std::chrono::seconds m_waiting;
    };

    nlohmann::json wamp_cast_json(const autobahn::wamp_event& event) { return wamp_cast_json_impl(*event); }

    nlohmann::json wamp_cast_json(const autobahn::wamp_call_result& result) { return wamp_cast_json_impl(result); }

    wamp_transport::wamp_transport(const network_parameters& net_params, io_runner& runner,
        boost::asio::io_context::strand& strand, wamp_transport::notify_fn_t fn, std::string server_prefix)
        : m_net_params(net_params)
        , m_io(runner)
        , m_strand(strand)
        , m_server_prefix(std::move(server_prefix))
        , m_server(m_net_params.get_connection_string(m_server_prefix))
        , m_wamp_host_name(websocketpp::uri(m_net_params.gait_wamp_url(m_server_prefix)).get_host())
        , m_wamp_call_prefix("com.greenaddress.")
        , m_wamp_call_options()
        , m_notify_fn(fn)
        , m_desired_state(state_t::disconnected)
        , m_state(state_t::disconnected)
        , m_failure_count(0)
    {
        using namespace std::placeholders;
        m_subscriptions.reserve(4u);

        m_wamp_call_options.set_timeout(std::chrono::seconds(WAMP_CALL_TIMEOUT_SECS));

        m_reconnect_thread = std::thread([this] { reconnect_handler(); });

        if (!m_net_params.is_tls_connection(m_server_prefix)) {
            m_client = std::make_unique<client>();
            m_client->set_pong_timeout_handler(std::bind(&wamp_transport::heartbeat_timeout_cb, this, _1, _2));
            m_client->init_asio(&m_io.get_io_context());
            return;
        }

        m_client_tls = std::make_unique<client_tls>();
        m_client_tls->set_pong_timeout_handler(std::bind(&wamp_transport::heartbeat_timeout_cb, this, _1, _2));
        m_client_tls->set_tls_init_handler([this](const websocketpp::connection_hdl) {
            return tls_init(m_wamp_host_name, m_net_params.gait_wamp_cert_roots(), m_net_params.gait_wamp_cert_pins(),
                m_net_params.cert_expiry_threshold());
        });
        m_client_tls->init_asio(&m_io.get_io_context());
    }

    wamp_transport::~wamp_transport()
    {
        no_std_exception_escape([this] { change_state_to(state_t::exited, std::string(), false); }, "wamp dtor(1)");
        no_std_exception_escape([this] { m_reconnect_thread.join(); }, "wamp dtor(2)");
    }

    void wamp_transport::connect(const std::string& proxy) { change_state_to(state_t::connected, proxy, true); }

    void wamp_transport::disconnect() { change_state_to(state_t::disconnected, std::string(), true); }

    void wamp_transport::reconnect()
    {
        // Only called by the top level session class in response to
        // exceptions from wamp_call. As such, just increment the
        // failure count and let the reconnect thread reconnect us.
        // If the failure has been detected by the connection already,
        // this should easily occur within the disconnect/connect
        // processing, avoiding a double disconnect/connect cycle.
        notify_failure("session level reconnect");
        m_condition.notify_all();
    }

    void wamp_transport::reconnect_hint(const nlohmann::json& hint, const std::string& proxy)
    {
        const auto hint_p = hint.find("hint");
        if (hint_p != hint.end()) {
            change_state_to(*hint_p == "connect" ? state_t::connected : state_t::disconnected, proxy, true);
        }
    }

    void wamp_transport::change_state_to(wamp_transport::state_t new_state, const std::string& proxy, bool wait)
    {
        GDK_LOG_SEV(log_level::info) << "change_state_to: requesting state " << state_str(new_state);
        locker_t locker(m_mutex);
        if (!proxy.empty()) {
            m_proxy = proxy;
        }
        const auto initial_state = m_state.load();
        GDK_RUNTIME_ASSERT(initial_state != state_t::exited);
        m_desired_state = new_state;
        const bool is_noop = new_state == initial_state;
        locker.unlock();
        m_condition.notify_all();

        if (!is_noop && wait) {
            // Busy wait for up to 30s while the reconnection thread changes state
            for (size_t i = 0; i < 600u; ++i) {
                std::this_thread::sleep_for(50ms);
                locker.lock();
                const auto current_state = m_state.load();
                locker.unlock();
                if (current_state == new_state || current_state == state_t::exited) {
                    GDK_LOG_SEV(log_level::info) << "change_state_to: changed to " << state_str(current_state);
                    return;
                }
            }
            throw timeout_error();
        }
    }

    void wamp_transport::emit_state(wamp_transport::state_t current, wamp_transport::state_t desired, uint64_t wait_ms)
    {
        constexpr bool async = true;
        nlohmann::json state(
            { { "current_state", state_str(current) }, { "next_state", state_str(desired) }, { "wait_ms", wait_ms } });
        m_notify_fn({ { "event", "network" }, { "network", std::move(state) } }, async);
    }

    const char* wamp_transport::state_str(state_t state) const
    {
        switch (state) {
        case state_t::disconnected:
            return "disconnected";
        case state_t::connected:
            return "connected";
        case state_t::exited:
            return "exited";
        }
        return "unknown";
    }

    void wamp_transport::heartbeat_timeout_cb(websocketpp::connection_hdl, const std::string&)
    {
        notify_failure("pong timeout detected");
    }

    void wamp_transport::notify_failure(const std::string& reason)
    {
        locker_t locker(m_mutex);
        notify_failure(locker, reason);
    }

    void wamp_transport::notify_failure(locker_t& locker, const std::string& reason, bool notify_condition)
    {
        ++m_failure_count;
        locker.unlock();
        GDK_LOG_SEV(log_level::info) << reason << ", notifying failure";
        if (notify_condition) {
            m_condition.notify_all();
        }
    }

    std::pair<wamp_transport::session_ptr, autobahn::wamp_websocket_transport*>
    wamp_transport::get_session_and_transport()
    {
        locker_t locker(m_mutex);
        return std::make_pair(m_session, m_transport.get());
    }

    autobahn::wamp_call_result wamp_transport::wamp_process_call(
        autobahn::wamp_websocket_transport* t, boost::future<autobahn::wamp_call_result>& fn)
    {
        for (;;) {
            const auto status = fn.wait_for(boost::chrono::seconds(1));
            if (status == boost::future_status::ready) {
                break;
            }
            if (status == boost::future_status::timeout) {
                locker_t locker(m_mutex);
                if (m_transport.get() != t || !m_transport->is_connected()) {
                    notify_failure(locker, "call transport disconnected/changed");
                    throw timeout_error{};
                }
            }
        }
        try {
            auto ret = fn.get();
            locker_t locker(m_mutex);
            m_last_ping_ts = std::chrono::system_clock::now();
            locker.unlock();
            return ret;
        } catch (const boost::future_error& ex) {
            notify_failure(std::string("wamp call exception: ") + ex.what());
            throw reconnect_error{};
        }
    }

    void wamp_transport::reconnect_handler()
    {
        const bool is_tls = m_net_params.is_tls_connection(m_server_prefix);
        const bool is_debug = gdk_config()["log_level"] == "debug";
        const auto& executor = m_io.get_io_context().get_executor();

        // The last failure number that we handled
        auto last_handled_failure_count = m_failure_count.load();
        exponential_backoff backoff;

        GDK_LOG_SEV(log_level::info) << "net: thread started for gdk version " << GDK_COMMIT;

        for (;;) {
            decltype(m_transport) t;
            decltype(m_session) s;
            decltype(m_subscriptions) subscriptions;

            locker_t locker(m_mutex);
            const auto state = m_state.load();
            auto desired_state = m_desired_state.load();
            const auto failure_count = m_failure_count.load();
            const bool need_to_ping = !m_proxy.empty();

            if (desired_state != state_t::exited && last_handled_failure_count != failure_count) {
                GDK_LOG_SEV(log_level::info) << "net: unhandled failure detected";
                desired_state = state_t::disconnected;
            } else if (state == desired_state) {
                // We are already in the desired state. Wait until something changes
                if (m_transport) {
                    if (!m_transport->is_connected()) {
                        // The transport has been closed or failed. Mark the
                        // error and loop again to reconnect if needed.
                        notify_failure(locker, "net: detected dead transport", false);
                        continue;
                    } else if (need_to_ping && is_elapsed(m_last_ping_ts, DEFAULT_PING)) {
                        if (!connection_ping_ok(m_transport, is_tls)) {
                            notify_failure(locker, "net: sending ping failed", false);
                            continue;
                        }
                        m_last_ping_ts = std::chrono::system_clock::now();
                    }
                }
                // Wait without conditions. In the event of a spurious wakeup
                // or nofify by another thread, we will loop to re-check.
                m_condition.wait_for(locker, 1s);
                continue;
            }

            GDK_LOG_SEV(log_level::info) << "net: desired " << state_str(desired_state) << " actual "
                                         << state_str(state);

            if (desired_state == state_t::exited || desired_state == state_t::disconnected) {
                // We want the connection closed
                if (m_session || m_transport) {
                    m_transport.swap(t);
                    m_session.swap(s);
                    m_subscriptions.swap(subscriptions);

                    unique_unlock unlocker(locker);
                    GDK_LOG_SEV(log_level::info) << "net: disconnecting";
                    handle_disconnect(executor, t, s);
                }

                // Mark all currently notified failures as handled. We
                // will then loop to either connect or not according
                // to our desired state.
                last_handled_failure_count = m_failure_count.load();

                m_state = desired_state;
                desired_state = m_desired_state.load();
                locker.unlock();
                emit_state(m_state, desired_state, 0);
                if (desired_state == state_t::exited) {
                    // Exit this thread so the caller can join() it
                    return;
                }
                backoff.reset(); // Start our backoff sequence again when we reconnect
                continue;
            }
            if (desired_state == state_t::connected) {
                // We want the connection open
                const std::string proxy = m_proxy;
                locker.unlock();

                GDK_LOG_SEV(log_level::info)
                    << "net: connect to " << m_server << (proxy.empty() ? "" : std::string(" via ") + proxy);

                if (is_tls) {
                    t = std::make_shared<transport_tls>(*m_client_tls, m_server, proxy, is_debug);
                } else {
                    t = std::make_shared<transport>(*m_client, m_server, proxy, is_debug);
                }
                s = std::make_shared<autobahn::wamp_session>(m_io.get_io_context(), is_debug);
                t->attach(std::static_pointer_cast<autobahn::wamp_transport_handler>(s));
                bool failed = false;
                if (no_std_exception_escape(
                        [&t] { future_wait(t->connect(), "transport connect"); }, "transport connect")) {
                    failed = true;
                    handle_disconnect(executor, t, s);
                }
                if (!failed
                    && no_std_exception_escape(
                        [&s] { future_wait(s->start(), "session connect"); }, "session connect")) {
                    failed = true;
                }
                if (!failed
                    && no_std_exception_escape(
                        [&s] { future_wait(s->join("realm1"), "session join"); }, "session join")) {
                    failed = true;
                }
                if (!failed
                    && no_std_exception_escape(
                        [t, &is_tls] { set_socket_options(t.get(), is_tls); }, "set socket options")) {
                    failed = true;
                }
                if (failed) {
                    backoff_handler(locker, backoff); // Wait longer before trying again
                    continue;
                }

                GDK_LOG_SEV(log_level::info) << "net: connection successful";
                backoff.reset(); // Start our backoff sequence again when we reconnect
                locker.lock();
                m_session.swap(s);
                m_transport.swap(t);
                m_state = state_t::connected;
                m_last_ping_ts = std::chrono::system_clock::now();
                // Mark all currently notified failures as handled
                last_handled_failure_count = m_failure_count.load();
                locker.unlock();
                emit_state(state_t::connected, state_t::connected, 0);
                continue;
            }
        }
    }

    void wamp_transport::backoff_handler(locker_t& locker, exponential_backoff& backoff)
    {
        backoff.increment();
        const auto backoff_time = backoff.get_backoff();
        GDK_LOG_SEV(log_level::info) << "net: backing off for " << backoff_time.count() << "s";
        const auto start = std::chrono::system_clock::now();
        auto&& elapsed_fn = [this, start, backoff_time] {
            if (is_elapsed(start, backoff_time)) {
                return true; // Backoff time expired
            }
            if (m_desired_state.load() != state_t::connected) {
                return true; // Another thread asked to disconnect or exit
            }
            return false;
        };
        emit_state(state_t::disconnected, state_t::connected, backoff_time.count() * 1000);
        // Wait for the backoff time, ignoring spurious wakeups
        locker.lock();
        m_condition.wait_for(locker, backoff_time, elapsed_fn);
    }

    void wamp_transport::subscribe(const std::string& topic, wamp_transport::subscribe_fn_t fn, bool is_initial)
    {
        decltype(m_subscriptions) subscriptions;

        locker_t locker(m_mutex);
        if (is_initial) {
            m_subscriptions.swap(subscriptions);
            m_subscriptions.reserve(4u);
        }
        decltype(m_session) s{ m_session };
        GDK_RUNTIME_ASSERT(s.get());
        autobahn::wamp_subscription sub;
        {
            // TODO: Set m_last_ping_ts whenever we receive a subscription
            unique_unlock unlocker(locker);
            const autobahn::wamp_subscribe_options options("exact");
            sub = s->subscribe(
                       topic, [fn](const autobahn::wamp_event& e) { fn(wamp_cast_json(e)); }, options)
                      .get();
        }
        GDK_LOG_SEV(log_level::debug) << "subscribed to " << topic << ":" << sub.id();
        m_subscriptions.emplace_back(sub);
    }

} // namespace sdk
} // namespace ga
