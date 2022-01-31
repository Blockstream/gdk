#include <array>
#include <cstdio>
#include <fstream>
#include <map>

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
#include "logging.hpp"
#include "memory.hpp"
#include "network_parameters.hpp"
#include "utils.hpp"
#include "version.h"
#include "wamp_transport.hpp"

using namespace std::literals;
namespace asio = boost::asio;

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
        static const auto DEFAULT_PING = boost::posix_time::seconds(20); // ping message interval
        static const uint32_t DEFAULT_KEEPIDLE = 1; // tcp heartbeat frequency in seconds
        static const uint32_t DEFAULT_KEEPINTERVAL = 1; // tcp heartbeat frequency in seconds
        static const uint32_t DEFAULT_KEEPCNT = 2; // tcp unanswered heartbeats

        static X509* cert_from_pem(const std::string& pem)
        {
            using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
            BIO_ptr input(BIO_new(BIO_s_mem()), BIO_free);
            BIO_write(input.get(), pem.c_str(), pem.size());
            return PEM_read_bio_X509_AUX(input.get(), NULL, NULL, NULL);
        }

        static std::string cert_to_pretty_string(const X509* cert)
        {
            using BIO_ptr = std::unique_ptr<BIO, decltype(&BIO_free)>;
            BIO_ptr output(BIO_new(BIO_s_mem()), BIO_free);
            if (!X509_print(output.get(), const_cast<X509*>(cert))) {
                return std::string("X509_print error");
            }

            char* str = nullptr;
            const auto size = BIO_get_mem_data(output.get(), &str);
            return std::string(str, size);
        }

        static bool is_cert_in_date_range(const X509* cert, uint32_t cert_expiry_threshold)
        {
            // Use adjusted times 24 hours in each direction to avoid timezone issues
            // and races, hence certs will be ignored until 24 hours after they are
            // actually valid and 24 hours before they strictly expire
            // Also allow a custom expiry threshold to reject certificates expiring at some
            // point in the future for testing/resilience
            const auto now = std::chrono::system_clock::now();
            auto start_before = std::chrono::system_clock::to_time_t(now - 24h);
            auto expire_after = std::chrono::system_clock::to_time_t(now + (24h * cert_expiry_threshold));

            const int before = X509_cmp_time(X509_get0_notBefore(cert), &start_before);
            if (before == 0) {
                GDK_LOG_SEV(log_level::error) << "Error checking certificate not before time";
                return false;
            }
            // -1: start time is earlier than or equal to yesterday - ok
            // +1: start time is later than yesterday - fail
            if (before == 1) {
                GDK_LOG_SEV(log_level::debug) << "Rejecting certificate (not yet valid)";
                return false;
            }

            const int after = X509_cmp_time(X509_get0_notAfter(cert), &expire_after);
            if (after == 0) {
                GDK_LOG_SEV(log_level::error) << "Error checking certificate not after time";
                return false;
            }
            // -1: expiry time is earlier than or equal to expire_after - fail
            // +1: expiry time is later than expire_after - ok
            if (after == -1) {
                // The not after (expiry) time is earlier than expire_after
                GDK_LOG_SEV(log_level::debug) << "Rejecting certificate (expired)";
                return false;
            }

            return true;
        }

        static bool check_cert_pins(
            const std::vector<std::string>& pins, asio::ssl::verify_context& ctx, uint32_t cert_expiry_threshold)
        {
            const int depth = X509_STORE_CTX_get_error_depth(ctx.native_handle());
            const bool is_leaf_cert = depth == 0;
            if (!is_leaf_cert) {
                // Checking for pinned intermediate certs is deferred until checking
                // the leaf node, at which point the entire chain can be walked
                return true;
            }

            typedef std::unique_ptr<STACK_OF(X509), void (*)(STACK_OF(X509)*)> X509_stack_ptr;
            auto free_x509_stack = [](STACK_OF(X509) * chain) { sk_X509_pop_free(chain, X509_free); };
            X509_stack_ptr chain(X509_STORE_CTX_get1_chain(ctx.native_handle()), free_x509_stack);

            std::array<unsigned char, SHA256_LEN> sha256_digest_buf;
            unsigned int written = 0;
            const int chain_length = sk_X509_num(chain.get());

            // Walk the certificate chain looking for a pinned certificate in `pins`
            GDK_LOG_SEV(log_level::debug) << "Checking for pinned certificate";
            for (int idx = 0; idx < chain_length; ++idx) {
                const X509* cert = sk_X509_value(chain.get(), idx);
                if (X509_digest(cert, EVP_sha256(), sha256_digest_buf.data(), &written) == 0
                    || written != sha256_digest_buf.size()) {
                    GDK_LOG_SEV(log_level::error) << "X509_digest failed certificate idx " << idx;
                    return false;
                }
                const auto hex_digest = b2h(sha256_digest_buf);
                if (std::find(pins.begin(), pins.end(), hex_digest) != pins.end()) {
                    GDK_LOG_SEV(log_level::debug) << "Found pinned certificate " << hex_digest;
                    if (is_cert_in_date_range(cert, cert_expiry_threshold)) {
                        return true;
                    }
                    GDK_LOG_SEV(log_level::warning) << "Ignoring expiring pinned certificate:\n"
                                                    << cert_to_pretty_string(cert);
                }
            }

            return false;
        }

        static auto tls_init(const std::string& host_name, const std::vector<std::string>& roots,
            const std::vector<std::string>& pins, uint32_t cert_expiry_threshold)
        {
            const auto ctx = std::make_shared<asio::ssl::context>(asio::ssl::context::tls);
            ctx->set_options(asio::ssl::context::default_workarounds | asio::ssl::context::no_sslv2
                | asio::ssl::context::no_sslv3 | asio::ssl::context::no_tlsv1 | asio::ssl::context::no_tlsv1_1
                | asio::ssl::context::single_dh_use);
            ctx->set_verify_mode(asio::ssl::context::verify_peer | asio::ssl::context::verify_fail_if_no_peer_cert);
            // attempt to load system roots
            ctx->set_default_verify_paths();
            for (const auto& root : roots) {
                if (root.empty()) {
                    // TODO: at the moment looks like the roots/pins are empty strings when absent
                    break;
                }

                using X509_ptr = std::unique_ptr<X509, decltype(&X509_free)>;
                X509_ptr cert(cert_from_pem(root), X509_free);
                if (!is_cert_in_date_range(cert.get(), cert_expiry_threshold)) {
                    // Avoid adding expired certificates as they can cause validation failures
                    // even if there are other non-expired roots available.
                    GDK_LOG_SEV(log_level::warning) << "Ignoring expiring root certificate:\n"
                                                    << cert_to_pretty_string(cert.get());
                    continue;
                }

                // add network provided root
                const asio::const_buffer root_const_buff(root.c_str(), root.size());
                ctx->add_certificate_authority(root_const_buff);
            }

            ctx->set_verify_callback([pins, host_name, cert_expiry_threshold](
                                         bool preverified, asio::ssl::verify_context& ctx) {
                // Pre-verification includes checking for things like expired certificates
                if (!preverified) {
                    const int err = X509_STORE_CTX_get_error(ctx.native_handle());
                    GDK_LOG_SEV(log_level::error) << "x509 certificate error: " << X509_verify_cert_error_string(err);
                    return false;
                }

                // If pins are defined check that at least one of the pins is in the
                // certificate chain
                // If no pins are specified skip the check altogether
                const bool have_pins = !pins.empty() && !pins[0].empty();
                if (have_pins && !check_cert_pins(pins, ctx, cert_expiry_threshold)) {
                    GDK_LOG_SEV(log_level::error) << "Failing ssl verification, failed pin check";
                    return false;
                }

                // Check the host name matches the target
                return asio::ssl::rfc2818_verification{ host_name }(true, ctx);
            });

            return ctx;
        }

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

    wamp_transport::wamp_transport(const network_parameters& net_params, wamp_transport::notify_fn_t fn)
        : m_net_params(net_params)
        , m_io()
        , m_work_guard(asio::make_work_guard(m_io))
        , m_server(m_net_params.get_connection_string())
        , m_wamp_host_name(websocketpp::uri(m_net_params.gait_wamp_url()).get_host())
        , m_wamp_call_prefix("com.greenaddress.")
        , m_wamp_call_options()
        , m_notify_fn(fn)
        , m_debug_logging(m_net_params.log_level() == "debug")
        , m_desired_state(state_t::disconnected)
        , m_state(state_t::disconnected)
        , m_failure_count(0)
    {
        using namespace std::placeholders;
        m_subscriptions.reserve(4u);

        m_wamp_call_options.set_timeout(std::chrono::seconds(WAMP_CALL_TIMEOUT_SECS));

        m_run_thread = std::thread([this] { m_io.run(); });
        m_reconnect_thread = std::thread([this] { reconnect_handler(); });

        if (!m_net_params.is_tls_connection()) {
            m_client = std::make_unique<client>();
            m_client->set_pong_timeout_handler(std::bind(&wamp_transport::heartbeat_timeout_cb, this, _1, _2));
            m_client->init_asio(&m_io);
            return;
        }

        m_client_tls = std::make_unique<client_tls>();
        m_client_tls->set_pong_timeout_handler(std::bind(&wamp_transport::heartbeat_timeout_cb, this, _1, _2));
        m_client_tls->set_tls_init_handler([this](const websocketpp::connection_hdl) {
            return tls_init(m_wamp_host_name, m_net_params.gait_wamp_cert_roots(), m_net_params.gait_wamp_cert_pins(),
                m_net_params.cert_expiry_threshold());
        });
        m_client_tls->init_asio(&m_io);
    }

    wamp_transport::~wamp_transport()
    {
        no_std_exception_escape([this] { change_state_to(state_t::exited, false); }, "wamp dtor(1)");
        no_std_exception_escape([this] { m_reconnect_thread.join(); }, "wamp dtor(2)");
        no_std_exception_escape([this] { m_work_guard.reset(); }, "wamp dtor(2)");
        no_std_exception_escape([this] { m_run_thread.join(); }, "wamp dtor(3)");
    }

    void wamp_transport::connect(const std::string& proxy)
    {
        if (!proxy.empty()) {
            locker_t locker(m_mutex);
            m_proxy = proxy;
        }
        change_state_to(state_t::connected, true);
    }

    void wamp_transport::disconnect() { change_state_to(state_t::disconnected, true); }

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

    void wamp_transport::reconnect_hint(const nlohmann::json& hint)
    {
        auto new_state = state_t::disconnected;
        const auto hint_p = hint.find("hint");
        if (hint_p != hint.end()) {
            GDK_RUNTIME_ASSERT(*hint_p == "now" || *hint_p == "disable");
            if (*hint_p == "now") {
                new_state = state_t::connected;
            }
        }
        GDK_LOG_SEV(log_level::info) << "reconnect_hint: " << state_str(new_state);
        change_state_to(new_state, true);
    }

    void wamp_transport::change_state_to(wamp_transport::state_t new_state, bool wait)
    {
        GDK_LOG_SEV(log_level::info) << "change_state_to: requesting state " << state_str(new_state);
        locker_t locker(m_mutex);
        m_desired_state = new_state;
        locker.unlock();
        m_condition.notify_all();

        if (wait) {
            // Busy wait for up to 30s while the reconnection thread changes state
            for (size_t i = 0; i < 300u; ++i) {
                std::this_thread::sleep_for(100ms);
                locker.lock();
                if (m_state == new_state) {
                    locker.unlock();
                    GDK_LOG_SEV(log_level::info) << "change_state_to: changed to " << state_str(new_state);
                    return;
                }
                locker.unlock();
            }
            throw timeout_error();
        }
    }

    void wamp_transport::emit_state(
        wamp_transport::state_t current, wamp_transport::state_t desired, uint64_t backoff_ms)
    {
        constexpr bool async = true;
        nlohmann::json state({ { "current_state", state_str(current) }, { "next_state", state_str(desired) },
            { "backoff_ms", backoff_ms } });
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
        const bool is_tls = m_net_params.is_tls_connection();
        const auto& executor = m_io.get_executor();

        // The last failure number that we handled
        auto last_handled_failure_count = m_failure_count.load();
        exponential_backoff backoff;

        GDK_LOG_SEV(log_level::info) << "net: thread started for gdk version " << GDK_COMMIT;

        for (;;) {
            decltype(m_transport) t;
            decltype(m_session) s;
            decltype(m_subscriptions) subscriptions;

            GDK_LOG_SEV(log_level::debug) << "net: taking mutex";
            locker_t locker(m_mutex);
            GDK_LOG_SEV(log_level::debug) << "net: mutex taken";
            const auto state = m_state.load();
            auto desired_state = m_desired_state.load();
            const auto failure_count = m_failure_count.load();
            const bool need_to_ping = !m_proxy.empty();

            if (desired_state != state_t::exited && last_handled_failure_count != failure_count) {
                GDK_LOG_SEV(log_level::info) << "net: unhandled failure detected";
                desired_state = state_t::disconnected;
            } else if (state == desired_state) {
                // We are already in the desired state. Wait until something changes
                GDK_LOG_SEV(log_level::debug) << "net: in state " << state_str(state);
                if (m_transport) {
                    if (!m_transport->is_connected()) {
                        // The transport has been closed or failed. Mark the
                        // error and loop again to reconnect if needed.
                        notify_failure(locker, "net: detected dead transport", false);
                        continue;
                    } else if (need_to_ping && is_elapsed(m_last_ping_ts, 20s)) {
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

                    locker.unlock();
                    GDK_LOG_SEV(log_level::info) << "net: disconnecting";
                    handle_disconnect(executor, t, s);
                    // If this disconnect was due to a handler failure,
                    // mark it handled. We will then either connect or
                    // not according to our desired state.
                    last_handled_failure_count = failure_count;
                    locker.lock();
                }

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
                    t = std::make_shared<transport_tls>(*m_client_tls, m_server, proxy, m_debug_logging);
                } else {
                    t = std::make_shared<transport>(*m_client, m_server, proxy, m_debug_logging);
                }
                s = std::make_shared<autobahn::wamp_session>(m_io, m_debug_logging);
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

    nlohmann::json wamp_transport::http_request(nlohmann::json params)
    {
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
            const auto ssl_ctx = tls_init(params["host"], root_certificates, {}, m_net_params.cert_expiry_threshold());

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
            const auto options = autobahn::wamp_subscribe_options("exact");
            sub = s->subscribe(
                       topic, [fn](const autobahn::wamp_event& e) { fn(wamp_cast_json(e)); }, options)
                      .get();
        }
        GDK_LOG_SEV(log_level::debug) << "subscribed to " << topic << ":" << sub.id();
        m_subscriptions.emplace_back(sub);
    }

} // namespace sdk
} // namespace ga
