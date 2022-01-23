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
#include "http_client.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "network_parameters.hpp"
#include "utils.hpp"
#include "version.h"
#include "wamp_transport.hpp"

#define TX_CACHE_LEVEL log_level::debug

using namespace std::literals;
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
        static const auto DEFAULT_PING = boost::posix_time::seconds(20); // ping message interval
        static const uint32_t DEFAULT_KEEPIDLE = 1; // tcp heartbeat frequency in seconds
        static const uint32_t DEFAULT_KEEPINTERVAL = 1; // tcp heartbeat frequency in seconds
        static const uint32_t DEFAULT_KEEPCNT = 2; // tcp unanswered heartbeats
        static const auto DEFAULT_DISCONNECT_WAIT = boost::chrono::seconds(2); // maximum wait time on disconnect

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

    } // namespace

    uint32_t websocket_rng_type::operator()() const
    {
        uint32_t b;
        get_random_bytes(sizeof(b), &b, sizeof(b));
        return b;
    }

    nlohmann::json wamp_cast_json(const autobahn::wamp_event& event) { return wamp_cast_json_impl(event); }

    nlohmann::json wamp_cast_json(const autobahn::wamp_call_result& result) { return wamp_cast_json_impl(result); }

    wamp_transport::wamp_transport(const network_parameters& net_params, wamp_transport::notify_fn_t fn)
        : m_net_params(net_params)
        , m_io()
        , m_work_guard(asio::make_work_guard(m_io))
        , m_wamp_call_prefix("com.greenaddress.")
        , m_wamp_call_options()
        , m_notify_fn(fn)
        , m_debug_logging(m_net_params.log_level() == "debug")
        , m_ping_timer(m_io)
        , m_reconnecting(false)
        , m_enabled(true)
    {
        constexpr uint32_t wamp_timeout_secs = 10;
        m_wamp_call_options.set_timeout(std::chrono::seconds(wamp_timeout_secs));

        m_run_thread = std::thread([this] { m_io.run(); });

        if (!m_net_params.is_tls_connection()) {
            m_client = std::make_unique<client>();
            boost::get<std::unique_ptr<client>>(m_client)->init_asio(&m_io);
            return;
        }

        m_client = std::make_unique<client_tls>();
        boost::get<std::unique_ptr<client_tls>>(m_client)->init_asio(&m_io);
        const auto host_name = websocketpp::uri(m_net_params.gait_wamp_url()).get_host();

        boost::get<std::unique_ptr<client_tls>>(m_client)->set_tls_init_handler(
            [this, host_name](const websocketpp::connection_hdl) {
                return tls_init(host_name, m_net_params.gait_wamp_cert_roots(), m_net_params.gait_wamp_cert_pins(),
                    m_net_params.cert_expiry_threshold());
            });
    }

    wamp_transport::~wamp_transport()
    {
        no_std_exception_escape([this] {
            reconnect_hint({ { "hint", "disable" } }); // Disable reconnect
            disconnect(true);
        });
        no_std_exception_escape([this] {
            m_work_guard.reset();
            m_run_thread.join();
        });
    }

    bool wamp_transport::set_reconnecting(bool want_to_reconnect)
    {
        bool currently_reconnecting = m_reconnecting;
        if (want_to_reconnect && currently_reconnecting) {
            return false; // Already reconnecting
        }
        bool can_reconnect = m_reconnecting.compare_exchange_strong(currently_reconnecting, want_to_reconnect);
        if (want_to_reconnect && can_reconnect) {
            // No one else is currently reconnecting.
            // Reset m_exit_flag to allow later cancelling of a reconnect.
            m_reconnect_promise = decltype(m_reconnect_promise)();
            m_reconnect_future = m_reconnect_promise.get_future();
        }
        return can_reconnect;
    }

    void wamp_transport::stop_reconnecting()
    {
        if (m_reconnecting) {
            // Set the future status to ready, causing is_reconnect_canceled to return true
            m_reconnect_promise.set_value();
        }
    }

    bool wamp_transport::is_reconnect_canceled(std::chrono::seconds secs) const
    {
        return m_reconnect_future.wait_for(secs) == std::future_status::ready;
    }

    void wamp_transport::set_reconnect_enabled(bool v) { m_enabled = v; }
    bool wamp_transport::is_reconnect_enabled() const { return m_enabled; }

    void wamp_transport::set_socket_options()
    {
        const bool is_tls = m_net_params.is_tls_connection();
        auto set_option = [this, is_tls](auto option) {
            if (is_tls) {
                GDK_RUNTIME_ASSERT(std::static_pointer_cast<transport_tls>(m_transport)->set_socket_option(option));
            } else {
                GDK_RUNTIME_ASSERT(std::static_pointer_cast<transport>(m_transport)->set_socket_option(option));
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

    void wamp_transport::connect(const std::string& proxy)
    {
        m_proxy = proxy;
        GDK_LOG_SEV(log_level::info) << "connecting";
        m_session = std::make_shared<autobahn::wamp_session>(m_io, m_debug_logging);

        const auto server = m_net_params.get_connection_string();
        std::string proxy_details;
        if (!proxy.empty()) {
            proxy_details = std::string(" through proxy ") + proxy;
        }
        GDK_LOG_SEV(log_level::info) << "Connecting using version " << GDK_COMMIT << " to " << server << proxy_details;
        decltype(m_transport) transport_p;
        using namespace std::placeholders;
        if (m_net_params.is_tls_connection()) {
            auto& clnt = *boost::get<std::unique_ptr<client_tls>>(m_client);
            clnt.set_pong_timeout_handler(std::bind(&wamp_transport::heartbeat_timeout_cb, this, _1, _2));
            transport_p = std::make_shared<transport_tls>(clnt, server, proxy, m_debug_logging);
        } else {
            auto& clnt = *boost::get<std::unique_ptr<client>>(m_client);
            clnt.set_pong_timeout_handler(std::bind(&wamp_transport::heartbeat_timeout_cb, this, _1, _2));
            transport_p = std::make_shared<transport>(clnt, server, proxy, m_debug_logging);
        }
        transport_p->attach(std::static_pointer_cast<autobahn::wamp_transport_handler>(m_session));
        m_transport = transport_p;
        m_transport->connect().get();
        m_session->start().get();
        m_session->join("realm1").get();
        set_socket_options();
        using std::placeholders::_1;
        start_ping_timer();
    }

    void wamp_transport::heartbeat_timeout_cb(websocketpp::connection_hdl, const std::string&)
    {
        GDK_LOG_SEV(log_level::info) << "pong timeout detected. reconnecting...";
        reconnect();
    }

    bool wamp_transport::ping() const
    {
        bool got_pong = false;
        no_std_exception_escape([this, &got_pong] {
            if (m_transport && m_transport->is_connected()) {
                if (m_net_params.is_tls_connection()) {
                    got_pong = std::static_pointer_cast<transport_tls>(m_transport)->ping(std::string());
                } else {
                    got_pong = std::static_pointer_cast<transport>(m_transport)->ping(std::string());
                }
            }
        });
        return got_pong;
    }

    autobahn::wamp_call_result wamp_transport::wamp_process_call(boost::future<autobahn::wamp_call_result>& fn) const
    {
        const auto ms = boost::chrono::milliseconds(m_wamp_call_options.timeout().count());
        for (;;) {
            const auto status = fn.wait_for(ms);
            if (status == boost::future_status::ready) {
                break;
            }
            if (status == boost::future_status::timeout && (!m_transport || !m_transport->is_connected())) {
                throw timeout_error{};
            }
        }
        try {
            return fn.get();
        } catch (const boost::future_error& ex) {
            GDK_LOG_SEV(log_level::warning) << "wamp_process_call exception: " << ex.what();
            throw reconnect_error{};
        }
    }

    void wamp_transport::ping_timer_handler(const boost::system::error_code& ec)
    {
        if (ec == asio::error::operation_aborted) {
            return;
        }

        if (!ping()) {
            GDK_LOG_SEV(log_level::info) << "ping failure detected. reconnecting...";
            reconnect();
        }

        start_ping_timer();
    }

    void wamp_transport::reconnect()
    {
        if (!m_io.get_executor().running_in_this_thread()) {
            GDK_LOG_SEV(log_level::info) << "reconnect: submitting to executor";
            auto f = asio::post(
                m_io.get_executor(), std::packaged_task<void()>(std::bind(&wamp_transport::reconnect, this)));
            f.get();
            return;
        }

        if (!is_reconnect_enabled()) {
            GDK_LOG_SEV(log_level::info) << "reconnect: disabled";
            return;
        }

        if (m_transport && m_transport->is_connected()) {
            GDK_LOG_SEV(log_level::info) << "reconnect: still connected";
            nlohmann::json net_json(
                { { "connected", true }, { "login_required", false }, { "heartbeat_timeout", true } });
            m_notify_fn({ { "event", "network" }, { "network", std::move(net_json) } }, true);
            return;
        }

        if (!set_reconnecting(true)) {
            GDK_LOG_SEV(log_level::info) << "reconnect: already in progress";
            return;
        }

        m_ping_timer.cancel();

        if (m_reconnect_thread) {
            GDK_LOG_SEV(log_level::info) << "reconnect: joining old reconnection thread";
            m_reconnect_thread->join();
            m_reconnect_thread.reset(); // In case 'new' throws below
        }

        m_reconnect_thread.reset(new std::thread([this] {
            std::ostringstream os;
            os << "reconnect: (" << std::hex << std::this_thread::get_id() << ") ";
            const auto prologue = os.str();

            GDK_LOG_SEV(log_level::info) << prologue << "started";

            exponential_backoff bo;
            uint32_t n = 0;
            for (;;) {
                const auto backoff_time = bo.backoff(n++);
                nlohmann::json net_json({ { "connected", false }, { "elapsed", bo.elapsed().count() },
                    { "waiting", bo.waiting().count() }, { "limit", bo.limit_reached() } });
                m_notify_fn({ { "event", "network" }, { "network", std::move(net_json) } }, true);

                if (!is_reconnect_enabled() || is_reconnect_canceled(backoff_time)) {
                    GDK_LOG_SEV(log_level::info) << prologue << "disabled/cancelled";
                    break;
                }

                try {
                    disconnect(false);
                    connect(m_proxy);
                    GDK_LOG_SEV(log_level::info) << prologue << "succeeded";

                    // FIXME: Re-work re-login
                    nlohmann::json net_json(
                        { { "connected", true }, { "login_required", true }, { "heartbeat_timeout", false } });
                    m_notify_fn({ { "event", "network" }, { "network", std::move(net_json) } }, true);

                    break;
                } catch (const std::exception& ex) {
                    GDK_LOG_SEV(log_level::info) << prologue << " exception: " << ex.what();
                    // Continue
                }
            }

            set_reconnecting(false);

            if (!m_transport || !m_transport->is_connected()) {
                start_ping_timer();
            }
        }));
    }

    void wamp_transport::reconnect_hint(const nlohmann::json& hint)
    {
        bool enable = false;
        const auto hint_p = hint.find("hint");
        if (hint_p != hint.end()) {
            GDK_RUNTIME_ASSERT(*hint_p == "now" || *hint_p == "disable");
            enable = *hint_p == "now";
        }
        GDK_LOG_SEV(log_level::info) << "reconnect_hint: " << (enable ? "enable" : "disable");

        // Enable/disable any new reconnection attempts
        set_reconnect_enabled(enable);
        if (!enable) {
            // Prevent the ping timer from attempting to reconnect
            m_ping_timer.cancel();

            // Stop any in-progress reconnection attempts
            stop_reconnecting();
            decltype(m_reconnect_thread) t;
            // Fetch the reconnect thread pointer from within the executor
            auto f = asio::post(m_io.get_executor(), std::packaged_task<void()>([this, &t] {
                if (m_reconnect_thread) {
                    std::swap(t, m_reconnect_thread);
                }
            }));
            f.get(); // Wait for the executor to run our pointer fetch

            if (t) {
                GDK_LOG_SEV(log_level::info) << "reconnect_hint: joining reconnection thread";
                t->join();
            }
        }
    }

    void wamp_transport::start_ping_timer()
    {
        GDK_LOG_SEV(log_level::debug) << "starting ping timer...";
        m_ping_timer.expires_from_now(DEFAULT_PING);
        using std::placeholders::_1;
        m_ping_timer.async_wait(std::bind(&wamp_transport::ping_timer_handler, this, _1));
    }

    void wamp_transport::disconnect(bool user_initiated)
    {
        GDK_LOG_SEV(log_level::info) << "disconnecting";
        m_ping_timer.cancel();

        if (m_session) {
            unsubscribe();
            no_std_exception_escape([this] {
                const auto status = m_session->leave().wait_for(DEFAULT_DISCONNECT_WAIT);
                if (status != boost::future_status::ready) {
                    GDK_LOG_SEV(log_level::info) << "future not ready on leave session";
                }
            });
            no_std_exception_escape([this] {
                const auto status = m_session->stop().wait_for(DEFAULT_DISCONNECT_WAIT);
                if (status != boost::future_status::ready) {
                    GDK_LOG_SEV(log_level::info) << "future not ready on stop session";
                }
            });
            m_session.reset();
        }

        if (m_transport) {
            no_std_exception_escape([&] {
                const auto status = m_transport->disconnect().wait_for(DEFAULT_DISCONNECT_WAIT);
                if (status != boost::future_status::ready) {
                    GDK_LOG_SEV(log_level::info) << "future not ready on disconnect";
                }
            });
            no_std_exception_escape([&] { m_transport->detach(); });
            // Wait for the transport to be disconnected
            while (m_transport->is_connected()) {
                GDK_LOG_SEV(log_level::info) << "waiting for connection to die";
                std::this_thread::sleep_for(1ms);
            }
            m_transport.reset();
        }

        if (!user_initiated) {
            // Note we don't emit a notification if the user explicitly
            // disconnected or destroyed the session.
            nlohmann::json details{ { "connected", false } };
            m_notify_fn({ { "event", "session" }, { "session", std::move(details) } }, false);
        }
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

    void wamp_transport::subscribe(
        wamp_transport::locker_t& locker, const std::string& topic, wamp_transport::subscribe_fn_t callback)
    {
        GDK_RUNTIME_ASSERT(locker.owns_lock());
        GDK_RUNTIME_ASSERT(m_session.get());
        unique_unlock unlocker(locker);
        const auto options = autobahn::wamp_subscribe_options("exact");
        auto sub = m_session
                       ->subscribe(
                           topic, [callback](const autobahn::wamp_event& e) { callback(wamp_cast_json(e)); }, options)
                       .get();
        GDK_LOG_SEV(log_level::debug) << "subscribed to topic:" << sub.id();
        m_subscriptions.emplace_back(sub);
    }

    void wamp_transport::unsubscribe()
    {
        decltype(m_subscriptions) subscriptions;
        {
            // FIXME: locker_t locker(m_mutex);
            subscriptions.swap(m_subscriptions);
        };

        no_std_exception_escape([this, &subscriptions] {
            for (const auto& sub : subscriptions) {
                const auto status = m_session->unsubscribe(sub).wait_for(DEFAULT_DISCONNECT_WAIT);
                if (status != boost::future_status::ready) {
                    GDK_LOG_SEV(log_level::info) << "future not ready on unsubscribe";
                }
            }
        });
    }

    void wamp_transport::clear_subscriptions()
    {
        m_subscriptions.clear();
        m_subscriptions.reserve(4u);
    }

} // namespace sdk
} // namespace ga
