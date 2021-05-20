#include "http_client.hpp"
#include "assertion.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "network_parameters.hpp"
#include "utils.hpp"

namespace asio = boost::asio;
namespace beast = boost::beast;

using namespace std::literals;

namespace ga {
namespace sdk {

    namespace {

        constexpr uint8_t HTTP_VERSION = 11;

        // This timeout is the time-frame in which the entire operation must complete.
        // ie. from issuing the initial request to receiving the entire response.
        // It is *not* a timeout between constituent consecutive packets.
        //
        // The underlying protocol ought to monitor time between underlying
        // transport packets, and timeout if there is an apparent interruption,
        // but since we cannot test that easily (on all platforms) we will apply
        // a 'whole operation' timeout here as belt-and-braces.
        // NOTE: this timeout expiring appears to cause a 'partial message' error,
        // rather than an obvious 'timeout' error.
        constexpr auto HTTP_TIMEOUT = 30s;

    } // namespace

    http_client::http_client(boost::asio::io_context& io)
        : m_resolver(asio::make_strand(io))
        , m_timeout(HTTP_TIMEOUT)
        , m_io(io)
    {
    }

    std::future<nlohmann::json> http_client::request(beast::http::verb verb, const nlohmann::json& params)
    {
        GDK_LOG_NAMED_SCOPE("http_client");

        m_host = params.at("host");
        m_port = params.at("port");
        const std::string target = params.at("target");
        const std::string proxy_uri = params.at("proxy");

        GDK_LOG_SEV(log_level::debug) << "Connecting to " << m_host << ":" << m_port << " for target " << target;

        const auto timeout_p = params.find("timeout");
        if (timeout_p != params.end()) {
            m_timeout = std::chrono::seconds(timeout_p->get<int>());
        }
        GDK_LOG_SEV(log_level::debug) << "HTTP timeout " << m_timeout.count() << " seconds";

        preamble(m_host);

        m_request.version(HTTP_VERSION);
        m_request.method(verb);
        m_request.target(target);
        m_request.set(beast::http::field::connection, "close");
        m_request.set(beast::http::field::host, m_host);
        m_request.set(beast::http::field::user_agent, "GreenAddress SDK");

        const auto data_p = params.find("data");
        if (data_p != params.end()) {
            m_request.body() = data_p->dump();
            m_request.prepare_payload();
        }

        const auto headers = params.value("headers", nlohmann::json{});
        if (!headers.empty()) {
            for (const auto& header : headers.items()) {
                const std::string value = header.value();
                m_request.set(beast::http::string_to_field(header.key()), value);
            }
        }

        m_accept = params.value("accept", "");

        if (!proxy_uri.empty()) {
            get_lowest_layer().expires_after(m_timeout);
            auto proxy = std::make_shared<socks_client>(m_io, get_next_layer());
            GDK_RUNTIME_ASSERT(proxy != nullptr);
            auto f = proxy->run(m_host + ":" + m_port, proxy_uri);
            f.get();
            async_handshake();
        } else {
            async_resolve(m_host, m_port);
        }

        return m_promise.get_future();
    }

    void http_client::on_resolve(beast::error_code ec, asio::ip::tcp::resolver::results_type results)
    {
        GDK_LOG_NAMED_SCOPE("http_client:on_resolve");

        NET_ERROR_CODE_CHECK("on resolve", ec);
        get_lowest_layer().expires_after(m_timeout);
        async_connect(std::move(results));
    }

    void http_client::on_write(beast::error_code ec, size_t __attribute__((unused)) bytes_transferred)
    {
        GDK_LOG_NAMED_SCOPE("http_client:on_write");

        NET_ERROR_CODE_CHECK("on write", ec);
        get_lowest_layer().expires_after(m_timeout);
        async_read();
    }

    void http_client::on_read(beast::error_code ec, size_t __attribute__((unused)) bytes_transferred)
    {
        GDK_LOG_NAMED_SCOPE("http_client:on_read");

        NET_ERROR_CODE_CHECK("on read", ec);
        get_lowest_layer().cancel();
        async_shutdown();
    }

    void http_client::on_shutdown(beast::error_code ec)
    {
        GDK_LOG_NAMED_SCOPE("http_client");

        if (ec && ec != asio::error::eof && ec != asio::ssl::error::stream_truncated) {
            set_exception(ec.message());
            return;
        }

        set_result();
    }

    void http_client::preamble(__attribute__((unused)) const std::string& host) {}

    void http_client::set_result()
    {
        const auto result = m_response.result();

        if (result == beast::http::status::not_modified) {
            const nlohmann::json body = { { "not_modified", true } };
            GDK_LOG_SEV(log_level::debug) << "using cached resource";
            m_promise.set_value(body);
            return;
        }

        if (beast::http::to_status_class(result) == beast::http::status_class::redirection) {
            const nlohmann::json body = { { "location", m_response[beast::http::field::location] } };
            m_promise.set_value(body);
            return;
        }

        if (result != beast::http::status::ok) {
            std::stringstream error;
            error << result;
            set_exception(error.str());
            return;
        }

        try {
            nlohmann::json body;

            if (m_accept == "json") {
                body["body"] = nlohmann::json::parse(m_response.body());
            } else if (m_accept == "base64") {
                body["body"] = base64_from_bytes(ustring_span(m_response.body()));
            } else {
                body["body"] = m_response.body();
            }

            for (const auto& field : m_response.base()) {
                const std::string field_name = field.name_string().to_string();
                const std::string field_value = field.value().to_string();
                body["headers"][boost::algorithm::to_lower_copy(field_name)] = field_value;
            }

            m_promise.set_value(body);
        } catch (const std::exception& ex) {
            m_promise.set_exception(std::make_exception_ptr(ex));
        }
    }

    void http_client::set_exception(const std::string& what)
    {
        m_promise.set_exception(std::make_exception_ptr(std::runtime_error(what)));
    }

    tls_http_client::tls_http_client(asio::io_context& io, asio::ssl::context& ssl_ctx)
        : http_client(io)
        , m_stream(asio::make_strand(io), ssl_ctx)
    {
    }

    void tls_http_client::on_connect(
        beast::error_code ec, __attribute__((unused)) const asio::ip::tcp::resolver::results_type::endpoint_type& type)
    {
        GDK_LOG_NAMED_SCOPE("http_client:on_connect");

        NET_ERROR_CODE_CHECK("on connect", ec);
        async_handshake();
    }

    void tls_http_client::on_handshake(beast::error_code ec)
    {
        GDK_LOG_NAMED_SCOPE("http_client:on_handshake");

        NET_ERROR_CODE_CHECK("on handshake", ec);
        get_lowest_layer().expires_after(m_timeout);
        async_write();
    }

#define ASYNC_READ                                                                                                     \
    beast::http::async_read(                                                                                           \
        m_stream, m_buffer, m_response, beast::bind_front_handler(&http_client::on_read, shared_from_this()));

#define ASYNC_RESOLVE                                                                                                  \
    m_resolver.async_resolve(host, port, beast::bind_front_handler(&http_client::on_resolve, shared_from_this()));

#define ASYNC_WRITE                                                                                                    \
    beast::http::async_write(                                                                                          \
        m_stream, m_request, beast::bind_front_handler(&http_client::on_write, shared_from_this()));

    beast::tcp_stream& tls_http_client::get_lowest_layer() { return boost::beast::get_lowest_layer(m_stream); }

    beast::tcp_stream& tls_http_client::get_next_layer() { return m_stream.next_layer(); }

    void tls_http_client::async_connect(asio::ip::tcp::resolver::results_type results)
    {
        get_lowest_layer().async_connect(
            results, beast::bind_front_handler(&tls_http_client::on_connect, shared_from_this()));
    }

    void tls_http_client::async_read() { ASYNC_READ; }

    void tls_http_client::async_write() { ASYNC_WRITE; }

    void tls_http_client::async_shutdown()
    {
        m_stream.async_shutdown(beast::bind_front_handler(&http_client::on_shutdown, shared_from_this()));
    }

    void tls_http_client::async_handshake()
    {
        get_lowest_layer().expires_after(m_timeout);
        m_stream.async_handshake(asio::ssl::stream_base::client,
            beast::bind_front_handler(&tls_http_client::on_handshake, shared_from_this()));
    }

    void tls_http_client::async_resolve(const std::string& host, const std::string& port) { ASYNC_RESOLVE; }

    void tls_http_client::preamble(const std::string& host)
    {
        if (!SSL_set_tlsext_host_name(m_stream.native_handle(), host.c_str())) {
            beast::error_code ec{ static_cast<int>(::ERR_get_error()), asio::error::get_ssl_category() };
            GDK_RUNTIME_ASSERT_MSG(false, ec.message());
        }
    }

    tcp_http_client::tcp_http_client(boost::asio::io_context& io)
        : http_client(io)
        , m_stream(asio::make_strand(io))
    {
    }

    boost::beast::tcp_stream& tcp_http_client::get_lowest_layer() { return m_stream; }

    boost::beast::tcp_stream& tcp_http_client::get_next_layer() { return m_stream; }

    void tcp_http_client::async_connect(asio::ip::tcp::resolver::results_type results)
    {
        m_stream.async_connect(results, beast::bind_front_handler(&tcp_http_client::on_connect, shared_from_this()));
    }

    void tcp_http_client::async_read() { ASYNC_READ; }

    void tcp_http_client::async_write() { ASYNC_WRITE; }

    void tcp_http_client::async_shutdown()
    {
        beast::error_code ec;
        m_stream.socket().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != beast::errc::not_connected) {
            NET_ERROR_CODE_CHECK("async_shutdown", ec);
            return;
        }

        set_result();
    }

    void tcp_http_client::async_handshake() { ASYNC_WRITE; }

    void tcp_http_client::async_resolve(const std::string& host, const std::string& port) { ASYNC_RESOLVE; }

    void tcp_http_client::on_connect(boost::beast::error_code ec,
        __attribute__((unused)) const boost::asio::ip::tcp::resolver::results_type::endpoint_type& type)
    {
        GDK_LOG_NAMED_SCOPE("tcp_http_client");

        NET_ERROR_CODE_CHECK("on connect", ec);

        async_write();
    }

#undef ASYNC_WRITE
#undef ASYNC_RESOLVE
#undef ASYNC_READ

} // namespace sdk
} // namespace ga
