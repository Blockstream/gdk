#include "http_client.hpp"
#include "assertion.hpp"
#include "logging.hpp"
#include "network_parameters.hpp"

namespace algo = boost::algorithm;
namespace asio = boost::asio;
namespace beast = boost::beast;

using namespace std::literals;

namespace ga {
namespace sdk {

    namespace {

        constexpr uint8_t HTTP_VERSION = 11;
        constexpr auto HTTP_TIMEOUT = 5s;

    } // namespace

    http_client::http_client(asio::io_context& io, asio::ssl::context& ssl_ctx)
        : m_resolver(asio::make_strand(io))
        , m_stream(asio::make_strand(io), ssl_ctx)
        , m_io(io)
    {
    }

    std::future<nlohmann::json> http_client::get(
        const std::string& host, const std::string& port, const std::string& target, const std::string& proxy_uri)
    {
        GDK_LOG_NAMED_SCOPE("http_client:get");

        m_request.version(HTTP_VERSION);
        m_request.method(beast::http::verb::get);
        m_request.target(target);
        m_request.set(beast::http::field::connection, "close");
        m_request.set(beast::http::field::host, host);
        m_request.set(beast::http::field::user_agent, "GreenAddress SDK");

        if (!proxy_uri.empty()) {
            auto proxy = std::make_shared<socks_client>(m_io, m_stream.next_layer());
            GDK_RUNTIME_ASSERT(proxy != nullptr);
            auto f = proxy->run(host + ":" + port, proxy_uri);
            f.get();
            m_stream.async_handshake(asio::ssl::stream_base::client,
                beast::bind_front_handler(&http_client::on_handshake, shared_from_this()));
        } else {
            m_resolver.async_resolve(
                host, port, beast::bind_front_handler(&http_client::on_resolve, shared_from_this()));
        }

        return m_promise.get_future();
    }

    void http_client::on_resolve(beast::error_code ec, asio::ip::tcp::resolver::results_type results)
    {
        GDK_LOG_NAMED_SCOPE("http_client:on_resolve");

        NET_ERROR_CODE_CHECK("on resolve", ec);
        beast::get_lowest_layer(m_stream).expires_after(HTTP_TIMEOUT);
        beast::get_lowest_layer(m_stream).async_connect(
            results, beast::bind_front_handler(&http_client::on_connect, shared_from_this()));
    }

    void http_client::on_connect(beast::error_code ec, asio::ip::tcp::resolver::results_type::endpoint_type)
    {
        GDK_LOG_NAMED_SCOPE("http_client:on_connect");

        NET_ERROR_CODE_CHECK("on connect", ec);
        beast::get_lowest_layer(m_stream).expires_after(HTTP_TIMEOUT);
        m_stream.async_handshake(
            asio::ssl::stream_base::client, beast::bind_front_handler(&http_client::on_handshake, shared_from_this()));
    }

    void http_client::on_handshake(beast::error_code ec)
    {
        GDK_LOG_NAMED_SCOPE("http_client:on_handshake");

        NET_ERROR_CODE_CHECK("on handshake", ec);
        beast::get_lowest_layer(m_stream).expires_after(HTTP_TIMEOUT);
        beast::http::async_write(
            m_stream, m_request, beast::bind_front_handler(&http_client::on_write, shared_from_this()));
    }

    void http_client::on_write(beast::error_code ec, size_t __attribute__((unused)) bytes_transferred)
    {
        GDK_LOG_NAMED_SCOPE("http_client:on_write");

        NET_ERROR_CODE_CHECK("on write", ec);
        beast::get_lowest_layer(m_stream).expires_after(HTTP_TIMEOUT);
        beast::http::async_read(
            m_stream, m_buffer, m_response, beast::bind_front_handler(&http_client::on_read, shared_from_this()));
    }

    void http_client::on_read(beast::error_code ec, size_t __attribute__((unused)) bytes_transferred)
    {
        GDK_LOG_NAMED_SCOPE("http_client:on_read");

        NET_ERROR_CODE_CHECK("on read", ec);

        beast::get_lowest_layer(m_stream).cancel();
        m_stream.async_shutdown(beast::bind_front_handler(&http_client::on_shutdown, shared_from_this()));
    }

    void http_client::on_shutdown(beast::error_code ec)
    {
        GDK_LOG_NAMED_SCOPE("http_client:on_shutdown");

        if (ec && ec != asio::error::eof) {
            set_exception(ec.message());
            return;
        }

        try {
            m_promise.set_value(nlohmann::json::parse(m_response.body()));
        } catch (const std::exception& ex) {
            m_promise.set_exception(std::make_exception_ptr(ex));
        }
    }

    void http_client::set_exception(const std::string& what)
    {
        m_promise.set_exception(std::make_exception_ptr(std::runtime_error(what)));
    }

} // namespace sdk
} // namespace ga
