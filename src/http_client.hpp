#ifndef GDK_HTTP_CLIENT_HPP
#define GDK_HTTP_CLIENT_HPP
#pragma once

#include <chrono>
#include <future>
#include <memory>
#include <nlohmann/json.hpp>

#include "boost_wrapper.hpp"
#include "gsl_wrapper.hpp"
#include "socks_client.hpp"

namespace ga {
namespace sdk {

    class http_client {
    public:
        http_client(const http_client&) = delete;
        http_client(http_client&&) = delete;
        http_client& operator=(const http_client&) = delete;
        http_client& operator=(http_client&&) = delete;
        virtual ~http_client() = default;

        std::future<nlohmann::json> request(boost::beast::http::verb verb, const nlohmann::json& params);

        void on_resolve(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type results);
        void on_write(boost::beast::error_code ec, size_t bytes_transferred);
        void on_read(boost::beast::error_code ec, size_t bytes_transferred);
        void on_shutdown(boost::beast::error_code ec);

    protected:
        explicit http_client(boost::asio::io_context& io);

        virtual boost::beast::tcp_stream& get_lowest_layer() = 0;
        virtual boost::beast::tcp_stream& get_next_layer() = 0;
        virtual void async_connect(boost::asio::ip::tcp::resolver::results_type results) = 0;
        virtual void async_read() = 0;
        virtual void async_write() = 0;
        virtual void async_shutdown() = 0;
        virtual void async_handshake() = 0;
        virtual void async_resolve(const std::string& host, const std::string& port) = 0;
        virtual void preamble(const std::string& host);

        void set_result();
        void set_exception(const std::string& what);

        boost::asio::ip::tcp::resolver m_resolver;
        boost::beast::flat_buffer m_buffer;
        boost::beast::http::request<boost::beast::http::string_body> m_request;
        boost::beast::http::response_parser<boost::beast::http::string_body> m_response;
        std::chrono::seconds m_timeout;
        std::string m_host;
        std::string m_port;
        std::string m_accept;

        std::promise<nlohmann::json> m_promise;

        boost::asio::io_context& m_io;
    };

    class tls_http_client final : public std::enable_shared_from_this<tls_http_client>, public http_client {
    public:
        explicit tls_http_client(boost::asio::io_context& io, boost::asio::ssl::context& ssl_ctx);

    private:
        boost::beast::tcp_stream& get_lowest_layer() override;
        boost::beast::tcp_stream& get_next_layer() override;
        void async_connect(boost::asio::ip::tcp::resolver::results_type results) override;
        void async_read() override;
        void async_write() override;
        void async_shutdown() override;
        void async_handshake() override;
        void async_resolve(const std::string& host, const std::string& port) override;
        void preamble(const std::string& host) override;

        void on_connect(
            boost::beast::error_code ec, const boost::asio::ip::tcp::resolver::results_type::endpoint_type& type);
        void on_handshake(boost::beast::error_code ec);

        boost::beast::ssl_stream<boost::beast::tcp_stream> m_stream;
    };

    class tcp_http_client final : public std::enable_shared_from_this<tcp_http_client>, public http_client {
    public:
        explicit tcp_http_client(boost::asio::io_context& io);

    private:
        boost::beast::tcp_stream& get_lowest_layer() override;
        boost::beast::tcp_stream& get_next_layer() override;
        void async_connect(boost::asio::ip::tcp::resolver::results_type results) override;
        void async_read() override;
        void async_write() override;
        void async_shutdown() override;
        void async_handshake() override;
        void async_resolve(const std::string& host, const std::string& port) override;

        void on_connect(
            boost::beast::error_code ec, const boost::asio::ip::tcp::resolver::results_type::endpoint_type& type);

        boost::beast::tcp_stream m_stream;
    };

    std::shared_ptr<boost::asio::ssl::context> tls_init(const std::string& host_name,
        const std::vector<std::string>& roots, const std::vector<std::string>& pins, uint32_t cert_expiry_threshold);

    inline std::shared_ptr<http_client> make_http_client(
        boost::asio::io_context& io, gsl::owner<boost::asio::ssl::context*> ssl_ctx)
    {
        return ssl_ctx != nullptr ? std::shared_ptr<http_client>(new tls_http_client(io, *ssl_ctx))
                                  : std::shared_ptr<http_client>(new tcp_http_client(io));
    }

} // namespace sdk
} // namespace ga

#endif
