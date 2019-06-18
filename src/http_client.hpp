#ifndef GDK_HTTP_CLIENT_HPP
#define GDK_HTTP_CLIENT_HPP
#pragma once

#include <future>
#include <memory>
#include <nlohmann/json.hpp>

#include "boost_wrapper.hpp"
#include "socks_client.hpp"

namespace ga {
namespace sdk {

    class http_client final : public std::enable_shared_from_this<http_client> {
    public:
        explicit http_client(boost::asio::io_context& io, boost::asio::ssl::context& ssl_ctx);

        http_client(const http_client&) = delete;
        http_client(http_client&&) = delete;
        http_client& operator=(const http_client&) = delete;
        http_client& operator=(http_client&&) = delete;

        std::future<nlohmann::json> get(const std::string& host, const std::string& port, const std::string& target,
            const std::string& proxy_uri = {});

    private:
        void on_resolve(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type results);
        void on_connect(boost::beast::error_code ec, boost::asio::ip::tcp::resolver::results_type::endpoint_type);
        void on_handshake(boost::beast::error_code ec);
        void on_write(boost::beast::error_code ec, size_t bytes_transferred);
        void on_read(boost::beast::error_code ec, size_t bytes_transferred);
        void on_shutdown(boost::beast::error_code ec);

        void set_result();
        void set_exception(const std::string& what);

        boost::asio::ip::tcp::resolver m_resolver;
        boost::beast::ssl_stream<boost::beast::tcp_stream> m_stream;
        boost::beast::flat_buffer m_buffer;
        boost::beast::http::request<boost::beast::http::empty_body> m_request;
        boost::beast::http::response<boost::beast::http::string_body> m_response;

        std::promise<nlohmann::json> m_promise;

        boost::asio::io_context& m_io;
    };
} // namespace sdk
} // namespace ga

#endif
