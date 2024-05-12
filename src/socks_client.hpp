#ifndef GDK_SOCKS_CLIENT_HPP
#define GDK_SOCKS_CLIENT_HPP
#pragma once

#include <memory>

namespace green {
namespace sdk {

    class socks_client final : public std::enable_shared_from_this<socks_client> {
    public:
        explicit socks_client(boost::asio::io_context& io, boost::beast::tcp_stream& stream);

        socks_client(const socks_client&) = delete;
        socks_client(socks_client&&) = delete;
        socks_client& operator=(const socks_client&) = delete;
        socks_client& operator=(socks_client&&) = delete;
        ~socks_client() = default;

        std::future<void> run(const std::string& endpoint, const std::string& proxy_uri);
        void shutdown();

    private:
        enum class reply_code {
            success,
            general_failure,
            connection_not_allowed,
            network_unreachable,
            host_unreachable,
            connection_refused,
            ttl_expired,
            not_supported,
            addr_type_not_supported
        };

        enum class negotiation_phase { method_selection, connect };

        void on_resolve(boost::beast::error_code ec, const boost::asio::ip::tcp::resolver::results_type& results);
        void on_connect(
            boost::beast::error_code ec, const boost::asio::ip::tcp::resolver::results_type::endpoint_type& type);
        void on_write(boost::beast::error_code ec, size_t bytes_transferred);
        void on_read(boost::beast::error_code ec, size_t bytes_transferred);
        void on_connect_read(boost::beast::error_code ec, size_t bytes_transferred);
        void on_domain_name_read(boost::beast::error_code ec, size_t bytes_transferred);

        std::string get_error_string(uint8_t response);
        void set_exception(const std::string& what);

        // SOCKS5 request. TODO: this is a simplified version of the code PR'd to websocketpp
        boost::asio::const_buffer method_selection_request();
        boost::asio::const_buffer connect_request(const std::string& domain_name);

        boost::asio::ip::tcp::resolver m_resolver;
        boost::beast::tcp_stream& m_stream;
        std::string m_endpoint;

        std::vector<unsigned char> m_request;
        std::vector<unsigned char> m_response;
        negotiation_phase m_negotiation_phase{ negotiation_phase::method_selection };

        std::promise<void> m_promise;
    };
} // namespace sdk
} // namespace green

#endif
