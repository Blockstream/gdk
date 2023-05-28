#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/classification.hpp>
#include <boost/algorithm/string/erase.hpp>
#include <boost/algorithm/string/predicate.hpp>
#include <boost/algorithm/string/split.hpp>
#include <boost/algorithm/string/trim.hpp>
#include <chrono>

#include "assertion.hpp"
#include "logging.hpp"
#include "network_parameters.hpp"
#include "socks_client.hpp"
#include "utils.hpp"

namespace algo = boost::algorithm;
namespace asio = boost::asio;
namespace beast = boost::beast;

namespace ga {
namespace sdk {

    socks_client::socks_client(asio::io_context& io, boost::beast::tcp_stream& stream)
        : m_resolver(asio::make_strand(io))
        , m_stream(stream)
    {
    }

    std::future<void> socks_client::run(const std::string& endpoint, const std::string& proxy_uri)
    {
        GDK_LOG_SEV(log_level::debug) << "socks_client:run";

        m_endpoint = endpoint;

        std::string proxy = algo::trim_copy(proxy_uri);
        GDK_RUNTIME_ASSERT(algo::starts_with(proxy, "socks5://"));
        algo::erase_all(proxy, "socks5://");

        std::vector<std::string> proxy_parts;
        algo::split(proxy_parts, proxy, algo::is_any_of(":"));
        GDK_RUNTIME_ASSERT(proxy_parts.size() == 2);

        const auto host = proxy_parts[0];
        const auto port = proxy_parts[1];

        m_resolver.async_resolve(host, port, beast::bind_front_handler(&socks_client::on_resolve, shared_from_this()));

        return m_promise.get_future();
    }

    void socks_client::shutdown()
    {
        GDK_LOG_SEV(log_level::debug) << "socks_client:shutdown";

        beast::error_code ec;
        m_stream.socket().shutdown(asio::ip::tcp::socket::shutdown_both, ec);
        if (ec && ec != beast::errc::not_connected) {
            GDK_RUNTIME_ASSERT(false);
        }
    }

    void socks_client::on_resolve(beast::error_code ec, const asio::ip::tcp::resolver::results_type& results)
    {
        GDK_LOG_SEV(log_level::debug) << "socks_client:on_resolve";

        NET_ERROR_CODE_CHECK("socks_client", ec);
        m_stream.async_connect(results, beast::bind_front_handler(&socks_client::on_connect, shared_from_this()));
    }

    void socks_client::on_connect(
        beast::error_code ec, __attribute__((unused)) const asio::ip::tcp::resolver::results_type::endpoint_type& type)
    {
        GDK_LOG_SEV(log_level::debug) << "socks_client:on_connect";

        NET_ERROR_CODE_CHECK("socks_client", ec);

        m_negotiation_phase = negotiation_phase::method_selection;

        asio::async_write(m_stream, method_selection_request(),
            beast::bind_front_handler(&socks_client::on_write, shared_from_this()));
    }

    void socks_client::on_write(boost::beast::error_code ec, size_t __attribute__((unused)) bytes_transferred)
    {
        GDK_LOG_SEV(log_level::debug) << "socks_client:on_write";

        NET_ERROR_CODE_CHECK("socks_client", ec);

        m_response.resize(m_negotiation_phase == negotiation_phase::method_selection ? 2 : 4);
        asio::async_read(
            m_stream, asio::buffer(m_response), beast::bind_front_handler(&socks_client::on_read, shared_from_this()));
    }

    void socks_client::on_read(boost::beast::error_code ec, size_t __attribute__((unused)) bytes_transferred)
    {
        GDK_LOG_SEV(log_level::debug) << "socks_client:on_read";

        NET_ERROR_CODE_CHECK("socks_client", ec);

        if (m_response[1] != static_cast<uint8_t>(reply_code::success)) {
            return set_exception(get_error_string(m_response[1]));
        }

        if (m_negotiation_phase == negotiation_phase::method_selection) {
            m_negotiation_phase = negotiation_phase::connect;

            asio::const_buffer request;
            try {
                request = connect_request(m_endpoint);
            } catch (const std::exception& ex) {
                GDK_LOG_SEV(log_level::warning)
                    << "exception creating request for endpoint '" << m_endpoint << "':" << ex.what();
                return set_exception(ex.what());
            }
            asio::async_write(
                m_stream, request, beast::bind_front_handler(&socks_client::on_write, shared_from_this()));
        } else {

            if (m_negotiation_phase != negotiation_phase::connect) {
                return set_exception("expected negotiation phase to be connect");
            }

            const bool is_single_byte = m_response[3] != 0x1 && m_response[3] != 0x4;
            const size_t response_size = is_single_byte ? 1 : m_response[3] * 4 + sizeof(uint16_t);
            m_response.resize(response_size);

            asio::async_read(m_stream, asio::buffer(m_response),
                beast::bind_front_handler(&socks_client::on_connect_read, shared_from_this()));
        }
    }

    void socks_client::on_connect_read(boost::beast::error_code ec, size_t __attribute__((unused)) bytes_transferred)
    {
        GDK_LOG_SEV(log_level::debug) << "socks_client:on_connect_read";

        NET_ERROR_CODE_CHECK("socks_client", ec);

        if (m_negotiation_phase != negotiation_phase::connect) {
            return set_exception("expected negotiation phase to be connect");
        }

        if (m_response.size() == 1) {
            m_response.resize(m_response[0] + sizeof(uint16_t));
            asio::async_read(m_stream, asio::buffer(m_response),
                beast::bind_front_handler(&socks_client::on_domain_name_read, shared_from_this()));
        } else {
            m_promise.set_value();
        }
    }

    void socks_client::on_domain_name_read(
        boost::beast::error_code ec, size_t __attribute__((unused)) bytes_transferred)
    {
        GDK_LOG_SEV(log_level::debug) << "socks_client:on_domain_name_read";

        NET_ERROR_CODE_CHECK("socks_client", ec);

        m_promise.set_value();
    }

    asio::const_buffer socks_client::method_selection_request()
    {
        // version: 5
        // methods: 1
        // authentication: no authentication
        m_request.assign({ 0x5, 0x1, 0x0 });
        return asio::const_buffer(m_request.data(), m_request.size());
    }

    asio::const_buffer socks_client::connect_request(const std::string& url)
    {
        GDK_RUNTIME_ASSERT(!url.empty());

        const nlohmann::json url_info = parse_url(url);

        // version: 5
        // command: connect
        // reserved
        // address type domain name: 3
        // address size
        const std::string host = url_info["host"];
        m_request.assign({ 0x5, 0x1, 0x0, 0x3, static_cast<unsigned char>(host.size()) });
        std::copy(std::cbegin(host), std::cend(host), std::back_inserter(m_request));

        const std::string port_string = url_info["port"];
        uint16_t port = htons(std::stoul(port_string, nullptr, 10));
        const auto p = reinterpret_cast<const unsigned char*>(&port);
        std::copy(p, p + sizeof(uint16_t), std::back_inserter(m_request));

        return asio::const_buffer(m_request.data(), m_request.size());
    }

    std::string socks_client::get_error_string(uint8_t response)
    {
        if (response > static_cast<uint8_t>(reply_code::addr_type_not_supported)) {
            return "unknown error";
        }

        switch (static_cast<reply_code>(response)) {
        case reply_code::success:
            return "succeeded";
        case reply_code::general_failure:
            return "general SOCKS server failure";
        case reply_code::connection_not_allowed:
            return "connection not allowed by ruleset";
        case reply_code::network_unreachable:
            return "network unreachable";
        case reply_code::host_unreachable:
            return "host unreachable";
        case reply_code::connection_refused:
            return "connection refused";
        case reply_code::ttl_expired:
            return "TTL expired";
        case reply_code::not_supported:
            return "command not supported";
        case reply_code::addr_type_not_supported:
            return "address type not supported";
        default:
            return "unknown error";
        }

        __builtin_unreachable();
    }

    void socks_client::set_exception(const std::string& what)
    {
        m_promise.set_exception(std::make_exception_ptr(std::runtime_error(what)));
    }

} // namespace sdk
} // namespace ga
