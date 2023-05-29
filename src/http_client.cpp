#include <boost/algorithm/string/case_conv.hpp>
#include <boost/algorithm/string/predicate.hpp>

#include "assertion.hpp"
#include "autobahn_wrapper.hpp"
#include "http_client.hpp"
#include "logging.hpp"
#include "memory.hpp"
#include "network_parameters.hpp"
#include "socks_client.hpp"
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

    std::shared_ptr<boost::asio::ssl::context> tls_init(const std::string& host_name,
        const std::vector<std::string>& roots, const std::vector<std::string>& pins, uint32_t cert_expiry_threshold)
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

        ctx->set_verify_callback(
            [pins, host_name, cert_expiry_threshold](bool preverified, asio::ssl::verify_context& vctx) {
                // Pre-verification includes checking for things like expired certificates
                if (!preverified) {
                    const int err = X509_STORE_CTX_get_error(vctx.native_handle());
                    GDK_LOG_SEV(log_level::error) << "x509 certificate error: " << X509_verify_cert_error_string(err);
                    return false;
                }

                // If pins are defined check that at least one of the pins is in the
                // certificate chain
                // If no pins are specified skip the check altogether
                const bool have_pins = !pins.empty() && !pins[0].empty();
                if (have_pins && !check_cert_pins(pins, vctx, cert_expiry_threshold)) {
                    GDK_LOG_SEV(log_level::error) << "Failing ssl verification, failed pin check";
                    return false;
                }

                // Check the host name matches the target
                return asio::ssl::rfc2818_verification{ host_name }(true, vctx);
            });

        return ctx;
    }

    http_client::http_client(boost::asio::io_context& io)
        : m_resolver(asio::make_strand(io))
        , m_timeout(HTTP_TIMEOUT)
        , m_io(io)
    {
    }

    std::future<nlohmann::json> http_client::request(beast::http::verb verb, const nlohmann::json& params)
    {
        GDK_LOG_SEV(log_level::debug) << "http_client";

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

        const auto headers = params.value("headers", nlohmann::json{});
        std::string content_type;
        for (const auto& header : headers.items()) {
            auto field = beast::http::string_to_field(header.key());
            std::string value = header.value();
            if (field == beast::http::field::content_type) {
                content_type = value;
            }
            m_request.set(field, value);
        }

        const auto data_p = params.find("data");
        if (data_p != params.end()) {
            if (content_type.empty() || data_p->type() == nlohmann::json::value_t::object
                || boost::algorithm::starts_with(content_type, "application/json")) {
                m_request.body() = data_p->dump();
            } else {
                m_request.body() = data_p->get<std::string>();
            }
            m_request.prepare_payload();
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
        GDK_LOG_SEV(log_level::debug) << "http_client:on_resolve";

        NET_ERROR_CODE_CHECK("on resolve", ec);
        get_lowest_layer().expires_after(m_timeout);
        async_connect(std::move(results));
    }

    void http_client::on_write(beast::error_code ec, size_t __attribute__((unused)) bytes_transferred)
    {
        GDK_LOG_SEV(log_level::debug) << "http_client:on_write";

        NET_ERROR_CODE_CHECK("on write", ec);
        get_lowest_layer().expires_after(m_timeout);
        m_response.body_limit(64 * 1024 * 1024);
        async_read();
    }

    void http_client::on_read(beast::error_code ec, size_t __attribute__((unused)) bytes_transferred)
    {
        GDK_LOG_SEV(log_level::debug) << "http_client:on_read";

        NET_ERROR_CODE_CHECK("on read", ec);
        get_lowest_layer().cancel();
        async_shutdown();
    }

    void http_client::on_shutdown(beast::error_code ec)
    {
        GDK_LOG_SEV(log_level::debug) << "http_client";

        if (ec && ec != asio::error::eof && ec != asio::ssl::error::stream_truncated) {
            set_exception(ec.message());
            return;
        }

        set_result();
    }

    void http_client::preamble(__attribute__((unused)) const std::string& host) {}

    void http_client::set_result()
    {
        auto response = m_response.release();
        const auto result = response.result();

        if (result == beast::http::status::not_modified) {
            const nlohmann::json body = { { "not_modified", true } };
            GDK_LOG_SEV(log_level::debug) << "using cached resource";
            m_promise.set_value(body);
            return;
        }

        if (beast::http::to_status_class(result) == beast::http::status_class::redirection) {
            const nlohmann::json body = { { "location", response[beast::http::field::location] } };
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
                body["body"] = nlohmann::json::parse(response.body());
            } else if (m_accept == "base64") {
                body["body"] = base64_from_bytes(ustring_span(response.body()));
            } else {
                body["body"] = std::move(response.body());
            }

            for (const auto& field : response.base()) {
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
        GDK_LOG_SEV(log_level::debug) << "http_client:on_connect";

        NET_ERROR_CODE_CHECK("on connect", ec);
        async_handshake();
    }

    void tls_http_client::on_handshake(beast::error_code ec)
    {
        GDK_LOG_SEV(log_level::debug) << "http_client:on_handshake";

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
        GDK_LOG_SEV(log_level::debug) << "tcp_http_client";

        NET_ERROR_CODE_CHECK("on connect", ec);

        async_write();
    }

#undef ASYNC_WRITE
#undef ASYNC_RESOLVE
#undef ASYNC_READ

} // namespace sdk
} // namespace ga
