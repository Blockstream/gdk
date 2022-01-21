#ifndef GDK_WAMP_TRANSPORT_HPP
#define GDK_WAMP_TRANSPORT_HPP
#pragma once

#include <string>
#include <vector>

#include "autobahn_wrapper.hpp"
#include "logging.hpp"

namespace ga {
namespace sdk {
    struct websocketpp_gdk_config;
    struct websocketpp_gdk_tls_config;
    struct tor_controller;

    using client = websocketpp::client<websocketpp_gdk_config>;
    using client_tls = websocketpp::client<websocketpp_gdk_tls_config>;

    nlohmann::json wamp_cast_json(const autobahn::wamp_event& event);
    nlohmann::json wamp_cast_json(const autobahn::wamp_call_result& result);

    template <typename T = std::string> T wamp_cast(const autobahn::wamp_call_result& result)
    {
        return result.template argument<T>(0);
    }

    template <typename T = std::string> boost::optional<T> wamp_cast_nil(const autobahn::wamp_call_result& result)
    {
        if (result.template argument<msgpack::object>(0).is_nil()) {
            return boost::none;
        }
        return result.template argument<T>(0);
    }

    class wamp_transport {
    public:
        using locker_t = std::unique_lock<std::mutex>;
        using notify_fn_t = std::function<void(nlohmann::json, bool)>;
        using subscribe_fn_t = std::function<void(nlohmann::json)>;
        using transport_t = std::shared_ptr<autobahn::wamp_websocket_transport>;

        wamp_transport(const network_parameters& net_params, notify_fn_t fn);
        ~wamp_transport();

        void connect();
        bool is_connected() const;
        void reconnect();
        void reconnect_hint(bool enabled);
        void disconnect(bool user_initiated);

        void subscribe(locker_t& locker, const std::string& topic, subscribe_fn_t callback);
        void unsubscribe();
        void clear_subscriptions();

        nlohmann::json http_request(nlohmann::json params);

        transport_t make_transport();
        bool ping() const;

        void heartbeat_timeout_cb(websocketpp::connection_hdl, const std::string&);
        void ping_timer_handler(const boost::system::error_code& ec);

        void set_socket_options();
        void start_ping_timer();

        std::string get_tor_socks5();
        void tor_sleep_hint(const std::string& hint);

        // Make a background WAMP call and return its result to the current thread.
        // The session mutex must not be held when calling this function.
        template <typename... Args>
        autobahn::wamp_call_result call(const std::string& method_name, Args&&... args) const
        {
            const std::string method{ m_wamp_call_prefix + method_name };
            auto fn = m_session->call(method, std::make_tuple(std::forward<Args>(args)...), m_wamp_call_options);
            return wamp_process_call(fn);
        }

        // Make a WAMP call on a currently locked session.
        template <typename... Args>
        autobahn::wamp_call_result call(locker_t& locker, const std::string& method_name, Args&&... args) const
        {
            unique_unlock unlocker(locker);
            return call(method_name, std::forward<Args>(args)...);
        }

        template <typename FN> void post(FN&& fn) { boost::asio::post(m_work_guard.get_executor(), fn); }

    private:
        autobahn::wamp_call_result wamp_process_call(boost::future<autobahn::wamp_call_result>& fn) const;

        bool set_reconnecting(bool want_to_reconnect);
        void stop_reconnecting();
        bool is_reconnect_canceled(std::chrono::seconds secs) const;
        void set_reconnect_enabled(bool v);
        bool is_reconnect_enabled() const;

        const network_parameters& m_net_params;
        notify_fn_t m_notify_fn;
        const bool m_debug_logging;
        std::string m_proxy;
        const bool m_has_network_proxy;

        boost::asio::io_context m_io;
        boost::variant<std::unique_ptr<client>, std::unique_ptr<client_tls>> m_client;
        transport_t m_transport;
        std::shared_ptr<autobahn::wamp_session> m_session;
        std::vector<autobahn::wamp_subscription> m_subscriptions;
        std::shared_ptr<tor_controller> m_tor_ctrl;
        std::string m_last_tor_socks5;
        autobahn::wamp_call_options m_wamp_call_options;
        const std::string m_wamp_call_prefix;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_work_guard;
        std::thread m_run_thread;
        boost::asio::deadline_timer m_ping_timer;
        std::unique_ptr<std::thread> m_reconnect_thread;
        std::promise<void> m_reconnect_promise;
        std::future<void> m_reconnect_future;
        std::atomic_bool m_reconnecting{ false };
        std::atomic_bool m_enabled{ true };
    };

} // namespace sdk
} // namespace ga

#endif
