#ifndef GDK_WAMP_TRANSPORT_HPP
#define GDK_WAMP_TRANSPORT_HPP
#pragma once

#include <optional>
#include <string>
#include <vector>

#include "autobahn_wrapper.hpp"
#include "logging.hpp"
#include "threading.hpp"

namespace ga {
namespace sdk {
    class exponential_backoff;
    struct websocketpp_gdk_config;
    struct websocketpp_gdk_tls_config;

    nlohmann::json wamp_cast_json(const autobahn::wamp_event& event);
    nlohmann::json wamp_cast_json(const autobahn::wamp_call_result& result);

    template <typename T = std::string> T wamp_cast(const autobahn::wamp_call_result& result)
    {
        return result.template argument<T>(0);
    }

    template <typename T = std::string> std::optional<T> wamp_cast_nil(const autobahn::wamp_call_result& result)
    {
        if (result.template argument<msgpack::object>(0).is_nil()) {
            return {};
        }
        return result.template argument<T>(0);
    }

    // Represents a WAMP server connection.
    // All public methods are called from outside this class only.
    class wamp_transport {
    public:
        using client = websocketpp::client<websocketpp_gdk_config>;
        using client_tls = websocketpp::client<websocketpp_gdk_tls_config>;

        using locker_t = std::unique_lock<std::mutex>;
        using notify_fn_t = std::function<void(nlohmann::json, bool)>;
        using subscribe_fn_t = std::function<void(nlohmann::json)>;

        wamp_transport(const network_parameters& net_params, notify_fn_t fn);
        ~wamp_transport();

        // Connect the transport. The proxy to use is passed to us as it can
        // be dynamic in some cases (e.g. using built-in tor). Choosing the
        // proxy to use is handled for all session types by the base class
        // session_impl.
        void connect(const std::string& proxy); // Currently synchronous

        // Disconnect the transport.
        void disconnect(); // Currently synchronous

        // Reconnect the transport in response to an error detected by a caller
        // outside this class. This is a no-op if the transport has already
        // detected the same error and has reconnected/is reconnecting.
        void reconnect(); // Async, returns without waiting

        // Change the state of the transport to connected or disconnected.
        void reconnect_hint(const nlohmann::json& hint, const std::string& proxy); // Currently synchronous

        // Subscribe to a topic. Use is_initial=true for the first
        // subscription after reconnecting
        void subscribe(const std::string& topic, subscribe_fn_t fn, bool is_initial = false);

        // Make a background WAMP call and return its result to the current thread.
        // The session mutex must not be held when calling this function.
        template <typename... Args> autobahn::wamp_call_result call(const std::string& method_name, Args&&... args)
        {
            const std::string method{ m_wamp_call_prefix + method_name };
            auto st = get_session_and_transport();
            if (!st.first || !st.second) {
                throw reconnect_error{};
            }
            auto fn = st.first->call(method, std::make_tuple(std::forward<Args>(args)...), m_wamp_call_options);
            return wamp_process_call(st.second, fn);
        }

        // Make a WAMP call on a currently locked session.
        template <typename... Args>
        autobahn::wamp_call_result call(locker_t& locker, const std::string& method_name, Args&&... args)
        {
            unique_unlock unlocker(locker);
            return call(method_name, std::forward<Args>(args)...);
        }

        // Post a function to run on the asio executor thread
        template <typename FN> void post(FN&& fn) { boost::asio::post(m_io.get_executor(), fn); }

    private:
        using session_ptr = std::shared_ptr<autobahn::wamp_session>;

        // Current and desired states
        enum class state_t : uint32_t {
            disconnected = 0, // Disconnected
            connected = 1, // Connected
            exited = 2, // Exited (no reconnect thread running)
        };
        const char* state_str(state_t state) const;

        void change_state_to(state_t new_state, const std::string& proxy, bool wait);
        void emit_state(state_t current, state_t desired, uint64_t wait_ms);

        void reconnect_handler();
        void backoff_handler(locker_t& locker, exponential_backoff& backoff);

        void heartbeat_timeout_cb(websocketpp::connection_hdl, const std::string&);

        // Notify failures to prompt a reconnect.
        void notify_failure(const std::string& reason);
        // NOTE: this overload unlocks the passed in locker.
        void notify_failure(locker_t& locker, const std::string& reason, bool notify_condition = true);

        std::pair<session_ptr, autobahn::wamp_websocket_transport*> get_session_and_transport();
        autobahn::wamp_call_result wamp_process_call(
            autobahn::wamp_websocket_transport* t, boost::future<autobahn::wamp_call_result>& fn);

        // These members are immutable after construction
        const network_parameters& m_net_params;
        boost::asio::io_context m_io;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_work_guard;
        std::thread m_run_thread; // Runs the asio context
        std::thread m_reconnect_thread; // Runs the reconnection logic
        const std::string m_server;
        const std::string m_wamp_host_name;
        const std::string m_wamp_call_prefix;
        autobahn::wamp_call_options m_wamp_call_options;
        notify_fn_t m_notify_fn;
        std::unique_ptr<client> m_client;
        std::unique_ptr<client_tls> m_client_tls;

        // This mutex protects the following members
        std::mutex m_mutex;
        // The desired state of the transport
        std::atomic<state_t> m_desired_state;
        // A condition variable and associated current state of the transport
        std::condition_variable m_condition;
        std::atomic<state_t> m_state;
        // The current proxy to use
        std::string m_proxy;
        // The count of failures detected, incremented to cause a reconnect
        std::atomic<uint32_t> m_failure_count;
        // The time of the last ping we sent
        std::chrono::time_point<std::chrono::system_clock> m_last_ping_ts;
        // The transport, session and any subscriptions
        std::shared_ptr<autobahn::wamp_websocket_transport> m_transport;
        session_ptr m_session;
        std::vector<autobahn::wamp_subscription> m_subscriptions;
    };

} // namespace sdk
} // namespace ga

#endif
