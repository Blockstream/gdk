#ifndef GDK_EXCEPTION_HPP
#define GDK_EXCEPTION_HPP
#pragma once

#include "autobahn_wrapper.hpp"
#include <utility>

namespace ga {
namespace sdk {

    using abort_error = autobahn::abort_error;
    using network_error = autobahn::network_error;
    using no_session_error = autobahn::no_session_error;
    using no_transport_error = autobahn::no_transport_error;
    using protocol_error = autobahn::protocol_error;

    class login_error : public std::runtime_error {
    public:
        login_error(const std::string& what)
            : std::runtime_error("login failed:" + what)
        {
        }
    };

    class reconnect_error : public std::runtime_error {
    public:
        reconnect_error()
            : std::runtime_error("reconnect required")
        {
        }
    };

    class timeout_error : public std::runtime_error {
    public:
        timeout_error()
            : std::runtime_error("timeout error")
        {
        }
    };

    class assertion_error : public std::runtime_error {
    public:
        assertion_error(const std::string& what)
            : std::runtime_error(what)
        {
        }
    };

    class user_error : public std::runtime_error {
    public:
        user_error(const std::string& what)
            : std::runtime_error(what)
        {
        }
    };

    std::pair<std::string, std::string> get_error_details(const autobahn::call_error& e);
    std::pair<std::string, std::string> remap_ga_server_error(const std::pair<std::string, std::string>& details);
} // namespace sdk
} // namespace ga

#endif
