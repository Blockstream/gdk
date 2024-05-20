#ifndef GDK_EXCEPTION_HPP
#define GDK_EXCEPTION_HPP
#pragma once

#include <stdexcept>
#include <utility>

namespace autobahn {
    class call_error;
}

namespace green {

    class login_error : public std::runtime_error {
    public:
        explicit login_error(const std::string& what)
            : std::runtime_error(what)
        {
        }
    };

    class connection_error : public std::runtime_error {
    public:
        connection_error(const char* what_str)
            : std::runtime_error(what_str)
        {
        }
    };

    class reconnect_error : public connection_error {
    public:
        reconnect_error()
            : connection_error("reconnect required")
        {
        }
    };

    class timeout_error : public connection_error {
    public:
        timeout_error()
            : connection_error("timeout error")
        {
        }
    };

    class assertion_error : public std::runtime_error {
    public:
        explicit assertion_error(const std::string& what)
            : std::runtime_error(what)
        {
        }
    };

    class user_error : public std::runtime_error {
    public:
        explicit user_error(const std::string& what)
            : std::runtime_error(what)
        {
        }
    };

    std::pair<std::string, std::string> get_error_details(const autobahn::call_error& e);
    std::pair<std::string, std::string> remap_ga_server_error(const std::pair<std::string, std::string>& details);

} // namespace green

#endif
