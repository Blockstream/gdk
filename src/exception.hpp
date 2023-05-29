#ifndef GDK_EXCEPTION_HPP
#define GDK_EXCEPTION_HPP
#pragma once

#include <stdexcept>
#include <utility>

namespace autobahn {
class call_error;
}

namespace ga {
namespace sdk {

    class login_error : public std::runtime_error {
    public:
        explicit login_error(const std::string& what)
            : std::runtime_error(what)
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
} // namespace sdk
} // namespace ga

#endif
