#ifndef GDK_ASSERTION_HPP
#define GDK_ASSERTION_HPP
#pragma once

#include <string>

#include "wally_wrapper.h"

namespace ga {
namespace sdk {
    void runtime_assert_message(
        bool condition, const std::string& error_message, const char* file, const char* func, const char* line);
}
} // namespace ga

#define GDK_STRINGIFY_(x) #x
#define GDK_STRINGIFY(x) GDK_STRINGIFY_(x)
#define GDK_RUNTIME_ASSERT(condition)                                                                                  \
    ga::sdk::runtime_assert_message(                                                                                   \
        condition, std::string(), __FILE__, static_cast<const char*>(__func__), GDK_STRINGIFY(__LINE__))
#define GDK_RUNTIME_ASSERT_MSG(condition, error_message)                                                               \
    ga::sdk::runtime_assert_message(                                                                                   \
        condition, error_message, __FILE__, static_cast<const char*>(__func__), GDK_STRINGIFY(__LINE__))
#define GDK_VERIFY(x) GDK_RUNTIME_ASSERT((x) == WALLY_OK)

#define NET_ERROR_CODE_CHECK(msg, ec)                                                                                  \
    if (ec) {                                                                                                          \
        set_exception(std::string{ msg } + ": " + (ec).message());                                                     \
        return;                                                                                                        \
    }

#endif
