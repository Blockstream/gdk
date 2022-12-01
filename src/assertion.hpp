#ifndef GDK_ASSERTION_HPP
#define GDK_ASSERTION_HPP
#pragma once

#include <string>

namespace ga {
namespace sdk {
    void runtime_assert_message(const std::string& error_message, const char* file, const char* func, const char* line);
}
} // namespace ga

#define GDK_STRINGIFY_(x) #x
#define GDK_STRINGIFY(x) GDK_STRINGIFY_(x)
#define GDK_RUNTIME_ASSERT(condition)                                                                                  \
    do {                                                                                                               \
        if (!(condition)) {                                                                                            \
            ga::sdk::runtime_assert_message(                                                                           \
                std::string(), __FILE__, static_cast<const char*>(__func__), GDK_STRINGIFY(__LINE__));                 \
        }                                                                                                              \
    } while (false)
#define GDK_RUNTIME_ASSERT_MSG(condition, error_message)                                                               \
    do {                                                                                                               \
        if (!(condition)) {                                                                                            \
            ga::sdk::runtime_assert_message(                                                                           \
                error_message, __FILE__, static_cast<const char*>(__func__), GDK_STRINGIFY(__LINE__));                 \
        }                                                                                                              \
    } while (false)
#define GDK_VERIFY(x) GDK_RUNTIME_ASSERT((x) == WALLY_OK)

#define NET_ERROR_CODE_CHECK(msg, ec)                                                                                  \
    if (ec) {                                                                                                          \
        set_exception(std::string{ msg } + ": " + (ec).message());                                                     \
        return;                                                                                                        \
    }

#endif
