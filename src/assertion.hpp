#ifndef GDK_ASSERTION_HPP
#define GDK_ASSERTION_HPP
#pragma once

#include <string>

namespace ga {
namespace sdk {
    void runtime_assert_message(const std::string& error_message, const char* file, unsigned int line);
}
} // namespace ga

#ifdef __FILE_NAME__
#define GDK_RUNTIME_ASSERT_MSG(condition, error_message)                                                               \
    do {                                                                                                               \
        if (!(condition)) {                                                                                            \
            ga::sdk::runtime_assert_message(error_message, __FILE_NAME__, __LINE__);                                   \
        }                                                                                                              \
    } while (false)
#else
#define GDK_RUNTIME_ASSERT_MSG(condition, error_message)                                                               \
    do {                                                                                                               \
        if (!(condition)) {                                                                                            \
            ga::sdk::runtime_assert_message(error_message, __FILE__, __LINE__);                                        \
        }                                                                                                              \
    } while (false)
#endif
#define GDK_RUNTIME_ASSERT(condition) GDK_RUNTIME_ASSERT_MSG(condition, std::string());
#define GDK_VERIFY(x) GDK_RUNTIME_ASSERT((x) == WALLY_OK)

#define NET_ERROR_CODE_CHECK(msg, ec)                                                                                  \
    if (ec) {                                                                                                          \
        set_exception(std::string{ msg } + ": " + (ec).message());                                                     \
        return;                                                                                                        \
    }

#endif
