#ifndef GDK_ASSERTION_HPP
#define GDK_ASSERTION_HPP
#pragma once

#include <string>

namespace green {
    [[noreturn]] void runtime_assert_message(const std::string& error_message, const char* file, unsigned int line);
    [[noreturn]] void throw_user_error(const std::string& error_message);
} // namespace green

#ifdef __FILE_NAME__
#define GDK_RUNTIME_ASSERT_MSG(condition, error_message)                                                               \
    do {                                                                                                               \
        if (!(condition)) {                                                                                            \
            green::runtime_assert_message(error_message, __FILE_NAME__, __LINE__);                                     \
        }                                                                                                              \
    } while (false)
#else
#define GDK_RUNTIME_ASSERT_MSG(condition, error_message)                                                               \
    do {                                                                                                               \
        if (!(condition)) {                                                                                            \
            green::runtime_assert_message(error_message, __FILE__, __LINE__);                                          \
        }                                                                                                              \
    } while (false)
#endif
#define GDK_RUNTIME_ASSERT(condition) GDK_RUNTIME_ASSERT_MSG(condition, std::string());
#define GDK_USER_ASSERT(condition, error_message)                                                                      \
    do {                                                                                                               \
        if (!(condition)) {                                                                                            \
            green::throw_user_error(error_message);                                                                    \
        }                                                                                                              \
    } while (false)
#define GDK_VERIFY(x) GDK_RUNTIME_ASSERT((x) == WALLY_OK)

#define NET_ERROR_CODE_CHECK(msg, ec)                                                                                  \
    if (ec) {                                                                                                          \
        set_exception(std::string{ msg } + ": " + (ec).message());                                                     \
        return;                                                                                                        \
    }

#endif
