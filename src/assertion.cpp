#include <stdexcept>

#include "assertion.hpp"
#include "exception.hpp"
#include "logging.hpp"

namespace ga {
namespace sdk {
    void runtime_assert_message(const std::string& error_message, const char* file, const char* func, unsigned int line)
    {
#ifndef __FILE_NAME__
        // Strip path from the file name
        const char* base = strrchr(file, '/');
        file = base ? base + 1 : file;
#endif
        const std::string msg
            = std::string("assertion failure: ") + file + ":" + func + ":" + std::to_string(line) + ":" + error_message;
        GDK_LOG_SEV(log_level::error) << msg
#if defined(__linux__) and not defined(NDEBUG) and defined(HAVE_BACKTRACE)
                                      << "\n:backtrace " << boost::stacktrace::stacktrace()
#endif
            ;
        throw assertion_error(msg);
    }
} // namespace sdk
} // namespace ga
