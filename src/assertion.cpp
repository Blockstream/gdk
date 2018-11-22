#include <stdexcept>

#include "assertion.hpp"
#include "logging.hpp"

namespace ga {
namespace sdk {
    void runtime_assert_message(
        bool condition, const std::string& error_message, const char* file, const char* func, const char* line)
    {
        if (!condition) {
            const std::string msg
                = std::string("assertion failure: ") + file + ":" + func + ":" + line + ":" + error_message;
            GDK_LOG_SEV(log_level::error) << msg;
            throw std::runtime_error(msg);
        }
    }
} // namespace sdk
} // namespace ga
