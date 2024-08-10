#include <stdexcept>

#include "assertion.hpp"
#include "exception.hpp"
#include "logging.hpp"

namespace green {

    void runtime_assert_message(const std::string& error_message, const char* file, unsigned int line)
    {
#ifndef __FILE_NAME__
        // Strip path from the file name
        const char* base = strrchr(file, '/');
        file = base ? base + 1 : file;
#endif
        const char* sep = error_message.empty() ? "" : ":";
        const std::string msg
            = std::string("assertion failure: ") + file + ":" + std::to_string(line) + sep + error_message;
        GDK_LOG(error) << msg;
        throw assertion_error(msg);
    }

    void throw_user_error(const std::string& error_message) { throw user_error(error_message); }

} // namespace green
