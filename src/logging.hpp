#ifndef GDK_LOGGING_HPP
#define GDK_LOGGING_HPP
#pragma once

#ifdef __ANDROID__
#include <android/log.h>
#endif

#include <boost/log/attributes/named_scope.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/async_frontend.hpp>
#include <boost/log/sinks/basic_sink_backend.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/trivial.hpp>

namespace ga {
namespace sdk {
    namespace log_level = boost::log::trivial;

    using gdk_logger_t = boost::log::sources::severity_logger_mt<log_level::severity_level>;

#ifdef __ANDROID__
    class android_backend : public boost::log::sinks::basic_formatted_sink_backend<char> {
    public:
        void consume(const boost::log::record_view&, const std::string& formatted_message)
        {
            // TODO: severity levels
            constexpr size_t MAX_LINE = 1024; // Maximum size of an Android log message
            if (formatted_message.size() < MAX_LINE) {
                __android_log_write(ANDROID_LOG_DEBUG, "GDK", formatted_message.c_str());
            } else {
                char buf[MAX_LINE + 1];
                for (size_t i = 0; i < formatted_message.size(); i += MAX_LINE) {
                    strncpy(buf, formatted_message.c_str() + i, MAX_LINE);
                    buf[MAX_LINE] = '\0';
                    if (buf[0] != '\0') {
                        __android_log_write(ANDROID_LOG_DEBUG, "GDK", buf);
                    }
                }
            }
        }
    };
#endif

#if defined(__ANDROID__) and not defined(NDEBUG)
    inline void start_android_std_outerr_bridge()
    {
        auto logger_thread = std::thread([] {
            int pipes[2];
            setvbuf(stdout, 0, _IOLBF, 0);
            setvbuf(stderr, 0, _IONBF, 0);

            pipe(pipes);
            dup2(pipes[1], 1);
            dup2(pipes[1], 2);

            ssize_t read_size;
            char buffer[1024];
            while ((read_size = read(pipes[0], buffer, sizeof buffer - 1)) > 0) {
                if (buffer[read_size - 1] == '\n')
                    --read_size;
                buffer[read_size] = 0;
                __android_log_write(ANDROID_LOG_DEBUG, "GDK", buffer);
            }
        });
        logger_thread.detach();
    }
#endif

    BOOST_LOG_INLINE_GLOBAL_LOGGER_INIT(gdk_logger, gdk_logger_t)
    {
#ifdef __ANDROID__
        using sink_t = boost::log::sinks::asynchronous_sink<android_backend>;
        auto sink = boost::make_shared<sink_t>(boost::make_shared<android_backend>());
        boost::log::core::get()->add_sink(sink);
#endif
        return gdk_logger_t{};
    }

#define GDK_LOG_SEV(sev) BOOST_LOG_SEV(::ga::sdk::gdk_logger::get(), sev)

} // namespace sdk
} // namespace ga

#endif
