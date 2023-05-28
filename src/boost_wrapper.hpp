#ifndef GDK_BOOST_WRAPPER_HPP
#define GDK_BOOST_WRAPPER_HPP
#pragma once

#if __clang__
#pragma clang diagnostic push
#else
#pragma GCC diagnostic push
#endif

#if __clang_major__ >= 7
#define BOOST_ASIO_HAS_STD_STRING_VIEW
#endif
#define BOOST_ASIO_DISABLE_IOCP
#define BOOST_ASIO_DISABLE_VISIBILITY

#if defined _WIN32 || defined WIN32 || defined __CYGWIN__
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#endif
#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/version.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/format.hpp>
#include <boost/log/attributes/named_scope.hpp>
#include <boost/log/core.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/async_frontend.hpp>
#include <boost/log/sinks/basic_sink_backend.hpp>
#include <boost/log/sources/global_logger_storage.hpp>
#include <boost/log/sources/logger.hpp>
#include <boost/log/trivial.hpp>
#include <boost/multiprecision/cpp_dec_float.hpp>
#include <boost/multiprecision/cpp_int.hpp>
#include <boost/smart_ptr/atomic_shared_ptr.hpp>
#include <boost/thread/tss.hpp>

#if __clang__
#pragma clang diagnostic pop
#else
#pragma GCC diagnostic pop
#endif

#endif
