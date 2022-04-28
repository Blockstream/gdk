#ifndef GDK_AUTOBAHN_WRAPPER_HPP
#define GDK_AUTOBAHN_WRAPPER_HPP
#pragma once

#ifdef __ANDROID__
#include <sys/epoll.h>
#undef EPOLL_CLOEXEC
#endif

#include "boost_wrapper.hpp"

#if __clang__
#pragma clang diagnostic push
#if !defined __APPLE__ && __clang_major__ >= 6
#pragma clang diagnostic ignored "-Wenum-compare"
#endif
#pragma clang diagnostic ignored "-Wignored-qualifiers"
#pragma clang diagnostic ignored "-Wnon-virtual-dtor"
#pragma clang diagnostic ignored "-Wunused-parameter"
#pragma clang diagnostic ignored "-Wnull-pointer-subtraction"
#pragma clang diagnostic ignored "-Wdeprecated-copy"
#endif

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattributes"
#pragma GCC diagnostic ignored "-Wignored-qualifiers"
#pragma GCC diagnostic ignored "-Wparentheses"
#pragma GCC diagnostic ignored "-Wnon-virtual-dtor"
#pragma GCC diagnostic ignored "-Wunused-parameter"
#if __GNUC__ > 7
#pragma GCC diagnostic ignored "-Wclass-memaccess"
#endif
#if __GNUC__ >= 9
#pragma GCC diagnostic ignored "-Wdeprecated-copy"
#endif

#include <autobahn/autobahn.hpp>
#include <autobahn/exceptions.hpp>
#include <autobahn/wamp_session.hpp>
#include <autobahn/wamp_websocketpp_websocket_transport.hpp>

#pragma GCC diagnostic pop

#if __clang__
#pragma clang diagnostic pop
#endif

#include <websocketpp/client.hpp>
#include <websocketpp/config/asio_client.hpp>

#endif
