#ifndef GDK_IO_RUNNER_HPP
#define GDK_IO_RUNNER_HPP
#pragma once

#include <boost/asio/io_context.hpp>
#include <boost/asio/thread_pool.hpp>
#include <memory>
#include <thread>

#include "boost/asio/io_context.hpp"

namespace ga {
namespace sdk {

    class io_runner {
    public:
        io_runner();
        ~io_runner();
        boost::asio::io_context& get_io_context();

    private:
        boost::asio::io_context m_io;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_work_guard;
        boost::asio::thread_pool m_pool; // Runs the asio context
    };

} // namespace sdk
} // namespace ga
//
#endif
