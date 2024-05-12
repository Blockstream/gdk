#ifndef GDK_IO_RUNNER_HPP
#define GDK_IO_RUNNER_HPP
#pragma once

#include <algorithm>
#include <array>
#include <boost/asio/io_context.hpp>
#include <gsl/span>
#include <memory>
#include <thread>

#include "utils.hpp"

namespace green {

    class io_container {
        std::unique_ptr<boost::asio::io_context> m_io;
        boost::asio::executor_work_guard<boost::asio::io_context::executor_type> m_work_guard;

    public:
        io_container();
        ~io_container();
        boost::asio::io_context& get_io_context();
        void start(gsl::span<std::thread> pool);
        void shutdown(gsl::span<std::thread> pool) noexcept;
    };

    template <size_t PoolSize> class io_runner {
    public:
        io_runner() { m_io.start(m_pool); }

        ~io_runner() { m_io.shutdown(m_pool); }
        boost::asio::io_context& get_io_context() { return m_io.get_io_context(); }

    private:
        io_container m_io;
        std::array<std::thread, PoolSize> m_pool;
    };

} // namespace green
//
#endif
