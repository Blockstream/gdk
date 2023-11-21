
#include "io_runner.hpp"

namespace ga {
namespace sdk {

    io_container::io_container()
        : m_io(std::make_unique<boost::asio::io_context>())
        , m_work_guard(boost::asio::make_work_guard(m_io->get_executor()))
    {
    }
    io_container::~io_container() { shutdown(gsl::span<std::thread>()); }

    boost::asio::io_context& io_container::get_io_context() { return *m_io; }
    void io_container::start(gsl::span<std::thread> pool)
    {
        auto thread_generator
            = [this]() { return std::thread([ioctx = std::ref(*this->m_io)]() { ioctx.get().run(); }); };
        std::generate(pool.begin(), pool.end(), thread_generator);
    }
    void io_container::shutdown(gsl::span<std::thread> pool) noexcept
    {
        no_std_exception_escape([wg = std::ref(m_work_guard)] { wg.get().reset(); }, "io_context m_work_guard");
        no_std_exception_escape(
            [pool = std::ref(pool)] {
                std::for_each(pool.get().begin(), pool.get().end(), [](auto& thread) { thread.join(); });
                ;
            },
            "io_context pool");
    }
} // namespace sdk
} // namespace ga
