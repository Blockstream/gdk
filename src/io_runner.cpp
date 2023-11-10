#include "io_runner.hpp"
#include "utils.hpp"

#include <thread>

namespace ga {
namespace sdk {

    io_runner::io_runner()
        : m_io(std::make_unique<boost::asio::io_context>())
        , m_work_guard(boost::asio::make_work_guard(m_io->get_executor()))
    {
        m_run_thread = std::thread([io = std::ref(*m_io)]() { io.get().run(); });
    }

    io_runner::~io_runner()
    {
        no_std_exception_escape([wg = std::ref(m_work_guard)] { wg.get().reset(); }, "io_runner m_work_guard");
        no_std_exception_escape([runner = std::ref(m_run_thread)] { runner.get().join(); }, "io_runner m_run_thread");
    }

    boost::asio::io_context& io_runner::get_io_context() { return *m_io; }

} // namespace sdk
} // namespace ga
