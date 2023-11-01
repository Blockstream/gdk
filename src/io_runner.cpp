#include "io_runner.hpp"

#include <boost/asio/post.hpp>

#include "utils.hpp"

namespace ga {
namespace sdk {

    io_runner::io_runner()
        : m_work_guard(boost::asio::make_work_guard(m_io.get_executor()))
        , m_pool(1)
    {
        boost::asio::post(m_pool, [io = std::ref(m_io)]() { io.get().run(); });
    }

    io_runner::~io_runner()
    {
        no_std_exception_escape([wg = std::ref(m_work_guard)] { wg.get().reset(); }, "io_runner m_work_guard");
        m_io.stop();
        no_std_exception_escape(
            [pool = std::ref(m_pool)] {
                pool.get().stop();
                pool.get().join();
            },
            "io_runner m_run_thread");
    }

    boost::asio::io_context& io_runner::get_io_context() { return m_io; }

} // namespace sdk
} // namespace ga
